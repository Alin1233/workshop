"""Tests unitaires du détecteur d'anomalies : variables, normalisation du score, inférence, robustesse.

Ces tests tournent SANS la stack (ni Prometheus ni Loki) : on injecte de faux clients. Ils couvrent le
calcul des variables, le comblement des valeurs manquantes, l'apprentissage/scoring du modèle robuste,
la boucle d'inférence et sa résistance aux sources vides ou injoignables, la désignation et la validation
du modèle, le seuil unique, ainsi que les scripts de ml/ (étiquetage, évaluation, générateur).
Aucun secret n'est écrit en dur : les mots de passe de test sont générés.
"""

import importlib.util
import json
import math
import sys
import threading
from collections import Counter
from pathlib import Path

import pytest
import yaml
from prometheus_client import REGISTRY

REPO = Path(__file__).resolve().parents[2]
# Le code des variables/modèle est partagé avec le service : on l'importe depuis son paquet `app`.
DETECTOR = REPO / "services" / "anomaly-detector"
if str(DETECTOR) not in sys.path:
    sys.path.insert(0, str(DETECTOR))

from app import features  # noqa: E402
from app import model as model_mod  # noqa: E402
from app import promclient  # noqa: E402
from app.promclient import SourceUnavailable, _scalar_from_vector  # noqa: E402

FLOORS = {
    "req_rate": 0.3, "error_ratio_5xx": 0.02, "latency_p95": 0.1,
    "login_failures_per_min": 1.0, "client_errors_4xx_rate": 0.2, "probe_failed": 0.1,
    "invalid_tokens_per_min": 1.0, "req_rate_per_min": 3.0, "waf_blocks_per_min": 1.0,
}
LOKI_FEATURES = {svc: [s.name for s in specs if s.source == "loki"] for svc, specs in features.FEATURES.items()}


def load_script(name):
    # Cette méthode permet d'importer un script de ml/ (ce n'est pas un paquet) sous un nom de module dédié.
    spec = importlib.util.spec_from_file_location(f"ml_{name}", REPO / "ml" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeClient:
    """Faux client Prometheus/Loki : renvoie des valeurs prédéfinies par requête, ou lève une erreur."""

    def __init__(self, mapping, error=None):
        self.mapping = mapping
        self.error = error
        self.calls = 0

    def query(self, expr, at=None):
        self.calls += 1
        if self.error:
            raise self.error
        return self.mapping.get(expr, float("nan"))

    def query_range(self, expr, start, end, step):
        if self.error:
            raise self.error
        return {}


def make_clients(values_by_service):
    # Cette méthode permet de fabriquer de faux clients cohérents avec les requêtes réelles des variables.
    prom_map, loki_map = {}, {}
    for service, specs in features.FEATURES.items():
        for spec in specs:
            value = values_by_service.get(service, {}).get(spec.name, 0.0)
            (prom_map if spec.source == "prom" else loki_map)[spec.query] = value
    return FakeClient(prom_map), FakeClient(loki_map)


def _normal_baseline():
    # Cette méthode permet de décrire un comportement normal plausible par service.
    return {
        "auth-service": {"req_rate": 1.0, "error_ratio_5xx": 0.0, "latency_p95": 0.2,
                         "login_failures_per_min": 0.0, "client_errors_4xx_rate": 0.1, "probe_failed": 0.0},
        "payment-api": {"req_rate": 1.5, "error_ratio_5xx": 0.0, "latency_p95": 0.05,
                        "invalid_tokens_per_min": 0.0, "client_errors_4xx_rate": 0.2, "probe_failed": 0.0},
        "frontend": {"req_rate_per_min": 120.0, "waf_blocks_per_min": 0.0, "probe_failed": 0.0},
    }


def gauge(name, **labels):
    # Cette méthode permet de lire la valeur courante d'une métrique exposée par le service.
    return REGISTRY.get_sample_value(name, labels)


@pytest.fixture(scope="module")
def trained_model():
    # Cette méthode permet d'entraîner un petit modèle déterministe sur un trafic normal synthétique bruité.
    import numpy as np

    rng = np.random.default_rng(0)
    baseline = _normal_baseline()
    normal_vectors, order = {}, {}
    for service in features.SERVICES:
        names = features.feature_names(service)
        order[service] = names
        base = np.array([baseline[service][n] for n in names])
        noise = rng.normal(0, 1, size=(80, len(names))) * (0.05 + 0.1 * base)
        samples = np.clip(base + noise, 0, None)
        normal_vectors[service] = samples.tolist()
    return model_mod.fit("test-model", normal_vectors, order, scale_floor=FLOORS, meta={"test": True})


@pytest.fixture
def clean_env(monkeypatch):
    # Cette méthode permet de neutraliser les variables d'environnement du service pour les tests HTTP.
    for name in ("MODEL_PATH", "MODEL_DIR", "PROMETHEUS_PASSWORD", "PROMETHEUS_PASSWORD_FILE", "LOKI_PASSWORD",
                 "LOKI_PASSWORD_FILE", "STALE_AFTER_CYCLES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PROMETHEUS_URL", "http://127.0.0.1:9")  # port fermé : refus immédiat
    monkeypatch.setenv("LOKI_URL", "http://127.0.0.1:9")
    return monkeypatch


# ----------------------------------------------------------------- variables

def test_extract_instant_maps_each_service():
    # Cette méthode permet de vérifier que chaque service reçoit toutes ses variables depuis le bon client.
    prom, loki = make_clients(_normal_baseline())
    observations, errors = features.extract_instant(prom, loki)
    assert errors == {}
    assert set(observations) == set(features.SERVICES)
    assert all(obs.complete for obs in observations.values())
    assert observations["auth-service"].values["req_rate"] == 1.0
    assert observations["payment-api"].values["req_rate"] == 1.5
    assert observations["frontend"].values["req_rate_per_min"] == 120.0


class RangeClient:
    """Faux client pour l'export : renvoie une série {timestamp: valeur} identique pour toutes les requêtes."""

    def __init__(self, series):
        self.series = series

    def query_range(self, expr, start, end, step):
        return dict(self.series)


def test_extract_range_aligns_grid_and_never_reads_the_future():
    # Cette méthode permet de vérifier l'export : grille calée sur le pas, et un point absent (Loki omet les fenêtres
    # vides) reste NaN au lieu d'emprunter la valeur du point suivant (fuite temporelle corrigée).
    series = {1000: 1.0, 1020: 5.0}  # pas de point à 1010 : fenêtre sans événement
    rows = features.extract_range(RangeClient(series), RangeClient(series), 1003, 1020, 10)
    auth = [r for r in rows if r["service"] == "auth-service"]
    assert [r["timestamp"] for r in auth] == [1000, 1010, 1020]
    assert auth[0]["req_rate"] == 1.0
    assert math.isnan(auth[1]["req_rate"])
    assert auth[2]["req_rate"] == 5.0


def test_clean_values_fills_no_data_but_never_missing_sources():
    # Cette méthode permet de vérifier le comblement : NaN (requête réussie sans donnée) → "zero" ou "median",
    # mais une variable ABSENTE (source injoignable) n'est jamais inventée.
    values = {"req_rate": float("nan"), "latency_p95": float("nan"), "error_ratio_5xx": 0.0,
              "login_failures_per_min": 3.0, "probe_failed": float("nan")}  # client_errors_4xx_rate manquante
    cleaned = features.clean_values("auth-service", values, {"latency_p95": 0.2})
    assert cleaned["req_rate"] == 0.0  # nan_fill="zero"
    assert cleaned["latency_p95"] == 0.2  # nan_fill="median"
    assert cleaned["login_failures_per_min"] == 3.0
    assert "client_errors_4xx_rate" not in cleaned


# ----------------------------------------------------------------- modèle / score

def test_idle_scores_near_zero(trained_model):
    # Cette méthode permet de garantir qu'une période creuse (aucune activité) ne déclenche aucune anomalie.
    for service in features.SERVICES:
        zeros = {name: 0.0 for name in features.feature_names(service)}
        assert trained_model.score_values(service, zeros)["score"] < 0.2, service


def test_normal_load_below_threshold(trained_model):
    # Cette méthode permet de garantir qu'une charge ordinaire reste sous le seuil d'alerte (0,8).
    for service, values in _normal_baseline().items():
        assert trained_model.score_values(service, values)["score"] < trained_model.threshold


def test_attack_crosses_threshold(trained_model):
    # Cette méthode permet de vérifier qu'une rafale anormale (une variable qui explose) dépasse le seuil.
    values = {name: 0.0 for name in features.feature_names("auth-service")}
    values["login_failures_per_min"] = 40.0  # force brute
    result = trained_model.score_values("auth-service", values)
    assert result["score"] > 0.8
    assert result["dominant_feature"] == "login_failures_per_min"


def test_score_is_bounded_and_monotonic(trained_model):
    # Cette méthode permet de vérifier que le score reste dans [0, 1] et croît avec l'ampleur de l'écart.
    previous = -1.0
    for blocks in (0, 5, 20, 100, 1000):
        values = {"req_rate_per_min": 0.0, "waf_blocks_per_min": blocks, "probe_failed": 0.0}
        score = trained_model.score_values("frontend", values)["score"]
        assert 0.0 <= score <= 1.0
        assert score >= previous
        previous = score


def test_scoring_maps_features_by_name_not_position(trained_model):
    # Cette méthode permet de vérifier (finding 4) que l'ordre des variables dans le JSON n'a aucune influence.
    shuffled = model_mod.RobustZScoreModel.from_dict(json.loads(json.dumps(trained_model.to_dict())))
    shuffled.params["payment-api"]["features"] = list(reversed(shuffled.params["payment-api"]["features"]))
    values = dict(_normal_baseline()["payment-api"], invalid_tokens_per_min=60.0)
    assert shuffled.score_values("payment-api", values) == trained_model.score_values("payment-api", values)


def test_model_with_other_features_is_refused(trained_model, tmp_path):
    # Cette méthode permet de vérifier (finding 4) qu'un modèle aux services ou variables différents est refusé au chargement.
    data = trained_model.to_dict()
    renamed = json.loads(json.dumps(data))
    sp = renamed["params"]["auth-service"]
    sp["features"] = [("old_name" if n == "req_rate" else n) for n in sp["features"]]
    sp["median"]["old_name"] = sp["median"].pop("req_rate")
    sp["scale"]["old_name"] = sp["scale"].pop("req_rate")
    path = tmp_path / "test-model.json"
    path.write_text(json.dumps(renamed))
    with pytest.raises(model_mod.ModelMismatch):
        model_mod.RobustZScoreModel.load(path, expected=features.expected_features())
    missing_service = json.loads(json.dumps(data))
    del missing_service["params"]["frontend"]
    path.write_text(json.dumps(missing_service))
    with pytest.raises(model_mod.ModelMismatch):
        model_mod.RobustZScoreModel.load(path, expected=features.expected_features())


# ----------------------------------------------------------------- désignation du modèle (finding 3)

def test_pointer_selects_model_not_filename_order(trained_model, tmp_path, clean_env):
    # Cette méthode permet de vérifier que le pointeur CURRENT désigne le modèle, quel que soit l'ordre des noms
    # (« rz-2026-10-19.json » trie après « -v2 », « -v10 » avant « -v2 »).
    from app import main

    for version in ("rz-2026-10-19", "rz-2026-10-19-v2", "rz-2026-10-19-v10"):
        model_mod.RobustZScoreModel(version, trained_model.params, trained_model.meta).save(tmp_path / f"{version}.json")
    (tmp_path / "CURRENT").write_text("rz-2026-10-19-v2.json\n")
    clean_env.setenv("MODEL_DIR", str(tmp_path))
    assert main.load_model().version == "rz-2026-10-19-v2"


def test_several_models_without_pointer_are_refused(trained_model, tmp_path, clean_env):
    # Cette méthode permet de vérifier qu'aucun modèle n'est choisi « au hasard » quand le pointeur manque.
    from app import main

    for version in ("rz-a", "rz-b"):
        model_mod.RobustZScoreModel(version, trained_model.params, trained_model.meta).save(tmp_path / f"{version}.json")
    clean_env.setenv("MODEL_DIR", str(tmp_path))
    with pytest.raises(main.ModelSelectionError):
        main.load_model()
    (tmp_path / "CURRENT").write_text("../rz-a.json")
    with pytest.raises(main.ModelSelectionError):
        main.load_model()


def test_repository_deploys_the_pointed_model(clean_env):
    # Cette méthode permet de vérifier le modèle réellement embarqué : pointeur présent, fichier cohérent avec sa
    # version, variables conformes au code, même modèle désigné dans ml/model/ (trace expérimentale).
    from app import main

    model = main.load_model()
    pointer = (DETECTOR / "model" / "CURRENT").read_text().strip()
    assert pointer == f"{model.version}.json"
    assert (REPO / "ml" / "model" / "CURRENT").read_text().strip() == pointer
    assert model.version == "rz-2026-10-19-v3"
    assert model.threshold == model_mod.THRESHOLD


# ----------------------------------------------------------------- inférence / robustesse

def test_score_once_uses_shared_feature_code(trained_model):
    # Cette méthode permet de vérifier la fonction d'inférence de bout en bout avec de faux clients.
    from app.main import score_once

    values = _normal_baseline()
    values["payment-api"]["invalid_tokens_per_min"] = 80.0  # rafale de jetons invalides
    prom, loki = make_clients(values)
    results, errors = score_once(prom, loki, trained_model)
    assert errors == {}
    assert results["payment-api"]["score"] > 0.8 and results["payment-api"]["complete"]
    assert results["auth-service"]["score"] < 0.8


def test_score_is_nan_before_first_cycle(trained_model):
    # Cette méthode permet de vérifier (finding 1) qu'avant tout cycle le score vaut NaN (« pas de donnée »), pas 0.
    from app.main import Detector

    prom, loki = make_clients(_normal_baseline())
    Detector(trained_model, prom, loki)
    assert math.isnan(gauge("anomaly_score", service="auth-service"))
    assert gauge("anomaly_data_available", service="auth-service") == 0


def test_stale_score_is_dropped_after_n_missed_cycles(trained_model):
    # Cette méthode permet de vérifier (finding 1) qu'un score élevé n'est pas maintenu pendant toute une panne :
    # conservé N-1 cycles (micro-coupure), puis remplacé par NaN avec anomaly_data_available = 0.
    from app.main import Detector

    values = _normal_baseline()
    values["auth-service"]["login_failures_per_min"] = 40.0
    prom, loki = make_clients(values)
    detector = Detector(trained_model, prom, loki, stale_after=3)
    detector.run_cycle()
    high = gauge("anomaly_score", service="auth-service")
    assert high > 0.8 and gauge("anomaly_data_available", service="auth-service") == 1
    prom.error = SourceUnavailable("prometheus down")
    for _ in range(2):
        detector.run_cycle()
        assert gauge("anomaly_score", service="auth-service") == high
        assert detector.service_state["auth-service"] == "stale"
    detector.run_cycle()
    assert math.isnan(gauge("anomaly_score", service="auth-service"))
    assert gauge("anomaly_data_available", service="auth-service") == 0
    assert detector.service_state["auth-service"] == "no_data" and detector.degraded
    assert gauge("anomaly_detector_source_up", source="prometheus") == 0
    prom.error = None
    detector.run_cycle()
    assert gauge("anomaly_score", service="auth-service") == high and not detector.source_errors


def test_loki_outage_degrades_only_loki_services(trained_model):
    # Cette méthode permet de vérifier (finding 2) qu'une panne de Loki n'empêche pas de scorer auth-service
    # (100 % Prometheus) et que les variables Loki manquantes ne passent pas pour « normales ».
    from app.main import Detector, score_once

    prom, loki = make_clients(_normal_baseline())
    loki.error = SourceUnavailable("loki down")
    results, errors = score_once(prom, loki, trained_model)
    assert set(errors) == {"loki"} and loki.calls == 1  # les requêtes Loki suivantes sont sautées
    assert results["auth-service"]["complete"]
    assert results["payment-api"]["missing"] == LOKI_FEATURES["payment-api"]
    assert results["frontend"]["missing"] == LOKI_FEATURES["frontend"]
    detector = Detector(trained_model, prom, loki, stale_after=1)
    detector.run_cycle()
    assert detector.service_state == {"auth-service": "ok", "payment-api": "no_data", "frontend": "no_data"}
    assert gauge("anomaly_data_available", service="auth-service") == 1
    assert math.isnan(gauge("anomaly_score", service="payment-api"))
    assert gauge("anomaly_detector_source_up", source="loki") == 0
    assert gauge("anomaly_detector_source_up", source="prometheus") == 1


def test_partial_score_is_exposed_only_when_it_already_crosses_the_threshold(trained_model):
    # Cette méthode permet de vérifier que, Loki en panne, une indisponibilité vue par Prometheus (sonde en échec)
    # reste détectée : la sévérité partielle est un minorant, donc un dépassement partiel est un dépassement certain.
    from app.main import Detector

    values = _normal_baseline()
    values["payment-api"]["probe_failed"] = 1.0
    prom, loki = make_clients(values)
    loki.error = SourceUnavailable("loki down")
    detector = Detector(trained_model, prom, loki, stale_after=1)
    detector.run_cycle()
    assert detector.service_state["payment-api"] == "partial"
    assert gauge("anomaly_score", service="payment-api") > 0.8
    assert gauge("anomaly_data_available", service="payment-api") == 0


def test_threshold_has_a_single_source_of_truth(trained_model):
    # Cette méthode permet de vérifier (finding 9) que le seuil vient du modèle, est exposé, comparé avec « ≥ »
    # par le service comme par la règle Prometheus, et n'est plus réglable par variable d'environnement.
    from app.main import Detector

    prom, loki = make_clients(_normal_baseline())
    detector = Detector(trained_model, prom, loki)
    assert gauge("anomaly_threshold") == trained_model.threshold == model_mod.THRESHOLD
    detector._log_transition("auth-service", {"score": detector.threshold, "severity": 1.0,
                                              "dominant_feature": "req_rate", "complete": True})
    assert detector._alerting["auth-service"]  # score égal au seuil ⇒ anomalie (≥)
    rules = yaml.safe_load((REPO / "infra" / "prometheus" / "rules" / "availability.yml").read_text())
    exprs = {r["alert"]: r["expr"] for g in rules["groups"] for r in g["rules"]}
    assert ">=" in exprs["AnomalyDetected"] and "anomaly_threshold" in exprs["AnomalyDetected"]
    assert "0.8" not in exprs["AnomalyDetected"]
    assert "ANOMALY_THRESHOLD" not in (REPO / "docker-compose.yml").read_text()


def test_detector_health_alerts_never_target_business_services():
    # Cette méthode permet de vérifier (finding 5) que la santé du détecteur est surveillée par des alertes dédiées,
    # étiquetées sur anomaly-detector et dont l'annotation proscrit toute action sur les services métier.
    rules = yaml.safe_load((REPO / "infra" / "prometheus" / "rules" / "availability.yml").read_text())
    by_name = {r["alert"]: r for g in rules["groups"] for r in g["rules"]}
    for name, metric in (("AnomalyDetectorBlind", "anomaly_detector_source_up"),
                         ("AnomalyDetectorDown", "anomaly_detector_last_run_timestamp")):
        rule = by_name[name]
        assert metric in rule["expr"]
        assert rule["labels"]["service"] == "anomaly-detector" and rule["labels"]["severity"] == "warning"
        assert "métier" in rule["annotations"]["description"]


def test_run_cycle_survives_unavailable_source(trained_model):
    # Cette méthode permet de vérifier que la boucle ne plante pas quand toutes les sources tombent.
    from app.main import Detector

    prom = FakeClient({}, error=SourceUnavailable("prometheus down"))
    loki = FakeClient({}, error=SourceUnavailable("loki down"))
    detector = Detector(trained_model, prom, loki)
    detector.run_cycle()  # ne doit pas lever
    assert detector.degraded and set(detector.source_errors) == {"prometheus", "loki"}


def test_service_exposes_metrics_with_unreachable_sources(clean_env, tmp_path, trained_model):
    # Cette méthode permet de vérifier le contrat HTTP (/health, /metrics) avec Prometheus/Loki injoignables.
    from fastapi.testclient import TestClient

    from app import main

    clean_env.setenv("MODEL_PATH", str(trained_model.save(tmp_path / "test-model.json")))
    with TestClient(main.app) as client:
        health = client.get("/health")
        assert health.status_code == 200 and health.json()["model_version"] == "test-model"
        metrics = client.get("/metrics").text
        assert 'anomaly_model_info{version="test-model"} 1.0' in metrics
        assert 'anomaly_score{service="auth-service"}' in metrics
        assert "anomaly_threshold 0.8" in metrics


def test_service_stays_up_without_model(clean_env, tmp_path):
    # Cette méthode permet de vérifier qu'un modèle absent ne fait pas planter le service (pas de crash-loop).
    from fastapi.testclient import TestClient

    from app import main

    clean_env.setenv("MODEL_PATH", str(tmp_path / "absent.json"))
    with TestClient(main.app) as client:
        health = client.get("/health")
        assert health.status_code == 503 and health.json()["status"] == "no_model"
        assert client.get("/metrics").status_code == 200


def test_service_refuses_mismatching_model_visibly(clean_env, tmp_path, trained_model):
    # Cette méthode permet de vérifier (finding 4) qu'un modèle incohérent est refusé et que /health l'explique.
    from fastapi.testclient import TestClient

    from app import main

    data = json.loads(json.dumps(trained_model.to_dict()))
    del data["params"]["frontend"]
    path = tmp_path / "test-model.json"
    path.write_text(json.dumps(data))
    clean_env.setenv("MODEL_PATH", str(path))
    with TestClient(main.app) as client:
        body = client.get("/health").json()
        assert body["status"] == "no_model" and body["reason"].startswith("model_mismatch")


def test_unreadable_secret_reports_degraded_instead_of_crashing(clean_env, tmp_path, trained_model):
    # Cette méthode permet de vérifier (finding 11) qu'un fichier de mot de passe absent ne fait pas planter le
    # démarrage : le service reste debout et /health l'indique (auth_secret_unreadable).
    from fastapi.testclient import TestClient

    from app import main

    clean_env.setenv("MODEL_PATH", str(trained_model.save(tmp_path / "test-model.json")))
    clean_env.setenv("PROMETHEUS_PASSWORD_FILE", str(tmp_path / "absent-secret"))
    with TestClient(main.app) as client:
        health = client.get("/health")
        assert health.status_code == 503
        assert health.json() == {"service": "anomaly-detector", "status": "degraded", "reason": "auth_secret_unreadable"}
        assert client.get("/metrics").status_code == 200


def test_empty_prometheus_result_is_nan():
    # Cette méthode permet de vérifier qu'un résultat Prometheus vide devient NaN (puis comblé en aval), sans erreur.
    assert math.isnan(_scalar_from_vector([]))
    assert _scalar_from_vector([{"value": [123, "0.5"]}]) == 0.5


def test_prometheus_client_sends_basic_auth(monkeypatch):
    # Cette méthode permet de vérifier que le client s'authentifie auprès de Prometheus (admin / mot de passe du secret)
    # et n'envoie aucun identifiant à une source non protégée (Loki interne).
    import base64
    import io
    import uuid

    seen = []
    password = uuid.uuid4().hex

    def fake_urlopen(request, timeout):
        seen.append(request)
        body = {"status": "success", "data": {"result": [{"value": [0, "1"]}]}}
        return io.BytesIO(json.dumps(body).encode())

    monkeypatch.setattr(promclient.urllib.request, "urlopen", fake_urlopen)
    assert promclient.PrometheusClient("http://prometheus:9090", username="admin", password=password).query("up") == 1.0
    assert promclient.LokiClient("http://loki:3100").query("count_over_time({service=\"waf\"}[1m])") == 1.0
    expected = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()
    assert seen[0].get_header("Authorization") == expected
    assert seen[1].get_header("Authorization") is None


# ----------------------------------------------------------------- ml/train.py (findings 6 et 8)

def test_evaluation_preprocesses_exactly_like_production(trained_model):
    # Cette méthode permet de vérifier (finding 6) que l'évaluation comble une latence manquante avec la médiane du
    # MODÈLE (comme le service), et non avec une médiane calculée sur tout le jeu de données.
    train = load_script("train")
    service = "auth-service"
    names = features.feature_names(service)
    raw = [dict(_normal_baseline()[service], latency_p95=float("nan")),
           dict(_normal_baseline()[service], latency_p95=5.0)]  # une latence extrême ne doit pas déplacer le comblement
    samples = {service: (names, raw, [1000.0, 1010.0], [("normal", None), ("normal", None)])}
    report = train.evaluate(trained_model, samples, [], train_until=0)
    expected = trained_model.score_values(service, features.clean_values(service, raw[0], trained_model.medians(service)))
    first = trained_model.score_values(service, dict(raw[0], latency_p95=trained_model.medians(service)["latency_p95"]))
    assert expected == first
    assert report["normal_samples"]["heldout"] == 2
    assert train.training_fill_medians(service, raw[:1] + [dict(raw[0], latency_p95=0.4)])["latency_p95"] == 0.4


def test_evaluation_reports_every_window_of_a_repeated_scenario(trained_model):
    # Cette méthode permet de vérifier (finding 8) qu'un scénario joué deux fois donne deux fenêtres distinctes,
    # chacune avec ses propres bornes et délais, au lieu d'hériter de la première.
    train = load_script("train")
    service = "auth-service"
    names = features.feature_names(service)
    labels = [{"id": 0, "scenario": "brute_force", "service": service, "start": 1000.0, "end": 1060.0},
              {"id": 1, "scenario": "brute_force", "service": service, "start": 2000.0, "end": 2060.0}]
    timestamps = [1000.0 + 10 * i for i in range(7)] + [2000.0 + 10 * i for i in range(7)]
    attack = dict(_normal_baseline()[service], login_failures_per_min=50.0)
    raw = [dict(_normal_baseline()[service])] * 2 + [attack] * 5 + [attack] * 7  # 1re fenêtre détectée plus tard
    phases = [train.phase_of(ts, service, labels) for ts in timestamps]
    report = train.evaluate(trained_model, {service: (names, raw, timestamps, phases)}, labels, train_until=0)
    entry = report["scenarios"][f"brute_force@{service}"]
    assert entry["windows"] == 2 and entry["windows_alerted"] == 2
    assert [w["start"] for w in entry["per_window"]] == [1000.0, 2000.0]
    assert [w["alert_delay_s"] for w in entry["per_window"]] == [40.0, 20.0]
    assert report["windows_alerted"] == "2/2"


# ----------------------------------------------------------------- ml/attack_scenarios.py (finding 7)

class _Done:
    def __init__(self, code):
        self.returncode, self.stdout, self.stderr = code, "", "erreur simulée" if code else ""


def test_failed_docker_stop_records_no_label(tmp_path, monkeypatch):
    # Cette méthode permet de vérifier qu'un arrêt de conteneur raté n'est pas étiqueté comme incident.
    attacks = load_script("attack_scenarios")
    monkeypatch.setattr(attacks.subprocess, "run", lambda *a, **k: _Done(1))
    labels = tmp_path / "labels.csv"
    assert attacks.run_one("http://127.0.0.1:9", "stop_payment", 0, "payment", True, labels) is False
    assert not labels.exists()


def test_scenario_without_expected_responses_records_no_label(tmp_path, monkeypatch):
    # Cette méthode permet de vérifier qu'une attaque qui n'atteint pas la stack (aucune réponse) n'est pas étiquetée,
    # et que transfer_abuse sans jeton s'arrête au lieu d'envoyer des requêtes anonymes.
    attacks = load_script("attack_scenarios")
    monkeypatch.setattr(attacks, "_request", lambda *a, **k: 0)
    monkeypatch.setattr(attacks.time, "sleep", lambda s: None)
    labels = tmp_path / "labels.csv"
    assert attacks.run_one("http://127.0.0.1:9", "waf_probe", 0.05, None, False, labels) is False
    assert attacks.run_one("http://127.0.0.1:9", "transfer_abuse", 0.05, None, False, labels) is False
    assert not labels.exists()
    monkeypatch.setattr(attacks, "_request", lambda *a, **k: 403)
    assert attacks.run_one("http://127.0.0.1:9", "waf_probe", 0.05, None, False, labels) is True
    assert labels.read_text().count("waf_probe") == 1


def test_container_is_derived_from_compose_labels(monkeypatch):
    # Cette méthode permet de vérifier que le conteneur visé est retrouvé par les labels du projet Compose.
    attacks = load_script("attack_scenarios")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        done = _Done(0)
        done.stdout = "abc123\n"
        return done

    assert attacks.resolve_container("mon-projet", "payment-api", run=fake_run) == "abc123"
    assert "label=com.docker.compose.project=mon-projet" in calls[0]
    assert attacks.check_responses("x", Counter({401: 9, 0: 1}), {401})


# ----------------------------------------------------------------- ml/generate_normal.py (finding 10)

def test_generator_draws_reproducible_decisions():
    # Cette méthode permet de vérifier que la suite de décisions ne dépend que de la graine.
    import random

    gen = load_script("generate_normal")
    first, second = random.Random(7), random.Random(7)
    assert [gen.draw_decision(first) for _ in range(50)] == [gen.draw_decision(second) for _ in range(50)]


def test_generator_bounds_in_flight_work():
    # Cette méthode permet de vérifier qu'une saturation fait ignorer les actions en trop au lieu de les empiler.
    gen = load_script("generate_normal")
    release = threading.Event()
    scheduler = gen.Scheduler(lambda decision: release.wait(5), max_in_flight=2)
    accepted = [scheduler.submit({}) for _ in range(5)]
    assert accepted == [True, True, False, False, False]
    assert scheduler.started == 2 and scheduler.skipped == 3
    release.set()
    scheduler.drain(5)
    assert scheduler.submit({}) is True
    release.set()
    scheduler.drain(5)
