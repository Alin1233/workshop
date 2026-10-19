"""Tests unitaires du détecteur d'anomalies : variables, normalisation du score, inférence, robustesse.

Ces tests tournent SANS la stack (ni Prometheus ni Loki) : on injecte de faux clients. Ils couvrent le
calcul des variables, le comblement des valeurs manquantes, l'apprentissage/scoring du modèle robuste,
la boucle d'inférence et sa résistance aux sources vides ou injoignables.
"""

import math
import sys
from pathlib import Path

import pytest

# Le code des variables/modèle est partagé avec le service : on l'importe depuis son paquet `app`.
DETECTOR = Path(__file__).resolve().parents[2] / "services" / "anomaly-detector"
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


# ----------------------------------------------------------------- variables

def test_extract_instant_maps_each_service():
    # Cette méthode permet de vérifier que chaque service reçoit toutes ses variables depuis le bon client.
    prom, loki = make_clients(_normal_baseline())
    observations = features.extract_instant(prom, loki)
    assert set(observations) == set(features.SERVICES)
    assert observations["auth-service"]["req_rate"] == 1.0
    assert observations["payment-api"]["req_rate"] == 1.5
    assert observations["frontend"]["req_rate_per_min"] == 120.0


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


def test_clean_vector_fills_missing_values():
    # Cette méthode permet de vérifier le comblement : "zero" pour l'absence d'activité, "median" pour la latence.
    medians = {"latency_p95": 0.2}
    values = {"req_rate": float("nan"), "latency_p95": float("nan"), "error_ratio_5xx": 0.0,
              "login_failures_per_min": 3.0, "client_errors_4xx_rate": float("nan"), "probe_failed": float("nan")}
    vector = features.clean_vector("auth-service", values, medians)
    names = features.feature_names("auth-service")
    assert vector[names.index("req_rate")] == 0.0  # nan_fill="zero"
    assert vector[names.index("latency_p95")] == 0.2  # nan_fill="median"
    assert vector[names.index("login_failures_per_min")] == 3.0


# ----------------------------------------------------------------- modèle / score

def test_idle_scores_near_zero(trained_model):
    # Cette méthode permet de garantir qu'une période creuse (aucune activité) ne déclenche aucune anomalie.
    for service in features.SERVICES:
        zeros = [0.0] * len(features.feature_names(service))
        result = trained_model.score_vector(service, zeros)
        assert result["score"] < 0.2, (service, result)


def test_normal_load_below_threshold(trained_model):
    # Cette méthode permet de garantir qu'une charge ordinaire reste sous le seuil d'alerte (0,8).
    baseline = _normal_baseline()
    for service in features.SERVICES:
        names = features.feature_names(service)
        vector = [baseline[service][n] for n in names]
        assert trained_model.score_vector(service, vector)["score"] < 0.8


def test_attack_crosses_threshold(trained_model):
    # Cette méthode permet de vérifier qu'une rafale anormale (une variable qui explose) dépasse le seuil.
    names = features.feature_names("auth-service")
    vector = [0.0] * len(names)
    vector[names.index("login_failures_per_min")] = 40.0  # force brute
    result = trained_model.score_vector("auth-service", vector)
    assert result["score"] > 0.8
    assert result["dominant_feature"] == "login_failures_per_min"


def test_score_is_bounded_and_monotonic(trained_model):
    # Cette méthode permet de vérifier que le score reste dans [0, 1] et croît avec l'ampleur de l'écart.
    names = features.feature_names("frontend")
    previous = -1.0
    for blocks in (0, 5, 20, 100, 1000):
        vector = [0.0] * len(names)
        vector[names.index("waf_blocks_per_min")] = blocks
        score = trained_model.score_vector("frontend", vector)["score"]
        assert 0.0 <= score <= 1.0
        assert score >= previous
        previous = score


# ----------------------------------------------------------------- inférence / robustesse

def test_score_once_uses_shared_feature_code(trained_model):
    # Cette méthode permet de vérifier la fonction d'inférence de bout en bout avec de faux clients.
    from app.main import score_once

    values = _normal_baseline()
    values["payment-api"]["invalid_tokens_per_min"] = 80.0  # rafale de jetons invalides
    prom, loki = make_clients(values)
    results = score_once(prom, loki, trained_model)
    assert results["payment-api"]["score"] > 0.8
    assert results["auth-service"]["score"] < 0.8


def test_run_cycle_survives_unavailable_source(trained_model):
    # Cette méthode permet de vérifier que la boucle ne plante pas et conserve l'état quand une source tombe.
    from app.main import Detector

    prom = FakeClient({}, error=SourceUnavailable("prometheus down"))
    loki = FakeClient({})
    detector = Detector(trained_model, prom, loki, threshold=0.8)
    detector.run_cycle()  # ne doit pas lever
    assert detector._degraded is True


def test_service_exposes_metrics_with_unreachable_sources(monkeypatch, tmp_path, trained_model):
    # Cette méthode permet de vérifier le contrat HTTP (/health, /metrics) avec Prometheus/Loki injoignables.
    from fastapi.testclient import TestClient

    from app import main

    path = trained_model.save(tmp_path / "test-model.json")
    monkeypatch.setenv("MODEL_PATH", str(path))
    monkeypatch.setenv("PROMETHEUS_URL", "http://127.0.0.1:9")  # port fermé : refus immédiat
    monkeypatch.setenv("LOKI_URL", "http://127.0.0.1:9")
    with TestClient(main.app) as client:
        health = client.get("/health")
        assert health.status_code == 200 and health.json()["model_version"] == "test-model"
        metrics = client.get("/metrics").text
        assert 'anomaly_model_info{version="test-model"} 1.0' in metrics
        assert 'anomaly_score{service="auth-service"}' in metrics


def test_service_stays_up_without_model(monkeypatch, tmp_path):
    # Cette méthode permet de vérifier qu'un modèle absent ne fait pas planter le service (pas de crash-loop).
    from fastapi.testclient import TestClient

    from app import main

    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "absent.json"))
    with TestClient(main.app) as client:
        health = client.get("/health")
        assert health.status_code == 503 and health.json()["status"] == "no_model"
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
    import json

    seen = []

    def fake_urlopen(request, timeout):
        seen.append(request)
        body = {"status": "success", "data": {"result": [{"value": [0, "1"]}]}}
        return io.BytesIO(json.dumps(body).encode())

    monkeypatch.setattr(promclient.urllib.request, "urlopen", fake_urlopen)
    assert promclient.PrometheusClient("http://prometheus:9090", username="admin", password="s3cret").query("up") == 1.0
    assert promclient.LokiClient("http://loki:3100").query("count_over_time({service=\"waf\"}[1m])") == 1.0
    expected = "Basic " + base64.b64encode(b"admin:s3cret").decode()
    assert seen[0].get_header("Authorization") == expected
    assert seen[1].get_header("Authorization") is None
