"""Service d'inférence du détecteur d'anomalies.

Boucle toutes les `SCRAPE_INTERVAL` secondes : interroge Prometheus (et Loki), calcule les variables
avec exactement le même code que l'entraînement (`app.features`), scoure chaque service avec le modèle
appris (`app.model`) et expose le résultat sur `/metrics` :
- `anomaly_score{service}` (0..1, NaN = pas de donnée) — consommé par la règle `AnomalyDetected` ;
- `anomaly_threshold` — seuil de calibration du modèle, lu par cette même règle (source unique du seuil) ;
- `anomaly_severity{service}` — sévérité brute (distance robuste), utile au diagnostic ;
- `anomaly_data_available{service}` — 1 si le score du dernier cycle repose sur des données complètes ;
- `anomaly_model_info{version}` — version du modèle chargé ;
- `anomaly_detector_source_up{source}` / `anomaly_detector_source_degraded` — état des sources ;
- `anomaly_detector_last_run_timestamp` — fin du dernier cycle (boucle vivante).

Dégradation (jamais de plantage, jamais de « normal » inventé) :
- une source injoignable rend ses variables manquantes, service par service (cf. `features.extract_instant`) ;
- un service incomplet n'est rescoré que si le score partiel atteint déjà le seuil : la sévérité partielle est un
  minorant de la sévérité complète, la détection est donc certaine ; sinon il est « périmé » ;
- un score périmé est conservé `STALE_AFTER_CYCLES` cycles au plus (micro-coupure), puis remplacé par NaN avec
  `anomaly_data_available=0` : une panne de Loki ne maintient pas indéfiniment une alerte, et ne fait pas croire
  non plus que tout va bien ;
- modèle absent/incohérent, ou secret illisible : le service reste debout, `/health` répond 503 avec la raison.
Les transitions sont journalisées en JSON (`event_type=anomaly_detected|anomaly_cleared|anomaly_unknown|
anomaly_degraded|anomaly_recovered`), le service concerné dans `target_service`.
"""

import math
import os
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from prometheus_client import Gauge

from resilience_common.observability import instrument, setup_logging
from resilience_common.settings import env, secret

from . import features
from .model import ModelMismatch, RobustZScoreModel
from .promclient import LokiClient, PrometheusClient, now

SERVICE = "anomaly-detector"
SOURCES = {"prom": "prometheus", "loki": "loki"}
POINTER = "CURRENT"  # fichier du répertoire des modèles désignant le modèle actif (nom de fichier)
logger = setup_logging(SERVICE, env("LOG_LEVEL", "INFO"))

ANOMALY_SCORE = Gauge("anomaly_score", "Score d'anomalie (0..1, NaN si pas de donnée) par service", ["service"])
ANOMALY_SEVERITY = Gauge("anomaly_severity", "Sévérité brute (distance robuste) par service", ["service"])
DATA_AVAILABLE = Gauge("anomaly_data_available", "1 si le score du dernier cycle repose sur des données complètes", ["service"])
THRESHOLD = Gauge("anomaly_threshold", "Seuil d'alerte pour lequel le modèle est calibré (lu par AnomalyDetected)")
MODEL_INFO = Gauge("anomaly_model_info", "Modèle chargé (toujours 1, label version)", ["version"])
SOURCE_UP = Gauge("anomaly_detector_source_up", "1 si la source répond, 0 si injoignable", ["source"])
SOURCE_DEGRADED = Gauge("anomaly_detector_source_degraded", "1 si au moins une source de données est injoignable")
LAST_RUN = Gauge("anomaly_detector_last_run_timestamp", "Horodatage de fin du dernier cycle d'inférence")


class ModelSelectionError(RuntimeError):
    """Aucun modèle désigné sans ambiguïté (pointeur absent avec plusieurs modèles, fichier introuvable…)."""


def _optional_secret(name: str) -> str | None:
    # Cette méthode permet de lire un mot de passe facultatif (<NAME>_FILE ou <NAME>) : Prometheus en exige un,
    # Loki interne non. Lève OSError si le fichier désigné est absent ou illisible (traité par le démarrage).
    if os.getenv(f"{name}_FILE") or os.getenv(name):
        return secret(name)
    return None


def _resolve_model_path() -> Path:
    # Cette méthode permet de désigner le modèle actif de façon déterministe, sans tri de noms de fichiers :
    # 1) MODEL_PATH explicite ; 2) le pointeur MODEL_DIR/CURRENT (nom du fichier, écrit par ml/train.py) ;
    # 3) à défaut de pointeur, l'unique *.json du répertoire. Plusieurs modèles sans pointeur ⇒ refus.
    explicit = env("MODEL_PATH", "")
    if explicit:
        return Path(explicit)
    model_dir = Path(env("MODEL_DIR", str(Path(__file__).resolve().parent.parent / "model")))
    pointer = model_dir / POINTER
    if pointer.exists():
        name = pointer.read_text(encoding="utf-8").strip()
        if not name or Path(name).name != name:
            raise ModelSelectionError(f"pointeur {pointer} invalide : {name!r} (un nom de fichier est attendu)")
        target = model_dir / name
        if not target.is_file():
            raise ModelSelectionError(f"le pointeur {pointer} désigne {name}, introuvable")
        return target
    candidates = list(model_dir.glob("*.json"))
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise ModelSelectionError(f"aucun modèle (*.json) dans {model_dir}")
    raise ModelSelectionError(f"{len(candidates)} modèles dans {model_dir} et pas de pointeur {POINTER}")


def load_model() -> RobustZScoreModel:
    # Cette méthode permet de charger le modèle actif et de le valider contre les variables du code ; la version
    # inscrite dans le JSON doit correspondre au nom du fichier désigné (pas de modèle renommé par erreur).
    path = _resolve_model_path()
    model = RobustZScoreModel.load(path, expected=features.expected_features())
    if model.version != path.stem:
        raise ModelMismatch(f"version {model.version!r} du JSON ≠ fichier {path.name}")
    return model


def score_once(prom: PrometheusClient, loki: LokiClient, model: RobustZScoreModel,
               at: float | None = None) -> tuple[dict[str, dict], dict[str, str]]:
    # Cette méthode permet de calculer les scores de tous les services à un instant donné (fonction pure, testable).
    # Chaque résultat indique s'il est complet et quelles variables manquent ; renvoie aussi les sources en échec.
    observations, errors = features.extract_instant(prom, loki, at)
    results: dict[str, dict] = {}
    for service in features.SERVICES:
        obs = observations[service]
        cleaned = features.clean_values(service, obs.values, model.medians(service))
        result = model.score_values(service, cleaned)
        result["complete"] = obs.complete
        result["missing"] = list(obs.missing)
        results[service] = result
    return results, errors


class Detector:
    """Encapsule l'état de la boucle d'inférence (scores, fraîcheur, état des sources, journalisation)."""

    def __init__(self, model: RobustZScoreModel, prom: PrometheusClient, loki: LokiClient, stale_after: int = 3):
        # Cette méthode permet d'initialiser le détecteur : tant qu'aucun cycle n'a abouti, le score vaut NaN
        # (« pas encore de donnée ») et non 0, qui ferait croire à un comportement normal.
        self.model = model
        self.prom = prom
        self.loki = loki
        self.threshold = model.threshold
        self.stale_after = max(1, stale_after)
        self._alerting: dict[str, bool] = {service: False for service in features.SERVICES}
        self._missed: dict[str, int] = {service: 0 for service in features.SERVICES}
        self.service_state: dict[str, str] = {service: "no_data" for service in features.SERVICES}
        self.source_errors: dict[str, str] = {}
        MODEL_INFO.labels(model.version).set(1)
        THRESHOLD.set(self.threshold)
        for service in features.SERVICES:
            ANOMALY_SCORE.labels(service).set(math.nan)
            ANOMALY_SEVERITY.labels(service).set(math.nan)
            DATA_AVAILABLE.labels(service).set(0)
        for source in SOURCES.values():
            SOURCE_UP.labels(source).set(1)
        SOURCE_DEGRADED.set(0)

    @property
    def degraded(self) -> bool:
        # Cette méthode permet de savoir si le détecteur fonctionne en mode dégradé (source en échec ou service sans donnée).
        return bool(self.source_errors) or any(state != "ok" for state in self.service_state.values())

    def run_cycle(self) -> None:
        # Cette méthode permet d'exécuter une évaluation : met à jour les métriques et journalise les transitions.
        results, errors = score_once(self.prom, self.loki, self.model)
        self._update_sources(errors)
        for service, result in results.items():
            if result["complete"] or result["score"] >= self.threshold:
                # Complet, ou partiel mais déjà au-dessus du seuil (minorant ⇒ détection certaine) : score frais.
                self._missed[service] = 0
                self.service_state[service] = "ok" if result["complete"] else "partial"
                ANOMALY_SCORE.labels(service).set(result["score"])
                ANOMALY_SEVERITY.labels(service).set(result["severity"])
                DATA_AVAILABLE.labels(service).set(1 if result["complete"] else 0)
                self._log_transition(service, result)
                continue
            self._missed[service] += 1
            DATA_AVAILABLE.labels(service).set(0)
            if self._missed[service] >= self.stale_after:
                # Plus de donnée exploitable depuis trop longtemps : on cesse d'exposer un score périmé.
                if self.service_state[service] != "no_data":
                    logger.warning("anomaly_unknown", extra={"event_type": "anomaly_unknown", "target_service": service,
                                                              "missing": result["missing"]})
                self.service_state[service] = "no_data"
                ANOMALY_SCORE.labels(service).set(math.nan)
                ANOMALY_SEVERITY.labels(service).set(math.nan)
                self._alerting[service] = False
            else:
                self.service_state[service] = "stale"  # dernier score conservé, encore récent
        LAST_RUN.set(now())

    def _update_sources(self, errors: dict[str, str]) -> None:
        # Cette méthode permet de suivre l'état de chaque source et de journaliser pannes et retours.
        named = {SOURCES[key]: message for key, message in errors.items()}
        for source in SOURCES.values():
            if source in named and source not in self.source_errors:
                logger.warning("source_unavailable", extra={"event_type": "anomaly_degraded", "source": source,
                                                            "error": named[source]})
            elif source not in named and source in self.source_errors:
                logger.info("source_recovered", extra={"event_type": "anomaly_recovered", "source": source})
            SOURCE_UP.labels(source).set(0 if source in named else 1)
        self.source_errors = named
        SOURCE_DEGRADED.set(1 if named else 0)

    def _log_transition(self, service: str, result: dict) -> None:
        # Cette méthode permet de journaliser l'entrée et la sortie d'état d'anomalie (sans spammer à chaque cycle).
        # Le service concerné va dans `target_service` : le champ `service` reste celui de l'émetteur (anomaly-detector).
        above = result["score"] >= self.threshold
        if above and not self._alerting[service]:
            logger.warning(
                "anomaly_detected",
                extra={
                    "event_type": "anomaly_detected", "target_service": service, "anomaly_score": result["score"],
                    "severity": result["severity"], "dominant_feature": result["dominant_feature"],
                    "complete": result["complete"],
                },
            )
        elif not above and self._alerting[service]:
            logger.info(
                "anomaly_cleared",
                extra={"event_type": "anomaly_cleared", "target_service": service, "anomaly_score": result["score"]},
            )
        self._alerting[service] = above


def _loop(detector: Detector, interval: float, stop: threading.Event) -> None:
    # Cette méthode permet de faire tourner la boucle d'inférence jusqu'à l'arrêt du service, sans jamais la laisser mourir.
    while not stop.is_set():
        start = time.perf_counter()
        try:
            detector.run_cycle()
        except Exception:  # noqa: BLE001 - une erreur inattendue ne doit pas tuer la boucle (anti crash-loop)
            logger.exception("inference_cycle_failed")
        stop.wait(max(0.5, interval - (time.perf_counter() - start)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Cette méthode permet de charger le modèle, de lire les secrets et de démarrer la boucle d'inférence.
    # Toute erreur de démarrage laisse le service debout (/health en 503 avec la raison) plutôt que de boucler en échec.
    app.state.detector = None
    app.state.startup_error = None
    try:
        model = load_model()
    except ModelMismatch as exc:
        app.state.startup_error = {"status": "no_model", "reason": f"model_mismatch: {exc}"}
    except Exception as exc:  # noqa: BLE001 - modèle absent, illisible, pointeur invalide…
        app.state.startup_error = {"status": "no_model", "reason": str(exc)}
    if app.state.startup_error is None:
        try:
            prom_password = _optional_secret("PROMETHEUS_PASSWORD")
            loki_password = _optional_secret("LOKI_PASSWORD")
        except (OSError, UnicodeDecodeError) as exc:
            app.state.startup_error = {"status": "degraded", "reason": "auth_secret_unreadable"}
            logger.error("auth_secret_unreadable", extra={"event_type": "anomaly_degraded", "error": str(exc)})
    if app.state.startup_error is not None:
        if app.state.startup_error["status"] == "no_model":
            logger.error("model_unavailable", extra={"event_type": "anomaly_degraded", "error": app.state.startup_error["reason"]})
        yield
        return
    prom = PrometheusClient(env("PROMETHEUS_URL", "http://prometheus:9090"),
                            username=env("PROMETHEUS_USER", "admin"), password=prom_password)
    loki = LokiClient(env("LOKI_URL", "http://loki:3100"), username=env("LOKI_USER", "admin"), password=loki_password)
    detector = Detector(model, prom, loki, stale_after=int(env("STALE_AFTER_CYCLES", "3")))
    interval = float(env("SCRAPE_INTERVAL", "10"))
    stop = threading.Event()
    thread = threading.Thread(target=_loop, args=(detector, interval, stop), name="anomaly-loop", daemon=True)
    thread.start()
    app.state.detector = detector
    logger.info("service_started", extra={"model_version": model.version, "interval_s": interval,
                                          "threshold": detector.threshold, "stale_after_cycles": detector.stale_after})
    yield
    stop.set()
    thread.join(timeout=5)


app = FastAPI(title="Resilience-Alpha — Anomaly Detector", version="1.0.0", lifespan=lifespan)
instrument(app, SERVICE)


@app.get("/health")
def health() -> JSONResponse:
    # Cette méthode permet de décrire l'état du détecteur : 200 "ok" ; 200 "degraded" s'il fonctionne partiellement
    # (source en échec, service sans donnée fraîche, détail par source et par service) ; 503 s'il ne peut rien scorer
    # ("no_model", ou "degraded" / auth_secret_unreadable), le service restant debout dans tous les cas.
    detector = getattr(app.state, "detector", None)
    if detector is None:
        error = getattr(app.state, "startup_error", None) or {"status": "no_model", "reason": "démarrage en cours"}
        return JSONResponse({"service": SERVICE, **error}, status_code=503)
    body = {
        "service": SERVICE,
        "status": "degraded" if detector.degraded else "ok",
        "model_version": detector.model.version,
        "threshold": detector.threshold,
        "sources": {source: ("down" if source in detector.source_errors else "up") for source in SOURCES.values()},
        "services": dict(detector.service_state),
    }
    if detector.source_errors:
        body["reason"] = "source_unavailable"
    return JSONResponse(body, status_code=200)
