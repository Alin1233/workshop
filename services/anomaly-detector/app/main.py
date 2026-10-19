"""Service d'inférence du détecteur d'anomalies.

Boucle toutes les `SCRAPE_INTERVAL` secondes : interroge Prometheus (et Loki), calcule les variables
avec exactement le même code que l'entraînement (`app.features`), scoure chaque service avec le modèle
appris (`app.model`) et expose le résultat sur `/metrics` :
- `anomaly_score{service}` (0..1) — consommé par la règle Prometheus `AnomalyDetected` (> 0,8) ;
- `anomaly_severity{service}` — sévérité brute (distance robuste), utile au diagnostic ;
- `anomaly_model_info{version}` — version du modèle chargé ;
- `anomaly_detector_source_degraded` — 1 si une source (Prometheus/Loki) est momentanément injoignable.

Robustesse : si une source tombe, on conserve le dernier score et on signale l'état dégradé, sans jamais
planter la boucle. Les franchissements de seuil sont journalisés en JSON (`event_type=anomaly_detected` /
`anomaly_cleared`) pour l'investigation et la corrélation (comme les autres services).
"""

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
from .model import RobustZScoreModel
from .promclient import LokiClient, PrometheusClient, SourceUnavailable, now

SERVICE = "anomaly-detector"
logger = setup_logging(SERVICE, env("LOG_LEVEL", "INFO"))

ANOMALY_SCORE = Gauge("anomaly_score", "Score d'anomalie (0..1) par service", ["service"])
ANOMALY_SEVERITY = Gauge("anomaly_severity", "Sévérité brute (distance robuste) par service", ["service"])
MODEL_INFO = Gauge("anomaly_model_info", "Modèle chargé (toujours 1, label version)", ["version"])
SOURCE_DEGRADED = Gauge("anomaly_detector_source_degraded", "1 si une source de données est injoignable")
LAST_RUN = Gauge("anomaly_detector_last_run_timestamp", "Horodatage de la dernière évaluation réussie")


def _optional_secret(name: str) -> str | None:
    # Cette méthode permet de lire un mot de passe facultatif (<NAME>_FILE ou <NAME>) : Prometheus en exige un,
    # Loki interne non.
    if os.getenv(f"{name}_FILE") or os.getenv(name):
        return secret(name)
    return None


def _resolve_model_path() -> Path:
    # Cette méthode permet de localiser le fichier modèle : MODEL_PATH explicite, sinon le plus récent de MODEL_DIR.
    explicit = env("MODEL_PATH", "")
    if explicit:
        return Path(explicit)
    model_dir = Path(env("MODEL_DIR", str(Path(__file__).resolve().parent.parent / "model")))
    candidates = sorted(model_dir.glob("*.json"))
    if not candidates:
        raise RuntimeError(f"Aucun modèle (*.json) trouvé dans {model_dir}")
    return candidates[-1]


def score_once(prom: PrometheusClient, loki: LokiClient, model: RobustZScoreModel, at: float | None = None) -> dict[str, dict]:
    # Cette méthode permet de calculer les scores de tous les services à un instant donné (fonction pure, testable).
    observations = features.extract_instant(prom, loki, at)
    results: dict[str, dict] = {}
    for service in features.SERVICES:
        vector = features.clean_vector(service, observations[service], model.medians(service))
        results[service] = model.score_vector(service, vector)
    return results


class Detector:
    """Encapsule l'état de la boucle d'inférence (dernier score, état des sources, seuil, journalisation)."""

    def __init__(self, model: RobustZScoreModel, prom: PrometheusClient, loki: LokiClient, threshold: float):
        # Cette méthode permet d'initialiser le détecteur avec le modèle, les clients et le seuil d'alerte.
        self.model = model
        self.prom = prom
        self.loki = loki
        self.threshold = threshold
        self._alerting: dict[str, bool] = {service: False for service in features.SERVICES}
        self._degraded = False
        MODEL_INFO.labels(model.version).set(1)
        for service in features.SERVICES:
            ANOMALY_SCORE.labels(service).set(0.0)
            ANOMALY_SEVERITY.labels(service).set(0.0)
        SOURCE_DEGRADED.set(0)

    def run_cycle(self) -> None:
        # Cette méthode permet d'exécuter une évaluation : met à jour les métriques et journalise les transitions.
        try:
            results = score_once(self.prom, self.loki, self.model)
        except SourceUnavailable as exc:
            if not self._degraded:
                logger.warning("source_unavailable", extra={"event_type": "anomaly_degraded", "error": str(exc)})
            self._degraded = True
            SOURCE_DEGRADED.set(1)
            return  # on conserve le dernier score exposé
        if self._degraded:
            logger.info("source_recovered", extra={"event_type": "anomaly_recovered"})
        self._degraded = False
        SOURCE_DEGRADED.set(0)
        for service, result in results.items():
            ANOMALY_SCORE.labels(service).set(result["score"])
            ANOMALY_SEVERITY.labels(service).set(result["severity"])
            self._log_transition(service, result)
        LAST_RUN.set(now())

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
    # Cette méthode permet de charger le modèle et de démarrer la boucle d'inférence en tâche de fond au démarrage.
    # Modèle absent ou illisible : le service reste debout (/health en 503 « no_model ») plutôt que de boucler en échec.
    app.state.detector = None
    try:
        model = RobustZScoreModel.load(_resolve_model_path())
    except Exception as exc:  # noqa: BLE001
        logger.error("model_unavailable", extra={"event_type": "anomaly_degraded", "error": str(exc)})
        yield
        return
    prom = PrometheusClient(env("PROMETHEUS_URL", "http://prometheus:9090"),
                            username=env("PROMETHEUS_USER", "admin"), password=_optional_secret("PROMETHEUS_PASSWORD"))
    loki = LokiClient(env("LOKI_URL", "http://loki:3100"),
                      username=env("LOKI_USER", "admin"), password=_optional_secret("LOKI_PASSWORD"))
    threshold = float(env("ANOMALY_THRESHOLD", "0.8"))
    detector = Detector(model, prom, loki, threshold)
    interval = float(env("SCRAPE_INTERVAL", "10"))
    stop = threading.Event()
    thread = threading.Thread(target=_loop, args=(detector, interval, stop), name="anomaly-loop", daemon=True)
    thread.start()
    app.state.detector = detector
    logger.info("service_started", extra={"model_version": model.version, "interval_s": interval, "threshold": threshold})
    yield
    stop.set()
    thread.join(timeout=5)


app = FastAPI(title="Resilience-Alpha — Anomaly Detector", version="1.0.0", lifespan=lifespan)
instrument(app, SERVICE)


@app.get("/health")
def health() -> JSONResponse:
    # Cette méthode permet d'indiquer que le service est vivant ; "degraded" si une source est momentanément injoignable
    # (200 : le service fonctionne et garde son dernier score), 503 « no_model » si aucun modèle n'a pu être chargé.
    detector = getattr(app.state, "detector", None)
    if detector is None:
        return JSONResponse({"service": SERVICE, "status": "no_model"}, status_code=503)
    body = {"service": SERVICE, "status": "degraded" if detector._degraded else "ok", "model_version": detector.model.version}
    return JSONResponse(body, status_code=200)
