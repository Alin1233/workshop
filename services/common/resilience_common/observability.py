"""Journaux JSON (consommés par Loki) et métriques HTTP (scrapées par Prometheus)."""

import json
import logging
import sys
import time
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

HTTP_REQUESTS = Counter(
    "http_requests_total",
    "Requêtes HTTP traitées",
    ["service", "method", "route", "status"],
)
HTTP_LATENCY = Histogram(
    "http_request_duration_seconds",
    "Durée de traitement des requêtes HTTP",
    ["service", "method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

_RESERVED = set(vars(logging.makeLogRecord({}))) | {"color_message"}
# Routes sondées en boucle (healthchecks, scrapes) : comptées en métriques mais pas journalisées.
_QUIET_ROUTES = {"/health", "/metrics"}


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str):
        # Cette méthode permet de mémoriser le nom du service à inscrire dans chaque ligne de journal.
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        # Cette méthode permet de sérialiser un enregistrement de log en une ligne JSON,
        # en y ajoutant les champs passés via `extra=` pour qu'ils soient filtrables dans Loki.
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "service": self.service,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(service: str, level: str = "INFO") -> logging.Logger:
    # Cette méthode permet de router tous les journaux (application et uvicorn) vers stdout au format JSON.
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = True
    # Le journal d'accès est remplacé par celui du middleware, plus riche.
    logging.getLogger("uvicorn.access").disabled = True
    return logging.getLogger(service)


def client_ip(request: Request) -> str:
    # Cette méthode permet de retrouver l'IP d'origine lorsque la requête traverse le reverse proxy nginx.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def instrument(app: FastAPI, service: str) -> None:
    # Cette méthode permet d'ajouter à l'application un middleware de logs/métriques par requête
    # et d'exposer l'endpoint /metrics pour Prometheus.
    logger = logging.getLogger(f"{service}.access")

    @app.middleware("http")
    async def observe(request: Request, call_next):
        # Cette méthode permet de mesurer chaque requête, de propager un identifiant de corrélation et de journaliser le résultat.
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["x-request-id"] = request_id
            return response
        finally:
            elapsed = time.perf_counter() - start
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            if route_path != "/metrics":
                HTTP_REQUESTS.labels(service, request.method, route_path, str(status)).inc()
                HTTP_LATENCY.labels(service, request.method, route_path).observe(elapsed)
            if route_path not in _QUIET_ROUTES or status >= 400:
                logger.info(
                    "http_request",
                    extra={
                        "request_id": request_id,
                        "method": request.method,
                        "path": request.url.path,
                        "route": route_path,
                        "status": status,
                        "duration_ms": round(elapsed * 1000, 2),
                        "client_ip": client_ip(request),
                        "user_id": getattr(request.state, "user_id", None),
                        "user_agent": request.headers.get("user-agent"),
                    },
                )

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        # Cette méthode permet d'exposer les métriques au format texte Prometheus.
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
