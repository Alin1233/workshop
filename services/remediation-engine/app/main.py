"""Moteur de remédiation — webhook Alertmanager authentifié et API d'état en lecture seule.

Routes :
- `POST /alerts` : webhook Alertmanager v4 (jeton porteur, comparaison à temps constant), réponse 202 immédiate ;
- `GET /api/state`, `GET /api/incidents`, `GET /api/incidents/{id}`, `GET /api/decision-table` : lecture seule, pour le
  dashboard de supervision (via son back-for-front) ; aucune route ne permet de déclencher une action ;
- `GET /health` (200 tant que le service sert, état dégradé détaillé dans le corps), `GET /metrics`.
Aucun port n'est publié : le moteur n'est joignable que sur les réseaux internes de la stack.
"""

import hmac
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from resilience_common.observability import client_ip, instrument, setup_logging
from resilience_common.settings import env

from . import metrics
from .config import Settings
from .decisions import table_document

SERVICE = "remediation-engine"
MAX_BODY = 1024 * 1024
logger = setup_logging(SERVICE, env("LOG_LEVEL", "INFO"))


def build_engine(settings: Settings):
    # Cette méthode permet d'assembler le moteur réel : proxy Docker, Prometheus, Loki, intégrité, témoin, et les
    # modules de blocage WAF et de pont de restauration quand ils sont disponibles (sinon : escalade, jamais d'improvisation).
    from .actions.docker_proxy import DockerProxy
    from .clients import IntegrityClient, LokiClient, PrometheusClient
    from .engine import Engine
    from .incidents import StateStore
    from .witness import Witness

    docker = DockerProxy(settings.docker_proxy_url, settings.compose_project)
    blocklist = bridge = None
    try:
        from .actions import waf_block
        # Chemin, liste d'exclusion (WAF_BLOCK_ALLOWLIST), contrôle interne du WAF : lus par le module lui-même
        blocklist = waf_block.WafBlocklist.from_env(docker)
        settings.waf_block_ttl_s = waf_block.ttl_from_env()
    except Exception as exc:  # noqa: BLE001 - module absent ou volume illisible : blocage indisponible, moteur debout
        logger.warning("waf_blocklist_unavailable", extra={"event_type": "remediation_degraded", "error": str(exc)})
    try:
        from .actions.db_restore import RestoreBridge
        if settings.bridge_dir is not None:
            bridge = RestoreBridge(settings.bridge_dir, timeout_s=settings.restore_timeout_s)
    except Exception as exc:  # noqa: BLE001 - pont absent : les corruptions confirmées seront escaladées
        logger.warning("restore_bridge_unavailable", extra={"event_type": "remediation_degraded", "error": str(exc)})
    return Engine(
        settings, docker,
        PrometheusClient(settings.prometheus_url, settings.prometheus_user, settings.prometheus_password_file),
        LokiClient(settings.loki_url), IntegrityClient(settings.payment_api_url), Witness(settings.witness_base_url),
        blocklist=blocklist, bridge=bridge, store=StateStore(settings.state_file))


def _read_token(path: str | None) -> str | None:
    # Cette méthode permet de relire le jeton du webhook (rotation sans redémarrage) ; None s'il est absent ou vide.
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def create_app(engine=None, settings: Settings | None = None) -> FastAPI:
    # Cette méthode permet de construire l'application ; les tests y injectent un moteur doté de faux clients.

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Cette méthode permet de démarrer le moteur (reprise des incidents, boucle de fond) et de l'arrêter proprement.
        if app.state.engine is None:
            app.state.settings = app.state.settings or Settings.from_env()
            app.state.engine = build_engine(app.state.settings)
        app.state.settings = app.state.settings or app.state.engine.settings
        await app.state.engine.start()
        logger.info("service_started", extra={"event_type": "remediation_started"})
        yield
        await app.state.engine.stop()

    app = FastAPI(title="Resilience-Alpha — Remediation Engine", version="1.0.0", lifespan=lifespan,
                  docs_url=None, redoc_url=None)
    app.state.engine = engine
    app.state.settings = settings
    instrument(app, SERVICE)

    def reject(request: Request, status: int, reason: str, detail: str) -> JSONResponse:
        # Cette méthode permet de refuser un appel du webhook en le journalisant (tentative de fausse alerte : S6).
        metrics.WEBHOOK_REJECTED.labels(reason).inc()
        logger.warning("remediation_webhook_rejected", extra={
            "event_type": "remediation_webhook_rejected", "reason": reason, "client_ip": client_ip(request)})
        headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
        return JSONResponse({"detail": detail}, status_code=status, headers=headers)

    @app.post("/alerts", status_code=202)
    async def alerts(request: Request) -> JSONResponse:
        # Cette méthode permet de recevoir les notifications d'Alertmanager : jeton porteur vérifié à temps constant,
        # alertes enregistrées puis traitées en tâche de fond ; la réponse 202 part sans attendre aucune action.
        expected = _read_token(app.state.settings.webhook_token_file)
        if expected is None:
            return reject(request, 503, "token_unavailable", "Jeton du webhook non configuré")
        scheme, _, provided = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(provided.strip().encode(), expected.encode()):
            return reject(request, 401, "unauthorized", "Jeton absent ou invalide")
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return reject(request, 413, "too_large", "Notification trop volumineuse")
        body = await request.body()
        if len(body) > MAX_BODY:
            return reject(request, 413, "too_large", "Notification trop volumineuse")
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
                raise ValueError("champ alerts manquant")
        except ValueError as exc:
            return reject(request, 400, "invalid_payload", f"Notification Alertmanager invalide : {exc}")
        result = app.state.engine.ingest(payload)
        logger.info("remediation_webhook", extra={
            "event_type": "remediation_webhook", "status": payload.get("status"), "alerts": result["accepted"],
            "group_key": payload.get("groupKey")})
        return JSONResponse(result, status_code=202)

    @app.get("/api/state")
    async def state() -> dict:
        # Cette méthode permet au dashboard de lire l'état global : incidents ouverts, historique récent, IP bloquées,
        # disponibilité du pont de restauration et des dépendances.
        return await app.state.engine.state()

    @app.get("/api/incidents")
    async def incidents(limit: int = Query(50, ge=1, le=500), open: bool = False) -> list[dict]:
        # Cette méthode permet de lister les incidents (les plus récents d'abord), éventuellement les seuls ouverts.
        return app.state.engine.list_incidents(limit, open_only=open)

    @app.get("/api/incidents/{incident_id}")
    async def incident(incident_id: str) -> dict:
        # Cette méthode permet de lire un incident complet avec sa chronologie horodatée.
        found = app.state.engine.get(incident_id)
        if found is None:
            raise HTTPException(404, "Incident introuvable")
        return found

    @app.get("/api/decision-table")
    def decision_table() -> list[dict]:
        # Cette méthode permet d'exposer la table de décision (documentation vivante pour le dashboard et le dossier).
        return table_document()

    @app.get("/health")
    async def health() -> JSONResponse:
        # Cette méthode permet d'indiquer que le service sert (200), avec le détail des dépendances : un pont, un Loki ou
        # un proxy indisponible rend l'état « degraded » sans faire échouer le healthcheck (déploiement --wait).
        engine = app.state.engine
        deps = dict(engine.dependencies)
        deps["webhook_token"] = _read_token(app.state.settings.webhook_token_file) is not None
        deps["state_store"] = engine.store.writable
        degraded = sorted(k for k, v in deps.items() if v is False)
        return JSONResponse({"service": SERVICE, "status": "degraded" if degraded else "ok", "degraded": degraded,
                             "checks": deps})

    return app


app = create_app()
