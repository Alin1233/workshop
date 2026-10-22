"""Back-for-front du dashboard de supervision : interface React et API JSON en lecture seule, derrière une
authentification basique.

Le navigateur ne joint que ce service : Prometheus, Alertmanager, Loki et l'API d'état du moteur de remédiation restent
sur le réseau interne `obs`, et leurs identifiants restent ici. Routes (toutes en GET) :
- `/health` (sans identifiant, réduit à l'état du processus : le healthcheck ne dépend d'aucune source) ;
- `/` et `/assets/*` : l'application React construite ;
- `/api/overview`, `/api/alerts`, `/api/incidents`, `/api/incidents/current`, `/api/incidents/{id}`, `/api/blocks`,
  `/api/events` : vues prédéfinies, chacune avec l'état de ses sources (`sources.<nom>.ok`, `error`, `age_s`).
Aucune route n'accepte de requête PromQL ou LogQL, ni ne relaie une écriture (`POST /alerts`, silences…).
"""

import asyncio
import base64
import binascii
import hmac
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from resilience_common.observability import client_ip, setup_logging

from . import shaping
from .config import Settings, read_secret
from .sources import INCIDENT_ID, Fetched, Sources

PUBLIC_PATHS = {"/health"}
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "Cache-Control": "no-store",
}
# Page servie en self uniquement : ni script ni style en ligne, aucune connexion vers une autre origine.
PAGE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
MISSING_BUILD = """<!doctype html><html lang="fr"><meta charset="utf-8"><title>Supervision</title>
<p>Interface non construite : lancer <code>npm run build</code> dans services/supervision-dashboard.</p></html>"""


def check_basic_auth(authorization: str | None, user: str, password: str) -> bool | None:
    # Cette méthode permet de vérifier l'en-tête « Authorization: Basic … » à temps constant ; None quand aucun
    # identifiant n'est fourni (défi du navigateur), False quand il est faux.
    if not authorization or not authorization.lower().startswith("basic "):
        return None
    try:
        given_user, _, given_password = base64.b64decode(authorization[6:].strip(), validate=True).decode(
            "utf-8").partition(":")
    except (binascii.Error, UnicodeDecodeError):
        return False
    user_ok = hmac.compare_digest(given_user.encode(), user.encode())
    password_ok = hmac.compare_digest(given_password.encode(), password.encode())
    return bool(password) and user_ok and password_ok


def _error(code: str, detail: str, status_code: int) -> JSONResponse:
    # Cette méthode permet de renvoyer une erreur sous la forme stable { code, detail } des autres services.
    return JSONResponse({"code": code, "detail": detail}, status_code=status_code)


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None,
               clock=time.time) -> FastAPI:
    # Cette méthode permet de construire l'application ; les tests injectent la configuration, un transport HTTP
    # factice (fausses sources) et une horloge.
    settings = settings or Settings.from_env()
    logger = setup_logging(settings.service, settings.log_level)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    sources = Sources(settings, transport=transport)
    episode = shaping.Episode()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Cette méthode permet de fermer proprement les connexions vers les sources à l'arrêt.
        logger.info("service_started", extra={"event_type": "supervision_started"})
        yield
        await sources.aclose()

    app = FastAPI(title="Resilience-Alpha — Supervision (back-for-front)", version="1.0.0", lifespan=lifespan,
                  description="Vues en lecture seule pour l'écran de supervision : composants, alertes, incidents, "
                              "blocages d'IP et événements. Aucune requête libre, aucune action.",
                  docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.sources = sources

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Cette méthode permet d'exiger l'identifiant (sauf /health), de refuser toute méthode autre que GET/HEAD avant
        # même le routage, et d'ajouter les en-têtes de sécurité (CSP stricte sur la page).
        password = read_secret(settings.auth_password_file)
        authenticated = check_basic_auth(request.headers.get("authorization"), settings.auth_user, password)
        if request.url.path not in PUBLIC_PATHS and not authenticated:
            if not password:
                response = _error("auth_not_configured", "Mot de passe absent : lancer scripts/init_secrets.py", 503)
            else:
                if authenticated is False:
                    logger.warning("supervision_auth_failed", extra={
                        "event_type": "auth_failure", "client_ip": client_ip(request), "path": request.url.path})
                response = _error("unauthorized", "Identifiant requis (admin / secrets/supervision_password)", 401)
                response.headers["WWW-Authenticate"] = 'Basic realm="supervision", charset="UTF-8"'
            response.headers.update(SECURITY_HEADERS)
            return response
        if request.method not in ("GET", "HEAD"):
            response = _error("read_only", "Supervision en lecture seule : GET uniquement", 405)
            response.headers["Allow"] = "GET, HEAD"
        else:
            response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        if not request.url.path.startswith("/api/"):
            response.headers["Content-Security-Policy"] = PAGE_CSP
        if response.status_code >= 500:
            logger.warning("supervision_request_failed", extra={"path": request.url.path,
                                                                "status": response.status_code})
        return response

    def envelope(now: float, *fetched: Fetched, **data) -> dict:
        # Cette méthode permet d'ajouter l'heure du serveur (chronomètres du navigateur) et l'état de chaque source lue.
        mono = sources.cache.clock()
        status: dict[str, dict] = {}
        for item in fetched:
            # Plusieurs lectures d'une même source : la source est en défaut si l'une d'elles l'est
            current = item.status(mono)
            if item.source not in status or not current["ok"]:
                status[item.source] = current
        return {"server_time": shaping.iso(now), "sources": status, **data}

    @app.get("/health", summary="Sonde de vie (sans identifiant, n'interroge aucune source)")
    async def health() -> dict:
        # Cette méthode permet au healthcheck Docker de vérifier que le processus sert ; aucune source n'est interrogée
        # (le service reste sain quand le moteur, Loki ou Prometheus sont arrêtés : l'interface l'affiche).
        return {"service": settings.service, "status": "ok"}

    @app.get("/api/overview", summary="Bandeau d'état global et carte des composants")
    async def overview() -> dict:
        # Cette méthode permet de produire le bandeau d'état global et la carte des composants.
        metrics, prom_alerts, am_alerts, state = await asyncio.gather(
            sources.metrics(), sources.prometheus_alerts(), sources.alertmanager_alerts(), sources.engine_state())
        now = clock()
        reach = {"prometheus": metrics.ok, "alertmanager": am_alerts.ok, "loki": True, "engine": state.ok}
        focus = shaping.focus_incident(state.data if state.ok else None)
        detail = None
        if focus and focus.get("open") and INCIDENT_ID.fullmatch(str(focus.get("id"))):
            found = await sources.engine_incident(focus["id"])
            detail = found.data if found.ok else None
        comps = shaping.components(metrics.data if metrics.ok else None, state.data if state.ok else None, reach, now)
        status = shaping.global_status(state.data if state.ok else None, detail, comps,
                                       prom_alerts.data if prom_alerts.ok else None,
                                       am_alerts.data if am_alerts.ok else None, reach, episode, now,
                                       settings.restored_window_s)
        return envelope(now, metrics, prom_alerts, am_alerts, state, status=status, components=comps,
                        integrity=shaping.integrity(metrics.data if metrics.ok else None, now),
                        anomaly=shaping.anomaly(metrics.data if metrics.ok else None))

    @app.get("/api/alerts", summary="Alertes actives (Prometheus, SOC Loki) et en attente de confirmation")
    async def alerts() -> dict:
        # Cette méthode permet de lister les alertes actives (Alertmanager : Prometheus et SOC Loki) et en attente.
        am_alerts, prom_alerts = await asyncio.gather(sources.alertmanager_alerts(), sources.prometheus_alerts())
        items = shaping.shape_alerts(am_alerts.data if am_alerts.ok else None,
                                     prom_alerts.data if prom_alerts.ok else None)
        return envelope(clock(), am_alerts, prom_alerts, alerts=items)

    @app.get("/api/incidents", summary="Derniers incidents résumés (20 au plus)")
    async def incidents(limit: int = Query(8, ge=1, le=20)) -> dict:
        # Cette méthode permet de lister les derniers incidents résumés (au plus 20, lus en une requête fixe).
        found = await sources.engine_incidents()
        everything = [i for i in (found.data or []) if isinstance(i, dict)]
        items = [shaping.shape_summary(i, everything) for i in everything[:limit]]
        return envelope(clock(), found, incidents=items)

    @app.get("/api/incidents/current", summary="Incident à raconter : ouvert le plus actif, sinon le dernier clos")
    async def current_incident() -> dict:
        # Cette méthode permet de lire l'incident à raconter (ouvert le plus actif, sinon le dernier clos) en entier.
        state = await sources.engine_state()
        focus = shaping.focus_incident(state.data if state.ok else None)
        if not focus or not INCIDENT_ID.fullmatch(str(focus.get("id"))):
            return envelope(clock(), state, incident=None)
        found = await sources.engine_incident(focus["id"])
        incident = shaping.shape_incident(found.data) if found.ok and found.data else None
        return envelope(clock(), state, found, incident=incident)

    @app.get("/api/incidents/{incident_id}", summary="Incident complet avec sa chronologie (identifiant validé)")
    async def incident(incident_id: str):
        # Cette méthode permet de lire un incident de l'historique ; l'identifiant est validé avant tout appel au moteur.
        if not INCIDENT_ID.fullmatch(incident_id):
            return _error("invalid_incident_id", "Identifiant d'incident invalide", 404)
        found = await sources.engine_incident(incident_id)
        if found.ok and found.data is None:
            return _error("incident_not_found", "Incident introuvable", 404)
        incident = shaping.shape_incident(found.data) if found.ok else None
        return envelope(clock(), found, incident=incident)

    @app.get("/api/blocks", summary="IP bloquées au WAF et état du pont de restauration")
    async def blocks() -> dict:
        # Cette méthode permet de lister les IP bloquées au WAF (échéance, durée) et l'état du pont de restauration.
        state = await sources.engine_state()
        now = clock()
        data = state.data if state.ok else None
        bridge = (data or {}).get("bridge")
        deps = (data or {}).get("dependencies") or {}
        return envelope(now, state, blocks=shaping.shape_blocks(data, now),
                        waf_blocklist=deps.get("waf_blocklist"),
                        bridge=shaping.redact(bridge) if isinstance(bridge, dict) else None)

    @app.get("/api/events", summary="Fil d'événements récents (types en liste blanche, 100 au plus)")
    async def events(limit: int = Query(40, ge=1, le=100)) -> dict:
        # Cette méthode permet de lire le fil d'événements récents (types en liste blanche, nombre borné).
        story, attack = await asyncio.gather(sources.story_events(), sources.attack_events())
        items = shaping.shape_events(story.data if story.ok else None, attack.data if attack.ok else None, limit)
        return envelope(clock(), story, attack, events=items)

    static_dir = Path(settings.static_dir)
    if (static_dir / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    async def index_page():
        # Cette méthode permet de servir l'application React construite (ou une page d'explication si elle manque).
        index = static_dir / "index.html"
        if index.is_file():
            return FileResponse(index, media_type="text/html")
        return HTMLResponse(MISSING_BUILD, status_code=503)

    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon():
        # Cette méthode permet de servir l'icône de l'onglet.
        icon = static_dir / "favicon.svg"
        if icon.is_file():
            return FileResponse(icon, media_type="image/svg+xml")
        return _error("not_found", "Icône absente", 404)

    return app


# Application lancée par uvicorn (app.main:app) : configuration lue dans l'environnement.
app = create_app()
