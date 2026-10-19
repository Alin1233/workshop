"""API de l'assistant opérateur : POST /ask (réponse sourcée), GET /health, GET /metrics et une page de consultation."""

import asyncio
import base64
import binascii
import hmac
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from langchain_core.embeddings import Embeddings
from langchain_core.language_models import BaseChatModel
from prometheus_client import Counter, Gauge, Histogram
from pydantic import BaseModel, Field

from resilience_common.observability import client_ip, instrument, setup_logging

from .alerts import alertmanager_reachable, fetch_active_alerts
from .config import Settings
from .corpus import load_corpus
from .rag import Assistant, KnowledgeBase, make_embeddings, make_llm

STATIC_DIR = Path(__file__).parent / "static"

QUESTIONS = Counter("ops_assistant_questions_total", "Questions posées à l'assistant", ["result"])
ANSWER_LATENCY = Histogram(
    "ops_assistant_stage_duration_seconds", "Durée des étapes de la chaîne RAG", ["stage"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60, 90, 120, 180),
)
INDEX_READY = Gauge("ops_assistant_index_ready", "1 si l'index documentaire est construit")
INDEX_CHUNKS = Gauge("ops_assistant_index_chunks", "Nombre de fragments indexés")
OLLAMA_UP = Gauge("ops_assistant_ollama_up", "1 si Ollama répond et dispose des modèles configurés")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}
PAGE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class AskIn(BaseModel):
    question: str = Field(min_length=3, max_length=500, description="Question de l'opérateur, en français")
    include_alerts: bool = Field(True, description="Joindre les alertes actives d'Alertmanager au contexte (lecture seule)")


class SourceOut(BaseModel):
    id: int
    source: str
    section: str
    score: float
    cited: bool
    excerpt: str


class AlertOut(BaseModel):
    name: str
    severity: str
    domain: str
    service: str
    summary: str
    starts_at: str


class AskOut(BaseModel):
    answer: str
    refused: bool
    cited: bool
    sources: list[SourceOut]
    alerts: list[AlertOut]
    alerts_error: str | None = None
    model: str
    timings_ms: dict[str, float]


class IndexState:
    def __init__(self) -> None:
        # Cette méthode permet de suivre l'état de l'index pour /health (en attente, construction, prêt, erreur).
        self.state = "pending"
        self.attempts = 0
        self.last_error: str | None = None
        self.documents: list[str] = []
        self.chunks = 0
        self.built_at: str | None = None

    def snapshot(self) -> dict:
        # Cette méthode permet d'exposer l'état courant de l'index sous forme sérialisable.
        return {"state": self.state, "attempts": self.attempts, "last_error": self.last_error,
                "documents": self.documents, "chunks": self.chunks, "built_at": self.built_at}


def _model_present(wanted: str, available: set[str]) -> bool:
    # Cette méthode permet de comparer un nom de modèle configuré (« mistral ») aux étiquettes d'Ollama (« mistral:latest »).
    return (wanted if ":" in wanted else f"{wanted}:latest") in available


async def probe_ollama(settings: Settings) -> dict:
    # Cette méthode permet de vérifier qu'Ollama répond et que les deux modèles configurés y sont installés.
    status = {"url": settings.ollama_base_url, "reachable": False, "llm_model": settings.llm_model,
              "embed_model": settings.embed_model, "llm_available": False, "embed_available": False}
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"{settings.ollama_base_url}/api/tags")
            response.raise_for_status()
        names = {model.get("name", "") for model in response.json().get("models", [])}
        status.update(reachable=True, llm_available=_model_present(settings.llm_model, names),
                      embed_available=_model_present(settings.embed_model, names))
    except (httpx.HTTPError, ValueError) as exc:
        status["error"] = type(exc).__name__
    return status


# Seule route ouverte sans identifiant : la sonde de vie (healthcheck Docker, `docker compose up --wait`).
PUBLIC_PATHS = {"/health"}


def check_basic_auth(authorization: str | None, settings: Settings) -> bool | None:
    # Cette méthode permet de vérifier l'en-tête « Authorization: Basic … » (comparaison à temps constant) ;
    # elle renvoie None quand aucun identifiant n'est fourni, pour distinguer le défi du navigateur d'un échec.
    if not authorization or not authorization.lower().startswith("basic "):
        return None
    try:
        user, _, password = base64.b64decode(authorization[6:].strip(), validate=True).decode("utf-8").partition(":")
    except (binascii.Error, UnicodeDecodeError):
        return False
    user_ok = hmac.compare_digest(user.encode(), settings.auth_user.encode())
    password_ok = hmac.compare_digest(password.encode(), settings.auth_password.encode())
    return bool(settings.auth_password) and user_ok and password_ok


def _error(code: str, detail: str, status_code: int, **extra) -> JSONResponse:
    # Cette méthode permet de renvoyer les erreurs sous la forme stable { code, detail } utilisée par les autres services.
    return JSONResponse({"code": code, "detail": detail, **extra}, status_code=status_code)


def create_app(
    settings: Settings | None = None,
    embeddings: Embeddings | None = None,
    llm: BaseChatModel | None = None,
    ollama_probe: Callable[[Settings], Awaitable[dict]] = probe_ollama,
) -> FastAPI:
    # Cette méthode permet de construire l'application ; les tests y injectent de faux embeddings / LLM et une fausse sonde.
    settings = settings or Settings.from_env()
    logger = setup_logging(settings.service, settings.log_level)
    # Les sondes /health interrogent Ollama et Alertmanager toutes les 15 s : pas une ligne de journal par requête HTTP.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    embeddings = embeddings or make_embeddings(settings)
    llm = llm or make_llm(settings)

    async def warm_up() -> None:
        # Cette méthode permet de charger le LLM en mémoire dès le démarrage (avec les options réelles : contexte,
        # threads, GPU) ; en CPU seul, le chargement à froid d'un modèle de 3 à 7 milliards de paramètres prend 50 à 90 s.
        start = time.perf_counter()
        try:
            await run_in_threadpool(llm.invoke, [("human", "Réponds seulement : OK")])
            logger.info("llm_warmed", extra={"llm_model": settings.llm_model,
                                             "duration_ms": round((time.perf_counter() - start) * 1000)})
        except Exception as exc:  # noqa: BLE001 - simple optimisation : la première question chargera le modèle
            logger.warning("llm_warmup_failed", extra={"llm_model": settings.llm_model, "error": f"{type(exc).__name__}: {exc}"[:300]})

    async def build_index(app: FastAPI) -> None:
        # Cette méthode permet de construire l'index en tâche de fond, en réessayant tant qu'Ollama est injoignable :
        # le service démarre et répond à /health (dégradé) même si le LLM n'est pas encore disponible.
        index: IndexState = app.state.index
        while True:
            index.attempts += 1
            index.state = "building"
            try:
                chunks, sources = await run_in_threadpool(
                    load_corpus, settings.corpus_root, settings.corpus_include, settings.corpus_exclude,
                    settings.chunk_size, settings.chunk_overlap,
                )
                index.documents, index.chunks = sources, len(chunks)
                start = time.perf_counter()
                kb = await run_in_threadpool(KnowledgeBase.build, chunks, sources, embeddings)
                ANSWER_LATENCY.labels("indexing").observe(time.perf_counter() - start)
                app.state.assistant = Assistant(kb, llm, settings)
                index.state, index.last_error, index.built_at = "ready", None, kb.built_at
                INDEX_READY.set(1)
                INDEX_CHUNKS.set(len(chunks))
                logger.info("index_ready", extra={"documents": len(sources), "chunks": len(chunks),
                                                  "attempt": index.attempts, "embed_model": settings.embed_model})
                if settings.llm_warmup:
                    await warm_up()
                return
            except Exception as exc:  # noqa: BLE001 - Ollama absent, modèle non installé, corpus vide : on réessaie
                index.state, index.last_error = "error", f"{type(exc).__name__}: {exc}"[:300]
                INDEX_READY.set(0)
                logger.warning("index_build_failed", extra={"attempt": index.attempts, "error": index.last_error,
                                                            "retry_in_s": settings.index_retry_seconds})
                await asyncio.sleep(settings.index_retry_seconds)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Cette méthode permet de lancer la construction de l'index au démarrage et de l'interrompre à l'arrêt.
        app.state.semaphore = asyncio.Semaphore(settings.max_concurrent_questions)
        task = asyncio.create_task(build_index(app))
        logger.info("service_started", extra={"llm_model": settings.llm_model, "ollama": settings.ollama_base_url,
                                              "alertmanager": settings.alertmanager_url or None})
        yield
        task.cancel()

    app = FastAPI(
        title="Resilience-Alpha — Assistant opérateur (RAG)", version="1.0.0", lifespan=lifespan,
        description="Consultation des procédures et de l'architecture. L'assistant n'exécute aucune action.",
    )
    app.state.settings = settings
    app.state.index = IndexState()
    app.state.assistant = None

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Cette méthode permet d'exiger l'identifiant de l'interface (sauf sur /health), de refuser les corps de requête
        # trop gros (ou sans taille annoncée) avant toute lecture, et d'ajouter les en-têtes de sécurité, avec une
        # politique CSP stricte pour la page de consultation.
        authenticated = check_basic_auth(request.headers.get("authorization"), settings)
        request.state.authenticated = bool(authenticated)
        if request.url.path not in PUBLIC_PATHS and not authenticated:
            if not settings.auth_password:
                return _error("auth_not_configured", "Mot de passe absent : lancer scripts/init_secrets.py", 503)
            if authenticated is False:
                logger.warning("assistant_auth_failed", extra={"client_ip": client_ip(request), "path": request.url.path,
                                                               "event_type": "auth_failure"})
            response = _error("unauthorized", "Identifiant requis (admin / secrets/ops_assistant_password)", 401)
            response.headers["WWW-Authenticate"] = 'Basic realm="ops-assistant", charset="UTF-8"'
            response.headers.update(SECURITY_HEADERS)
            return response
        if request.method == "POST":
            length = request.headers.get("content-length")
            if length is None:
                return _error("length_required", "En-tête Content-Length obligatoire", 411)
            if not length.isdigit() or int(length) > settings.max_body_bytes:
                return _error("payload_too_large", f"Requête limitée à {settings.max_body_bytes} octets", 413)
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        if request.url.path == "/" or request.url.path.startswith("/static/"):
            response.headers["Content-Security-Policy"] = PAGE_CSP
        return response

    # Le middleware d'observabilité est ajouté en dernier : il enveloppe le garde et journalise donc aussi les 411/413.
    instrument(app, settings.service)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index_page() -> FileResponse:
        # Cette méthode permet de servir la page minimale de consultation de l'assistant.
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    @app.get("/health")
    async def health(request: Request) -> JSONResponse:
        # Cette méthode permet d'indiquer si l'assistant peut réellement répondre (Ollama + modèles + index).
        # Elle répond 200 tant que le processus sert des requêtes : l'état d'Ollama et de l'index est dans le corps
        # (« status »: « degraded », « ready »: false). Composant non critique, l'assistant ne doit jamais faire échouer
        # le déploiement (`docker compose up --wait`) ni passer « unhealthy » parce que le LLM est absent ou distant.
        ollama = await ollama_probe(settings)
        ollama_ok = ollama["reachable"] and ollama["llm_available"] and ollama["embed_available"]
        OLLAMA_UP.set(1 if ollama_ok else 0)
        index = app.state.index.snapshot()
        checks = {"ollama": ollama, "index": index}
        if settings.alertmanager_url:
            checks["alertmanager"] = {"url": settings.alertmanager_url,
                                      "reachable": await alertmanager_reachable(settings.alertmanager_url)}
        ok = ollama_ok and index["state"] == "ready"
        body = {"service": settings.service, "status": "ok" if ok else "degraded", "ready": ok}
        # Sans identifiant, l'état seul : ni adresse d'Ollama, ni liste des documents, ni dernière erreur.
        if request.state.authenticated:
            body["checks"] = checks
        return JSONResponse(body, status_code=200)

    @app.post("/ask", response_model=AskOut, responses={503: {"description": "Index, LLM ou file d'attente indisponible"},
                                                         504: {"description": "Délai de génération dépassé"}})
    async def ask(body: AskIn, request: Request):
        # Cette méthode permet de répondre à une question d'opérateur avec les extraits cités ; elle ne fait que lire
        # (corpus, alertes) et borne le nombre de générations simultanées pour ne pas saturer le CPU du PC Hôte.
        assistant: Assistant | None = request.app.state.assistant
        request_id = getattr(request.state, "request_id", None)
        if assistant is None:
            QUESTIONS.labels("unavailable").inc()
            return _error("index_unavailable", "Index documentaire en cours de construction ou Ollama injoignable",
                          503, index=request.app.state.index.snapshot())
        alerts, alerts_error = [], None
        if body.include_alerts and settings.alertmanager_url:
            try:
                alerts = await fetch_active_alerts(settings.alertmanager_url)
            except (httpx.HTTPError, ValueError):
                alerts_error = "alertmanager_unreachable"
        semaphore: asyncio.Semaphore = request.app.state.semaphore
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=settings.queue_timeout_seconds)
        except TimeoutError:
            QUESTIONS.labels("busy").inc()
            return _error("assistant_busy", "L'assistant traite déjà une question, réessayez dans un instant", 503)
        future = asyncio.get_running_loop().run_in_executor(None, assistant.answer, body.question, alerts)

        def release(done: asyncio.Future) -> None:
            # Cette méthode permet de rendre le jeton à la fin réelle de la génération, même si le client a déjà reçu
            # un 504, et de consommer l'éventuelle erreur d'une génération abandonnée.
            semaphore.release()
            if not done.cancelled():
                done.exception()

        future.add_done_callback(release)
        try:
            result = await asyncio.wait_for(asyncio.shield(future), timeout=settings.answer_timeout_seconds)
        except TimeoutError:
            QUESTIONS.labels("timeout").inc()
            logger.warning("assistant_timeout", extra={"request_id": request_id, "model": assistant.model_name})
            return _error("llm_timeout", "Le modèle n'a pas répondu à temps", 504)
        except Exception as exc:  # noqa: BLE001 - Ollama arrêté, modèle absent, coupure réseau
            QUESTIONS.labels("error").inc()
            logger.warning("llm_unavailable", extra={"request_id": request_id, "error": f"{type(exc).__name__}: {exc}"[:300],
                                                     "event_type": "llm_unavailable"})
            return _error("llm_unavailable", "Le LLM local (Ollama) est injoignable : consulter directement les documents",
                          503, documents=request.app.state.index.documents)
        ANSWER_LATENCY.labels("retrieval").observe(result.retrieval_ms / 1000)
        ANSWER_LATENCY.labels("generation").observe(result.generation_ms / 1000)
        QUESTIONS.labels("refused" if result.refused else "answered").inc()
        logger.info("assistant_answer", extra={
            "request_id": request_id, "event_type": "assistant_question", "question": body.question[:300],
            "model": result.model, "refused": result.refused, "cited": bool(result.cited_ids),
            "sources": result.cited_sources, "alerts": len(alerts), "retrieval_ms": result.retrieval_ms,
            "generation_ms": result.generation_ms,
        })
        return AskOut(
            answer=result.text, refused=result.refused, cited=bool(result.cited_ids),
            sources=[SourceOut(id=hit.id, source=hit.source, section=hit.section, score=hit.score,
                               cited=hit.id in result.cited_ids, excerpt=hit.document.page_content[:400])
                     for hit in result.hits],
            alerts=[AlertOut(**alert) for alert in alerts], alerts_error=alerts_error, model=result.model,
            timings_ms={"retrieval": result.retrieval_ms, "generation": result.generation_ms},
        )

    return app


# Application lancée par uvicorn (app.main:app) : configuration lue dans l'environnement.
app = create_app()
