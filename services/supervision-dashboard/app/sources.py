"""Lecture seule des sources de la supervision : Prometheus, Alertmanager, Loki et API d'état du moteur de remédiation.

Garde-fous :
- **requêtes prédéfinies** : les expressions PromQL et LogQL sont des constantes de ce module ; aucun paramètre reçu du
  navigateur n'est transmis à une source (seul un identifiant d'incident validé par expression régulière l'est) ;
- **GET uniquement**, vers une liste fermée de chemins par source (`Upstream.routes`) : ni `POST /alerts` du moteur, ni
  silence Alertmanager, ni route d'écriture, même si le code appelant se trompait ;
- **délais courts** et **cache** de 1,5 s par requête, partagé par tous les navigateurs, avec une seule requête en vol
  par clé : dix écrans ouverts n'envoient pas plus de requêtes qu'un seul ;
- **erreurs par source** : une source en panne donne `ok: false` et un message court, jamais une exception qui
  ferait tomber l'API entière.
"""

import asyncio
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Settings, read_secret

logger = logging.getLogger("supervision-dashboard.sources")

# ─────────────────────────────── requêtes prédéfinies ───────────────────────────────
# Une seule requête instantanée pour la carte des composants : santé des cibles, sondes de bout en bout (succès et code
# HTTP, qui distingue un WAF muet d'un frontal en 502), intégrité du registre, scores du détecteur ML et son seuil.
METRICS_QUERY = (
    '{__name__=~"up|probe_success|probe_http_status_code|payment_ledger_integrity_ok'
    '|payment_ledger_integrity_last_check_timestamp|anomaly_score|anomaly_threshold|anomaly_detector_source_up"}'
)
# Fil d'événements : journaux du récit de l'incident (moteur, détecteur, intégrité, dépendances), sans le bruit des
# notifications reçues ou répétées ; à part, les événements d'attaque, nombreux, qui sont regroupés avant affichage.
STORY_EVENTS_QUERY = (
    '{event_type=~"remediation_.+|anomaly_detected|anomaly_cleared|integrity_violation|dependency_failure",'
    ' event_type!~"remediation_(webhook|duplicate)"}'
)
ATTACK_EVENTS_QUERY = '{event_type=~"auth_failure|waf_remediation_block"}'
STORY_EVENTS_LIMIT = 80
ATTACK_EVENTS_LIMIT = 300
ENGINE_INCIDENTS_LIMIT = 20
INCIDENT_ID = re.compile(r"inc-[0-9]{8}-[0-9]{6}-[0-9a-f]{6}")


class SourceError(Exception):
    """Source injoignable ou réponse inattendue : message court, affiché tel quel dans le panneau concerné."""


class Upstream:
    """Client HTTP d'une source : GET seulement, vers une liste fermée de chemins, identifiant relu à chaque appel."""

    def __init__(self, name: str, base_url: str, routes: tuple[str, ...],
                 client: Callable[[], httpx.AsyncClient], credentials: Callable[[], tuple[str, str]] | None = None):
        # Cette méthode permet de déclarer une source, ses seuls chemins autorisés et son identifiant éventuel.
        self.name = name
        self.base_url = base_url
        self.routes = tuple(re.compile(route) for route in routes)
        self._client = client
        self._credentials = credentials

    async def get(self, path: str, params: dict | None = None, missing_ok: bool = False) -> Any:
        # Cette méthode permet de lire un document JSON sur un chemin autorisé ; toute erreur devient une SourceError.
        if not any(route.fullmatch(path) for route in self.routes):
            raise ValueError(f"chemin non autorisé vers {self.name} : {path}")
        auth = None
        if self._credentials is not None:
            user, password = self._credentials()
            if not password:
                raise SourceError("identifiant non configuré")
            auth = httpx.BasicAuth(user, password)
        try:
            response = await self._client().get(f"{self.base_url}{path}", params=params, auth=auth)
        except httpx.TimeoutException as exc:
            raise SourceError("délai dépassé") from exc
        except httpx.ConnectError as exc:
            raise SourceError("injoignable") from exc
        except httpx.HTTPError as exc:
            raise SourceError(f"erreur réseau ({type(exc).__name__})") from exc
        if response.status_code == 404 and missing_ok:
            return None
        if response.status_code in (401, 403):
            raise SourceError(f"identifiant refusé (HTTP {response.status_code})")
        if response.status_code >= 400:
            raise SourceError(f"HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise SourceError("réponse illisible") from exc


@dataclass
class Fetched:
    """Résultat d'une lecture : données ou erreur, horodatage (monotone) et durée de l'appel."""

    source: str
    ok: bool
    data: Any = None
    error: str | None = None
    at: float = 0.0
    latency_ms: int = 0

    def status(self, now: float) -> dict:
        # Cette méthode permet de décrire l'état de la source pour l'interface (pastille « source indisponible »).
        return {"ok": self.ok, "error": self.error, "age_s": round(max(0.0, now - self.at), 1),
                "latency_ms": self.latency_ms}


class Cache:
    """Cache à durée de vie courte, une seule requête en vol par clé (les appels concurrents attendent son résultat)."""

    MAX_ENTRIES = 256

    def __init__(self, ttl_s: float, clock: Callable[[], float] = time.monotonic):
        # Cette méthode permet de fixer la durée de vie des entrées (les erreurs sont mises en cache comme les succès).
        self.ttl_s = ttl_s
        self.clock = clock
        self._entries: dict[str, Fetched] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._health: dict[str, bool] = {}

    def _fresh(self, key: str) -> Fetched | None:
        # Cette méthode permet de renvoyer l'entrée si elle est encore valable.
        entry = self._entries.get(key)
        return entry if entry is not None and self.clock() - entry.at < self.ttl_s else None

    async def get(self, key: str, source: str, loader: Callable[[], Awaitable[Any]]) -> Fetched:
        # Cette méthode permet de lire une clé : entrée fraîche, sinon un seul appel à la source pour tous les demandeurs.
        entry = self._fresh(key)
        if entry is not None:
            return entry
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            entry = self._fresh(key)
            if entry is not None:
                return entry
            started = self.clock()
            try:
                data = await loader()
                entry = Fetched(source, True, data, None, self.clock(), round((self.clock() - started) * 1000))
            except SourceError as exc:
                entry = Fetched(source, False, None, str(exc), self.clock(), round((self.clock() - started) * 1000))
            self._entries[key] = entry
            self._track(entry)
            self._prune()
            return entry

    def _track(self, entry: Fetched) -> None:
        # Cette méthode permet de journaliser une seule fois chaque perte et chaque retour d'une source.
        previous = self._health.get(entry.source)
        self._health[entry.source] = entry.ok
        if previous is None or previous == entry.ok:
            if previous is None and not entry.ok:
                logger.warning("supervision_source_down", extra={
                    "event_type": "supervision_source_down", "source": entry.source, "error": entry.error})
            return
        if entry.ok:
            logger.info("supervision_source_up", extra={"event_type": "supervision_source_up", "source": entry.source})
        else:
            logger.warning("supervision_source_down", extra={
                "event_type": "supervision_source_down", "source": entry.source, "error": entry.error})

    def _prune(self) -> None:
        # Cette méthode permet de borner la mémoire (identifiants d'incidents consultés) : les plus anciennes entrées partent.
        if len(self._entries) <= self.MAX_ENTRIES:
            return
        for key, _ in sorted(self._entries.items(), key=lambda item: item[1].at)[:len(self._entries) - self.MAX_ENTRIES]:
            self._entries.pop(key, None)
            self._locks.pop(key, None)


class Sources:
    """Les quatre sources de la supervision et leurs lectures prédéfinies (aucune n'accepte de requête du client)."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None,
                 clock: Callable[[], float] = time.time):
        # Cette méthode permet d'assembler les clients ; les tests injectent un transport factice (aucun réseau).
        self.settings = settings
        self.clock = clock
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self.cache = Cache(settings.cache_ttl_s)
        s = settings
        self.prometheus = Upstream("prometheus", s.prometheus_url, (r"/api/v1/query", r"/api/v1/alerts"), self.client,
                                   lambda: (s.prometheus_user, read_secret(s.prometheus_password_file)))
        self.alertmanager = Upstream("alertmanager", s.alertmanager_url, (r"/api/v2/alerts",), self.client,
                                     lambda: (s.alertmanager_user, read_secret(s.alertmanager_password_file)))
        self.loki = Upstream("loki", s.loki_url, (r"/loki/api/v1/query_range",), self.client)
        self.engine = Upstream("engine", s.engine_url,
                               (r"/api/state", r"/api/incidents", rf"/api/incidents/{INCIDENT_ID.pattern}"), self.client)

    def client(self) -> httpx.AsyncClient:
        # Cette méthode permet de partager un client HTTP (connexions réutilisées) avec des délais courts.
        if self._client is None:
            self._client = httpx.AsyncClient(
                transport=self._transport, follow_redirects=False, headers={"user-agent": self.settings.service},
                timeout=httpx.Timeout(self.settings.timeout_s, connect=self.settings.connect_timeout_s))
        return self._client

    async def aclose(self) -> None:
        # Cette méthode permet de fermer les connexions à l'arrêt du service.
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ─────────────────────────────── lectures prédéfinies ───────────────────────────────

    async def metrics(self) -> Fetched:
        # Cette méthode permet de lire les métriques de la carte des composants (une requête instantanée constante).
        async def load():
            body = await self.prometheus.get("/api/v1/query", {"query": METRICS_QUERY})
            if not isinstance(body, dict) or body.get("status") != "success":
                raise SourceError("réponse Prometheus inattendue")
            return body["data"].get("result") or []
        return await self.cache.get("prometheus:metrics", "prometheus", load)

    async def prometheus_alerts(self) -> Fetched:
        # Cette méthode permet de lire les règles d'alerte en attente (pending) ou actives côté Prometheus.
        async def load():
            body = await self.prometheus.get("/api/v1/alerts")
            if not isinstance(body, dict) or body.get("status") != "success":
                raise SourceError("réponse Prometheus inattendue")
            return (body.get("data") or {}).get("alerts") or []
        return await self.cache.get("prometheus:alerts", "prometheus", load)

    async def alertmanager_alerts(self) -> Fetched:
        # Cette méthode permet de lire les alertes actives d'Alertmanager (Prometheus et règles SOC de Loki), en GET.
        async def load():
            body = await self.alertmanager.get("/api/v2/alerts", {"active": "true", "silenced": "true",
                                                                  "inhibited": "true"})
            if not isinstance(body, list):
                raise SourceError("réponse Alertmanager inattendue")
            return body
        return await self.cache.get("alertmanager:alerts", "alertmanager", load)

    async def engine_state(self) -> Fetched:
        # Cette méthode permet de lire l'état du moteur : incidents ouverts et récents, IP bloquées, pont, dépendances.
        async def load():
            body = await self.engine.get("/api/state")
            if not isinstance(body, dict):
                raise SourceError("réponse du moteur inattendue")
            return body
        return await self.cache.get("engine:state", "engine", load)

    async def engine_incidents(self) -> Fetched:
        # Cette méthode permet de lire les derniers incidents résumés (nombre fixe ; le client choisit seulement combien
        # en afficher parmi eux).
        async def load():
            body = await self.engine.get("/api/incidents", {"limit": str(ENGINE_INCIDENTS_LIMIT)})
            if not isinstance(body, list):
                raise SourceError("réponse du moteur inattendue")
            return body
        return await self.cache.get("engine:incidents", "engine", load)

    async def engine_incident(self, incident_id: str) -> Fetched:
        # Cette méthode permet de lire un incident complet avec sa chronologie ; l'identifiant est validé avant tout appel.
        if not INCIDENT_ID.fullmatch(incident_id):
            raise ValueError("identifiant d'incident invalide")

        async def load():
            body = await self.engine.get(f"/api/incidents/{incident_id}", missing_ok=True)
            if body is not None and not isinstance(body, dict):
                raise SourceError("réponse du moteur inattendue")
            return body
        return await self.cache.get(f"engine:incident:{incident_id}", "engine", load)

    async def _events(self, key: str, query: str, limit: int) -> Fetched:
        # Cette méthode permet de lire une requête LogQL constante sur la fenêtre récente, du plus récent au plus ancien.
        async def load():
            end = time.time_ns()
            start = end - self.settings.events_window_s * 1_000_000_000
            body = await self.loki.get("/loki/api/v1/query_range", {
                "query": query, "start": str(start), "end": str(end), "limit": str(limit), "direction": "backward"})
            if not isinstance(body, dict) or body.get("status") != "success":
                raise SourceError("réponse Loki inattendue")
            return (body.get("data") or {}).get("result") or []
        return await self.cache.get(key, "loki", load)

    async def story_events(self) -> Fetched:
        # Cette méthode permet de lire les événements du récit (moteur, détecteur, intégrité, dépendances).
        return await self._events("loki:story", STORY_EVENTS_QUERY, STORY_EVENTS_LIMIT)

    async def attack_events(self) -> Fetched:
        # Cette méthode permet de lire les événements d'attaque (échecs d'authentification, requêtes bloquées au WAF).
        return await self._events("loki:attack", ATTACK_EVENTS_QUERY, ATTACK_EVENTS_LIMIT)
