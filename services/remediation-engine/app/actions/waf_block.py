"""Blocage d'IP au WAF : réponse à une tentative de compromission (force brute, injections, rafale de jetons invalides).

À ne pas confondre avec un redémarrage (disponibilité) : ici on coupe l'accès de l'attaquant, le service reste en place.

Mécanisme (détails, preuves et risques : services/remediation-engine/docs/waf-blocking.md) :
- le moteur écrit la liste des IP bloquées dans le volume partagé `waf-blocklist` (fichier `blocked-ips.conf`, monté en
  lecture seule dans le WAF), uniquement des lignes `"<ip>" 1;` incluses dans un bloc `map` nginx
  (infra/waf/00-remediation-blocklist.conf.template) ;
- il recharge nginx à chaud (SIGHUP au PID 1 du conteneur waf, via docker-socket-proxy : `DockerProxy.signal`) ;
  un fichier invalide fait échouer le rechargement et nginx garde l'ancienne configuration ;
- le WAF répond 403 `{"detail":"blocked_by_remediation"}` avant ModSecurity et journalise une ligne JSON
  `event_type=waf_remediation_block` (hors règle SOC WafAttackBlocked, qui ne lit que l'audit ModSecurity) ;
- la vérification interroge le port interne 8081 du WAF (`/remediation/blocklist?ip=`), qui répond selon la
  configuration réellement chargée : c'est la preuve que le rechargement a pris effet.

L'état (motif, incident, expiration) est conservé dans `blocked-ips.json` à côté du fichier rendu : il survit à un
redémarrage du moteur. Toutes les écritures sont atomiques (fichier temporaire puis renommage dans le même répertoire)
et sérialisées (verrou de thread + verrou fcntl sur `.blocked-ips.lock`, au cas où deux processus partageraient le volume).

Les méthodes sont synchrones (fichiers, HTTP) : depuis une tâche asyncio, les appeler via `asyncio.to_thread`.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import logging
import os
import re
import socket
import struct
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from . import ActionError

if TYPE_CHECKING:
    from .docker_proxy import DockerProxy

logger = logging.getLogger("remediation-engine.waf")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Chemin attendu par le WAF (include /waf-blocklist/blocked-ips.con[f]) : ne pas en changer sans adapter infra/waf/.
DEFAULT_PATH = Path("/waf-blocklist/blocked-ips.conf")
DEFAULT_CHECK_URL = "http://waf:8081/remediation/blocklist"
# Court par défaut : au labo, tous les clients arrivent par la même IP NAT (172.16.255.252), la bloquer coupe tout le monde.
DEFAULT_TTL_S = 300
MAX_TTL_S = 86_400
MAX_ENTRIES = 1_000

# Jamais bloquées, même si WAF_BLOCK_ALLOWLIST est défini (healthcheck du WAF : curl localhost).
ALWAYS_ALLOWED: tuple[str, ...] = ("127.0.0.0/8", "::1/128")
# Défauts : boucle locale + dmz (sondes blackbox, frontal, moteur), sous-réseau fixe 172.31.<DMZ_OCTET>.0/24 avec
# DMZ_OCTET entre 248 et 255. Les réseaux du moteur et la passerelle d'edge (clients locaux, tunnels SSH) ont des
# adresses attribuées par Docker : elles sont découvertes à l'exécution. Jamais 172.16.0.0/12 en bloc : l'IP NAT du
# labo (172.16.255.252) en fait partie.
DEFAULT_ALLOWLIST: tuple[str, ...] = ALWAYS_ALLOWED + ("172.31.248.0/21",)
# Un réseau découvert plus large qu'un /16 n'est pas ajouté automatiquement (il pourrait couvrir le réseau du labo).
MIN_DISCOVERED_PREFIX = 16

_ENTRY_LINE = re.compile(r'^"([0-9A-Fa-f:.]+)" 1;$')
_HEADER = (
    "# Généré par remediation-engine (WafBlocklist) : ne pas modifier à la main.\n"
    "# Inclus dans un bloc map nginx du WAF (infra/waf/00-remediation-blocklist.conf.template) : une IP bloquée par ligne.\n"
    "# Motif, incident et expiration : blocked-ips.json, dans le même répertoire.\n"
)


@dataclass
class BlockEntry:
    """IP bloquée au WAF : expiration (epoch, secondes), motif et incident à l'origine du blocage."""

    ip: str
    expires_at: float
    reason: str
    incident_id: str


def normalize_ip(value: object) -> IPAddress:
    # Cette méthode permet de valider une adresse IP unique (pas un réseau) et de la ramener à sa forme canonique,
    # celle que nginx compare ($remote_addr) ; une IPv4 encapsulée dans une IPv6 (::ffff:a.b.c.d) redevient IPv4.
    if not isinstance(value, str) or not value.strip():
        raise ActionError(f"adresse IP absente ou invalide : {str(value)[:64]!r}")
    text = value.strip()
    if "/" in text or "%" in text:
        raise ActionError(f"une adresse IP unique est attendue (ni réseau ni zone) : {text[:64]!r}")
    try:
        addr = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ActionError(f"adresse IP invalide : {text[:64]!r}") from exc
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.is_unspecified or addr.is_multicast or (addr.version == 4 and addr.is_reserved):
        raise ActionError(f"adresse non bloquable (non attribuable à un client) : {addr}")
    return addr


def parse_networks(values: Iterable[str]) -> list[IPNetwork]:
    # Cette méthode permet de convertir une liste de réseaux CIDR (ou d'adresses seules) en objets ipaddress ;
    # une entrée invalide est une erreur de configuration (ActionError), jamais ignorée en silence.
    networks: list[IPNetwork] = []
    for raw in values:
        text = str(raw).strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError as exc:
            raise ActionError(f"réseau invalide dans la liste d'exclusion du WAF : {text[:64]!r}") from exc
    return networks


def allowlist_from_env(environ: Mapping[str, str] | None = None) -> list[str]:
    # Cette méthode permet de construire la liste d'exclusion : défauts sûrs + réseaux de WAF_BLOCK_ALLOWLIST
    # (séparés par des virgules ou des espaces). La variable complète les défauts, elle ne les remplace pas.
    env = os.environ if environ is None else environ
    extra = [item for item in re.split(r"[\s,]+", env.get("WAF_BLOCK_ALLOWLIST", "")) if item]
    parse_networks(extra)
    return list(dict.fromkeys([*DEFAULT_ALLOWLIST, *extra]))


def ttl_from_env(environ: Mapping[str, str] | None = None) -> int:
    # Cette méthode permet de lire la durée de blocage par défaut (WAF_BLOCK_TTL_SECONDS, 300 s sinon), bornée.
    env = os.environ if environ is None else environ
    raw = env.get("WAF_BLOCK_TTL_SECONDS", "") or str(DEFAULT_TTL_S)
    try:
        ttl = int(raw)
    except ValueError as exc:
        raise ActionError(f"WAF_BLOCK_TTL_SECONDS invalide : {raw[:32]!r}") from exc
    if not 1 <= ttl <= MAX_TTL_S:
        raise ActionError(f"WAF_BLOCK_TTL_SECONDS hors bornes (1 à {MAX_TTL_S}) : {ttl}")
    return ttl


def local_subnets(route_file: Path = Path("/proc/net/route")) -> list[IPNetwork]:
    # Cette méthode permet de lister les sous-réseaux IPv4 directement connectés au conteneur du moteur (ses réseaux
    # Docker) : son trafic témoin vers le WAF en vient, il ne doit jamais pouvoir se bloquer lui-même.
    try:
        lines = route_file.read_text().splitlines()[1:]
    except OSError:
        return []
    networks: list[IPNetwork] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 8 or fields[0] == "lo" or fields[1] == "00000000" or fields[2] != "00000000":
            continue
        try:
            dest = socket.inet_ntoa(struct.pack("<L", int(fields[1], 16)))
            mask = socket.inet_ntoa(struct.pack("<L", int(fields[7], 16)))
            network = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
        except (ValueError, struct.error, OSError):
            continue
        if network.prefixlen >= MIN_DISCOVERED_PREFIX:
            networks.append(network)
    return networks


def container_networks(info: Mapping) -> list[IPNetwork]:
    # Cette méthode permet d'extraire d'un `docker inspect` du WAF la passerelle de chacun de ses réseaux (/32, /128) :
    # les clients de l'hôte (127.0.0.1:<port publié>, proxy userland de Docker) et les tunnels SSH arrivent par celle
    # d'edge. Pas le sous-réseau entier : un vrai client distant garde son IP (DNAT) et la dmz est déjà exclue en dur.
    networks: list[IPNetwork] = []
    attached = ((info or {}).get("NetworkSettings") or {}).get("Networks") or {}
    for net in attached.values():
        if not isinstance(net, Mapping):
            continue
        for gateway in (net.get("Gateway"), net.get("IPv6Gateway")):
            if gateway:
                try:
                    networks.append(ipaddress.ip_network(gateway))
                except ValueError:
                    pass
    return networks


def render(entries: Iterable[BlockEntry]) -> str:
    # Cette méthode permet de produire le fichier lu par nginx : en-tête de commentaires puis une ligne `"<ip>" 1;` par IP,
    # triées. Ni motif ni identifiant d'incident (texte libre) n'y figurent : rien ne peut s'y injecter dans la config.
    addresses = sorted({normalize_ip(entry.ip) for entry in entries}, key=lambda a: (a.version, int(a)))
    return _HEADER + "".join(f'"{addr}" 1;\n' for addr in addresses)


def parse_rendered(text: str) -> set[str]:
    # Cette méthode permet de relire les IP d'un fichier rendu (lignes de commentaires ignorées).
    found = set()
    for line in text.splitlines():
        match = _ENTRY_LINE.match(line.strip())
        if match:
            found.add(match.group(1))
    return found


def _http_get_json(url: str, timeout: float = 2.0) -> dict:
    # Cette méthode permet d'interroger le contrôle interne du WAF et de renvoyer sa réponse JSON.
    request = urllib.request.Request(url, headers={"Connection": "close"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(4096) or b"{}")


class WafBlocklist:
    """Liste des IP bloquées au WAF par le moteur : validation, persistance, rendu atomique, rechargement, vérification."""

    def __init__(self, path: Path, docker: "DockerProxy", waf_service: str = "waf",
                 allowlist: Iterable[str] = DEFAULT_ALLOWLIST, *,
                 check_url: str | None = DEFAULT_CHECK_URL, verify_timeout_s: float = 5.0,
                 discover: bool = True, max_entries: int = MAX_ENTRIES,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 fetch: Callable[[str], dict] = _http_get_json, route_file: Path = Path("/proc/net/route")):
        # Cette méthode permet de configurer la liste : fichier rendu (dans le volume partagé), client du proxy Docker,
        # service Compose du WAF, réseaux jamais bloqués (boucle locale toujours incluse) et contrôle interne du WAF.
        # Aucun accès disque ni réseau ici : les fichiers sont créés à la première opération (expire() au démarrage).
        self.path = Path(path)
        self.state_path = self.path.with_suffix(".json")
        self.lock_path = self.path.with_name(f".{self.path.stem}.lock")
        self._docker = docker
        self._waf_service = waf_service
        self._static = parse_networks([*ALWAYS_ALLOWED, *allowlist])
        self._check_url = check_url
        self._verify_timeout_s = verify_timeout_s
        self._max_entries = max_entries
        self._clock = clock
        self._sleep = sleep
        self._fetch = fetch
        self._local = local_subnets(route_file) if discover else []
        self._waf_nets: list[IPNetwork] | None = None if discover else []
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls, docker: "DockerProxy", environ: Mapping[str, str] | None = None, **kwargs) -> "WafBlocklist":
        # Cette méthode permet de construire la liste depuis l'environnement du moteur : WAF_BLOCKLIST_PATH,
        # WAF_BLOCK_ALLOWLIST, WAF_BLOCK_CHECK_URL (vide = vérification sans contrôle interne), WAF_SERVICE.
        env = os.environ if environ is None else environ
        return cls(Path(env.get("WAF_BLOCKLIST_PATH", "") or DEFAULT_PATH), docker,
                   env.get("WAF_SERVICE", "") or "waf", allowlist_from_env(env),
                   check_url=env.get("WAF_BLOCK_CHECK_URL", DEFAULT_CHECK_URL) or None, **kwargs)

    # ───────────────────────────── API publique ─────────────────────────────

    def block(self, ip: str, ttl_s: int, reason: str, incident_id: str) -> BlockEntry:
        # Cette méthode permet de bloquer une IP pendant ttl_s secondes : validation, refus des réseaux exclus
        # (ActionError), écriture atomique de l'état et du fichier rendu, puis rechargement du WAF si la liste a changé.
        # Une IP déjà bloquée voit son expiration prolongée (jamais raccourcie) sans rechargement.
        addr = normalize_ip(ip)
        covering = self.allowlisted(str(addr))
        if covering:
            logger.warning("remediation_waf_block_refused", extra={
                "event_type": "remediation_waf_refused", "client_ip": str(addr), "allowlist": covering,
                "incident_id": str(incident_id)[:100]})
            raise ActionError(f"{addr} appartient à un réseau exclu du blocage ({covering}) : jamais bloquée")
        if self._waf_nets is None:
            # Passerelles du WAF inconnues (proxy Docker momentanément injoignable) : on ne bloque pas à l'aveugle,
            # l'IP pourrait être celle par laquelle arrivent les opérateurs (tunnel SSH). Nouvel essai au prochain appel.
            raise ActionError("réseaux du WAF non découverts (proxy Docker injoignable) : blocage différé")
        if isinstance(ttl_s, bool) or not isinstance(ttl_s, (int, float)) or not 1 <= ttl_s <= MAX_TTL_S:
            raise ActionError(f"durée de blocage invalide : {ttl_s!r} (1 à {MAX_TTL_S} s)")
        with self._locked():
            state = self._load()
            now = self._clock()
            entries = {e.ip: e for e in state["entries"] if e.expires_at > now}
            previous = entries.get(str(addr))
            if previous is None and len(entries) >= self._max_entries:
                raise ActionError(f"liste de blocage pleine ({self._max_entries} IP) : blocage de {addr} refusé")
            expires_at = max(now + float(ttl_s), previous.expires_at if previous else 0.0)
            entry = BlockEntry(str(addr), expires_at, str(reason)[:200], str(incident_id)[:100])
            entries[entry.ip] = entry
            self._commit(list(entries.values()), state["reload_pending"])
        logger.warning("remediation_waf_block", extra={
            "event_type": "remediation_waf_block", "client_ip": entry.ip, "ttl_s": int(ttl_s),
            "expires_at": entry.expires_at, "reason": entry.reason, "incident_id": entry.incident_id,
            "extended": previous is not None})
        return entry

    def unblock(self, ip: str) -> bool:
        # Cette méthode permet de lever le blocage d'une IP ; renvoie False si elle n'était pas bloquée (rien n'est réécrit).
        addr = str(normalize_ip(ip))
        with self._locked():
            state = self._load()
            remaining = [e for e in state["entries"] if e.ip != addr]
            if len(remaining) == len(state["entries"]):
                return False
            self._commit(remaining, state["reload_pending"])
        logger.info("remediation_waf_unblock", extra={"event_type": "remediation_waf_unblock", "client_ip": addr})
        return True

    def expire(self, now: float | None = None) -> list[str]:
        # Cette méthode permet de retirer les blocages échus et de renvoyer leurs IP. Elle ne réécrit et ne recharge que si
        # quelque chose a changé : entrée échue, fichier rendu absent ou désynchronisé (arrêt brutal entre deux écritures),
        # ou rechargement précédent en échec (nouvel essai). À appeler au démarrage puis périodiquement.
        now = self._clock() if now is None else now
        with self._locked():
            state = self._load()
            dropped = [e.ip for e in state["entries"] if e.expires_at <= now]
            remaining = [e for e in state["entries"] if e.expires_at > now]
            current = self._read_rendered()
            in_sync = current is not None and current == render(remaining)
            if dropped or not in_sync or state["reload_pending"] or state["recovered"]:
                self._commit(remaining, state["reload_pending"])
        if dropped:
            logger.info("remediation_waf_expire", extra={"event_type": "remediation_waf_expire", "client_ips": dropped})
        return dropped

    def active(self) -> list[BlockEntry]:
        # Cette méthode permet de lister les blocages en cours (non échus), du plus proche de l'expiration au plus lointain.
        with self._locked():
            state = self._load()
        now = self._clock()
        return sorted((e for e in state["entries"] if e.expires_at > now), key=lambda e: e.expires_at)

    def verify(self, ip: str) -> bool:
        # Cette méthode permet de vérifier que le blocage est effectif : l'IP est dans le fichier rendu, le WAF est en
        # bonne santé après le rechargement et, surtout, son contrôle interne (configuration réellement chargée par les
        # workers nginx) la déclare bloquée. Le rechargement étant asynchrone, on réessaie jusqu'à verify_timeout_s.
        try:
            addr = str(normalize_ip(ip))
        except ActionError:
            return False
        rendered = self._read_rendered()
        if rendered is None or addr not in parse_rendered(rendered):
            logger.warning("remediation_waf_verify_failed", extra={
                "event_type": "remediation_waf_verify", "client_ip": addr, "check": "file"})
            return False
        deadline = time.monotonic() + max(self._verify_timeout_s, 0.0)
        last = "health"
        while True:
            health = self._health()
            if health in ("healthy", "running"):
                last = "loaded_config"
                if self._check_url is None or self._loaded(addr):
                    return True
            if time.monotonic() >= deadline:
                break
            self._sleep(0.25)
        logger.warning("remediation_waf_verify_failed", extra={
            "event_type": "remediation_waf_verify", "client_ip": addr, "check": last, "waf_health": health})
        return False

    def allowlisted(self, ip: str) -> str | None:
        # Cette méthode permet de savoir si une IP est protégée du blocage ; renvoie le réseau qui la couvre (ou None).
        addr = normalize_ip(ip)
        for network in self.allowlist_networks():
            if addr.version == network.version and addr in network:
                return str(network)
        return None

    def allowlist_networks(self) -> list[IPNetwork]:
        # Cette méthode permet d'obtenir la liste d'exclusion effective : configuration, réseaux du moteur et passerelles
        # des réseaux du WAF (edge comprise), ces dernières lues via le proxy Docker et redemandées tant qu'elles manquent.
        if self._waf_nets is None:
            self._waf_nets = self._discover_waf_networks()
        return list(dict.fromkeys([*self._static, *self._local, *(self._waf_nets or [])]))

    def ready(self) -> bool:
        # Cette méthode permet de savoir si le volume partagé est accessible en écriture (sinon : blocage impossible).
        return self.path.parent.is_dir() and os.access(self.path.parent, os.W_OK | os.X_OK)

    # ───────────────────────────── Interne ─────────────────────────────

    @contextmanager
    def _locked(self) -> Iterator[None]:
        # Cette méthode permet de sérialiser les opérations : verrou de thread (tâches du moteur) puis verrou fcntl sur un
        # fichier du volume (autre processus). Un volume inaccessible devient une ActionError explicite.
        with self._lock:
            try:
                fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            except OSError as exc:
                raise ActionError(f"volume de la liste de blocage inaccessible ({self.path.parent}) : {exc}") from exc
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)

    def _load(self) -> dict:
        # Cette méthode permet de relire l'état persistant. Fichier absent : liste vide, ou reconstruite depuis le fichier
        # rendu s'il en existe un ; fichier illisible : mis de côté (.corrupt-<ts>) puis même reconstruction, avec la
        # durée par défaut, pour ne pas lever en silence un blocage en cours.
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            entries = [BlockEntry(str(normalize_ip(e["ip"])), float(e["expires_at"]), str(e.get("reason", "")),
                                  str(e.get("incident_id", ""))) for e in data.get("entries", [])]
            return {"entries": entries, "reload_pending": bool(data.get("reload_pending")), "recovered": False}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, KeyError, ActionError) as exc:
            aside = self.state_path.with_name(f"{self.state_path.name}.corrupt-{int(self._clock())}")
            try:
                self.state_path.rename(aside)
            except OSError:
                pass
            logger.error("remediation_waf_state_unreadable", extra={
                "event_type": "remediation_state_error", "error": str(exc), "moved_to": str(aside)})
        rendered = self._read_rendered() or ""
        expires_at = self._clock() + DEFAULT_TTL_S
        entries = [BlockEntry(ip, expires_at, "reconstruit depuis le fichier rendu", "") for ip in parse_rendered(rendered)]
        return {"entries": entries, "reload_pending": False, "recovered": bool(entries)}

    def _read_rendered(self) -> str | None:
        # Cette méthode permet de lire le fichier rendu tel que le WAF le voit (None s'il n'existe pas encore).
        try:
            return self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ActionError(f"fichier de blocage illisible ({self.path}) : {exc}") from exc

    def _commit(self, entries: list[BlockEntry], reload_pending: bool) -> None:
        # Cette méthode permet d'appliquer un nouvel état : état JSON (rechargement marqué « en attente »), fichier rendu
        # s'il diffère, SIGHUP au WAF si l'ensemble des IP a changé ou si un rechargement précédent a échoué, puis état
        # JSON final. Un arrêt brutal entre deux étapes est rattrapé par expire() (désynchronisation ou attente).
        content = render(entries)
        current = self._read_rendered()
        must_reload = reload_pending or parse_rendered(current or "") != parse_rendered(content)
        self._write_state(entries, must_reload)
        if current != content:
            self._atomic_write(self.path, content, 0o644)
        if not must_reload:
            return
        try:
            self._docker.signal(self._waf_service, "HUP")
        except ActionError as exc:
            logger.error("remediation_waf_reload_failed", extra={
                "event_type": "remediation_waf_reload", "result": "failed", "error": str(exc)})
            raise ActionError(f"rechargement du WAF impossible (nouvel essai au prochain expire()) : {exc}") from exc
        except Exception as exc:  # noqa: BLE001 — tout échec du client Docker devient une ActionError
            logger.error("remediation_waf_reload_failed", extra={
                "event_type": "remediation_waf_reload", "result": "failed", "error": repr(exc)})
            raise ActionError(f"rechargement du WAF impossible : {exc!r}") from exc
        self._write_state(entries, False)
        logger.info("remediation_waf_reload", extra={
            "event_type": "remediation_waf_reload", "result": "ok", "blocked_ips": len(entries)})

    def _write_state(self, entries: list[BlockEntry], reload_pending: bool) -> None:
        # Cette méthode permet d'écrire l'état persistant (lisible du seul moteur) de façon atomique.
        payload = {"version": 1, "updated_at": self._clock(), "reload_pending": reload_pending,
                   "entries": [asdict(e) for e in sorted(entries, key=lambda e: e.expires_at)]}
        self._atomic_write(self.state_path, json.dumps(payload, ensure_ascii=False, indent=1) + "\n", 0o600)

    def _atomic_write(self, target: Path, content: str, mode: int) -> None:
        # Cette méthode permet d'écrire un fichier sans jamais exposer de contenu partiel : fichier temporaire dans le même
        # répertoire (nom hors du motif lu par le WAF), fsync, droits définitifs, renommage atomique puis fsync du répertoire.
        try:
            fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        except OSError as exc:
            raise ActionError(f"écriture impossible dans {target.parent} : {exc}") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, mode)
            os.replace(tmp, target)
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise ActionError(f"écriture de {target} impossible : {exc}") from exc
        try:
            dir_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass

    def _health(self) -> str:
        # Cette méthode permet de lire l'état du conteneur WAF (proxy injoignable : « unknown »).
        try:
            return self._docker.health(self._waf_service)
        except Exception as exc:  # noqa: BLE001 — l'état est seulement observé, jamais bloquant
            logger.warning("remediation_waf_health_unknown", extra={
                "event_type": "remediation_waf_verify", "error": str(exc)})
            return "unknown"

    def _loaded(self, addr: str) -> bool:
        # Cette méthode permet de demander au WAF (port interne 8081) si l'IP figure dans sa configuration chargée.
        url = f"{self._check_url}?{urllib.parse.urlencode({'ip': addr})}"
        try:
            return int(self._fetch(url).get("blocked", 0)) == 1
        except (OSError, ValueError, TypeError, AttributeError, urllib.error.URLError):
            return False

    def _discover_waf_networks(self) -> list[IPNetwork] | None:
        # Cette méthode permet de lire les réseaux du conteneur WAF via le proxy Docker (lecture seule) ;
        # renvoie None en cas d'échec pour réessayer à la prochaine opération, [] si le client ne sait pas inspecter.
        inspect = getattr(self._docker, "inspect", None)
        if not callable(inspect):
            if not (hasattr(self._docker, "container_id") and isinstance(getattr(self._docker, "base_url", None), str)):
                logger.warning("remediation_waf_discovery_unavailable", extra={
                    "event_type": "remediation_waf_discovery",
                    "detail": "client Docker sans inspect : passerelle edge à fournir via WAF_BLOCK_ALLOWLIST"})
                return []
            inspect = self._inspect_via_proxy
        try:
            networks = container_networks(inspect(self._waf_service))
        except Exception as exc:  # noqa: BLE001 — découverte opportuniste, nouvel essai plus tard
            logger.warning("remediation_waf_discovery_failed", extra={
                "event_type": "remediation_waf_discovery", "error": str(exc)})
            return None
        logger.info("remediation_waf_discovery", extra={
            "event_type": "remediation_waf_discovery", "networks": [str(n) for n in networks]})
        return networks

    def _inspect_via_proxy(self, service: str) -> dict:
        # Cette méthode permet d'inspecter le conteneur d'un service avec la seule API publique de DockerProxy
        # (container_id, base_url) quand il n'expose pas de méthode inspect : GET /containers/{id}/json, autorisé
        # par CONTAINERS=1 sur docker-socket-proxy.
        cid = self._docker.container_id(service)
        url = f"{self._docker.base_url.rstrip('/')}/containers/{urllib.parse.quote(cid, safe='')}/json"
        with urllib.request.urlopen(url, timeout=float(getattr(self._docker, "timeout", 10.0))) as response:
            return json.loads(response.read())
