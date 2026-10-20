"""Client HTTP minimal (bibliothèque standard) vers docker-socket-proxy.

Le moteur ne voit jamais le socket Docker : il ne parle qu'au proxy, joignable sur le seul réseau interne `docker-api`,
qui ne laisse passer que la lecture d'état des conteneurs et les opérations de reprise (restart, start, kill).
Les conteneurs sont retrouvés par leurs labels Compose (projet + service) : jamais par un nom ou un identifiant reçu
dans une alerte.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

from . import ActionError

# États Docker ramenés au vocabulaire du moteur (contrat : healthy | unhealthy | starting | running | exited | none)
_STATUS = {"created": "exited", "exited": "exited", "dead": "exited", "removing": "exited",
           "restarting": "starting", "paused": "unhealthy"}


class DockerProxy:
    """Client HTTP minimal vers docker-socket-proxy (http://docker-socket-proxy:2375)."""

    def __init__(self, base_url: str, project: str, timeout: float = 10.0):
        # Cette méthode permet de mémoriser l'adresse du proxy, le projet Compose ciblé et le délai par requête.
        self.base_url = base_url.rstrip("/")
        self.project = project
        self.timeout = timeout

    def _request(self, method: str, path: str, query: dict | None = None, timeout: float | None = None):
        # Cette méthode permet d'appeler l'API Docker à travers le proxy et de renvoyer (statut, corps JSON ou None) ;
        # un refus du proxy (403) ou une erreur réseau devient une ActionError explicite.
        url = self.base_url + path + (f"?{urllib.parse.urlencode(query)}" if query else "")
        request = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None)
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as err:
            detail = err.read()[:300].decode(errors="replace").strip()
            if err.code == 403:
                raise ActionError(f"docker-socket-proxy refuse {method} {path} (403)") from err
            return err.code, {"message": detail}
        except (urllib.error.URLError, OSError, ValueError) as err:
            raise ActionError(f"docker-socket-proxy injoignable ({method} {path}) : {err}") from err

    def _find(self, service: str) -> dict | None:
        # Cette méthode permet de retrouver le conteneur d'un service Compose du projet (hors conteneurs « run » ponctuels),
        # en privilégiant celui qui tourne si plusieurs existent.
        filters = {"label": [f"com.docker.compose.project={self.project}", f"com.docker.compose.service={service}"]}
        status, containers = self._request("GET", "/containers/json", {"all": "1", "filters": json.dumps(filters)})
        if status != 200 or not isinstance(containers, list):
            raise ActionError(f"liste des conteneurs illisible (HTTP {status})")
        candidates = [c for c in containers if (c.get("Labels") or {}).get("com.docker.compose.oneoff", "False") != "True"]
        if not candidates:
            return None
        candidates.sort(key=lambda c: (c.get("State") != "running", -(c.get("Created") or 0)))
        return candidates[0]

    def container_id(self, service: str) -> str:
        # Cette méthode permet d'obtenir l'identifiant du conteneur d'un service Compose, ou de lever ActionError s'il n'existe pas.
        container = self._find(service)
        if container is None:
            raise ActionError(f"aucun conteneur pour le service {service} (projet {self.project})")
        return container["Id"]

    def _post(self, service: str, operation: str, query: dict | None = None, timeout: float | None = None) -> int:
        # Cette méthode permet d'envoyer une opération de reprise (restart, start, kill) au conteneur d'un service.
        cid = self.container_id(service)
        status, body = self._request("POST", f"/containers/{cid}/{operation}", query, timeout)
        if status not in (204, 304):
            raise ActionError(f"{operation} {service} refusé par Docker (HTTP {status}) : {(body or {}).get('message', '')}")
        return status

    def restart(self, service: str, timeout_s: int = 10) -> None:
        # Cette méthode permet de redémarrer le conteneur d'un service (fonctionne aussi sur un conteneur arrêté).
        self._post(service, "restart", {"t": str(int(timeout_s))}, timeout=timeout_s + self.timeout + 5)

    def start(self, service: str) -> None:
        # Cette méthode permet de démarrer le conteneur arrêté d'un service (304 = déjà démarré, accepté).
        self._post(service, "start", timeout=self.timeout + 5)

    def signal(self, service: str, sig: str) -> None:
        # Cette méthode permet d'envoyer un signal au processus principal du conteneur (ex. HUP pour recharger le WAF).
        if not sig.isalnum():
            raise ActionError(f"signal invalide : {sig!r}")
        self._post(service, "kill", {"signal": sig})

    def inspect(self, service: str) -> dict:
        # Cette méthode permet de lire le `docker inspect` du conteneur d'un service (réseaux, état) ; ActionError sinon.
        cid = self.container_id(service)
        status, info = self._request("GET", f"/containers/{cid}/json")
        if status != 200 or not isinstance(info, dict):
            raise ActionError(f"inspection du conteneur {service} impossible (HTTP {status})")
        return info

    def health(self, service: str) -> str:
        # Cette méthode permet de lire l'état de santé d'un service : healthy / unhealthy / starting (healthcheck Docker),
        # running (pas de healthcheck), exited (arrêté), none (aucun conteneur). Proxy injoignable : ActionError.
        container = self._find(service)
        if container is None:
            return "none"
        status, info = self._request("GET", f"/containers/{container['Id']}/json")
        if status == 404:
            return "none"
        if status != 200 or not isinstance(info, dict):
            raise ActionError(f"état du conteneur {service} illisible (HTTP {status})")
        state = info.get("State") or {}
        raw = state.get("Status", "exited")
        if raw != "running":
            return _STATUS.get(raw, "exited")
        health = (state.get("Health") or {}).get("Status")
        return health if health in ("healthy", "unhealthy", "starting") else "running"

    def ping(self) -> bool:
        # Cette méthode permet de vérifier que le proxy répond et autorise la lecture des conteneurs (pour /health).
        try:
            status, _ = self._request("GET", "/containers/json", {"limit": "1"}, timeout=3)
            return status == 200
        except ActionError:
            return False
