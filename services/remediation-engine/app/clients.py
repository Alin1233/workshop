"""Clients HTTP (bibliothèque standard) : Prometheus (authentification basique), Loki (réseau obs, sans identifiant)
et contrôle d'intégrité interne de payment-api. Ils sont synchrones : le moteur les appelle dans un thread."""

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request


class SourceError(RuntimeError):
    """Source de données injoignable ou réponse inexploitable."""


def _get_json(url: str, timeout: float, headers: dict | None = None) -> dict:
    # Cette méthode permet de lire une réponse JSON, en convertissant toute erreur réseau ou HTTP en SourceError.
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as err:
        raise SourceError(f"HTTP {err.code} sur {url.split('?')[0]}") from err
    except (urllib.error.URLError, OSError, ValueError) as err:
        raise SourceError(f"{url.split('?')[0]} injoignable : {err}") from err


class PrometheusClient:
    """Requêtes instantanées PromQL, authentifiées (admin / fichier de mot de passe relu à chaque appel)."""

    def __init__(self, base_url: str, user: str = "admin", password_file: str | None = None, timeout: float = 5.0):
        # Cette méthode permet de mémoriser l'adresse de Prometheus et le fichier secret du mot de passe.
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password_file = password_file
        self.timeout = timeout

    def _headers(self) -> dict:
        # Cette méthode permet de construire l'en-tête d'authentification basique (secret relu : rotation sans redémarrage).
        if not self.password_file:
            return {}
        try:
            with open(self.password_file, encoding="utf-8") as handle:
                password = handle.read().strip()
        except OSError as err:
            raise SourceError(f"mot de passe Prometheus illisible : {err}") from err
        token = base64.b64encode(f"{self.user}:{password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def query(self, expr: str) -> list[dict]:
        # Cette méthode permet d'exécuter une requête PromQL instantanée et de renvoyer le vecteur résultat.
        url = f"{self.base_url}/api/v1/query?{urllib.parse.urlencode({'query': expr})}"
        data = _get_json(url, self.timeout, self._headers())
        if data.get("status") != "success":
            raise SourceError(f"requête PromQL refusée : {data.get('error')}")
        return data["data"]["result"]

    def scalar(self, expr: str) -> float | None:
        # Cette méthode permet de lire une seule valeur (None si le vecteur est vide).
        result = self.query(expr)
        return float(result[0]["value"][1]) if result else None

    def probes(self) -> dict[str, float]:
        # Cette méthode permet de lire l'état des sondes de bout en bout (label service → probe_success).
        return {r["metric"].get("service", r["metric"].get("instance", "?")): float(r["value"][1])
                for r in self.query('probe_success{job="blackbox-http"}')}

    def ready(self) -> bool:
        # Cette méthode permet de vérifier que Prometheus répond et accepte l'identifiant (pour /health).
        try:
            self.query("vector(1)")
            return True
        except SourceError:
            return False


class LokiClient:
    """Requêtes LogQL sur Loki, joint directement sur le réseau interne obs (sans authentification)."""

    def __init__(self, base_url: str, timeout: float = 5.0):
        # Cette méthode permet de mémoriser l'adresse de Loki.
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def metric(self, expr: str) -> list[dict]:
        # Cette méthode permet d'exécuter une requête métrique LogQL instantanée (vecteur résultat).
        url = f"{self.base_url}/loki/api/v1/query?{urllib.parse.urlencode({'query': expr})}"
        data = _get_json(url, self.timeout)
        if data.get("status") != "success":
            raise SourceError(f"requête LogQL refusée : {data.get('error')}")
        return data["data"]["result"]

    def latest(self, expr: str, since_s: float = 900) -> dict | None:
        # Cette méthode permet de lire la ligne de journal la plus récente correspondant au sélecteur (JSON décodé).
        end = time.time()
        params = {"query": expr, "start": str(int((end - since_s) * 1e9)), "end": str(int(end * 1e9)),
                  "limit": "1", "direction": "backward"}
        data = _get_json(f"{self.base_url}/loki/api/v1/query_range?{urllib.parse.urlencode(params)}", self.timeout)
        lines = [(int(ts), line) for stream in data.get("data", {}).get("result", []) for ts, line in stream["values"]]
        if not lines:
            return None
        ts, line = max(lines)
        try:
            entry = json.loads(line)
        except ValueError:
            entry = {"raw": line}
        entry["_ts"] = ts / 1e9
        return entry

    def top_ip(self, expr: str) -> tuple[str, float] | None:
        # Cette méthode permet de trouver l'IP cliente la plus fautive d'une requête `sum by (client_ip)` (None si aucune).
        counts = [(r["metric"].get("client_ip", ""), float(r["value"][1])) for r in self.metric(expr)]
        counts = [(ip, n) for ip, n in counts if ip and ip != "unknown"]
        return max(counts, key=lambda item: item[1]) if counts else None

    def ready(self) -> bool:
        # Cette méthode permet de vérifier que Loki répond (pour /health).
        try:
            request = urllib.request.Request(f"{self.base_url}/ready")
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status == 200
        except (urllib.error.URLError, OSError):
            return False


class IntegrityClient:
    """Contrôle d'intégrité interne du registre (payment-api, réseau app) : 200 cohérent, 409 incohérent, 503 base KO."""

    def __init__(self, base_url: str, timeout: float = 10.0):
        # Cette méthode permet de mémoriser l'adresse interne de payment-api.
        self.url = base_url.rstrip("/") + "/internal/integrity"
        self.timeout = timeout

    def check(self) -> tuple[int | None, dict]:
        # Cette méthode permet de renvoyer (code HTTP, rapport) ; code None si l'API est injoignable.
        try:
            with urllib.request.urlopen(self.url, timeout=self.timeout) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as err:
            try:
                body = json.loads(err.read() or b"{}")
            except ValueError:
                body = {}
            return err.code, body if isinstance(body, dict) else {"body": body}
        except (urllib.error.URLError, OSError, ValueError) as err:
            return None, {"error": str(err)}
