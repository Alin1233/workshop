"""Clients HTTP minimalistes (bibliothèque standard) pour interroger Prometheus et Loki.

On n'ajoute volontairement aucune dépendance (pas de `requests`) : les API HTTP de Prometheus et
de Loki suffisent via `urllib`. Les erreurs réseau remontent sous forme de `SourceUnavailable`
pour que la boucle d'inférence reste robuste (dernier score conservé plutôt que plantage).
"""

import base64
import json
import math
import time
import urllib.error
import urllib.parse
import urllib.request


class SourceUnavailable(RuntimeError):
    """Signale qu'une source de données (Prometheus/Loki) est momentanément injoignable."""


def basic_auth_header(username: str | None, password: str | None) -> dict[str, str]:
    # Cette méthode permet de construire l'en-tête d'authentification basique (Prometheus exige admin / mot de passe),
    # ou aucun en-tête lorsque la source n'est pas protégée (Loki sur le réseau interne).
    if not password:
        return {}
    token = base64.b64encode(f"{username or 'admin'}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _get_json(url: str, timeout: float, headers: dict[str, str] | None = None) -> dict:
    # Cette méthode permet d'exécuter un GET JSON et de convertir toute erreur réseau en SourceUnavailable
    # (un 401 dû à un mauvais identifiant compris : l'état dégradé est alors visible sur /health).
    request = urllib.request.Request(url, headers={"User-Agent": "anomaly-detector/1.0", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read() or b"{}")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise SourceUnavailable(str(exc)) from exc


def _scalar_from_vector(result: list) -> float:
    # Cette méthode permet d'extraire la valeur d'un résultat « vector » (on agrège côté requête, donc 0 ou 1 série).
    if not result:
        return math.nan
    value = result[0].get("value")
    if not value or len(value) < 2:
        return math.nan
    try:
        return float(value[1])
    except (TypeError, ValueError):
        return math.nan


class PrometheusClient:
    """Interroge l'API HTTP de Prometheus (`/api/v1/query` et `/api/v1/query_range`)."""

    def __init__(self, base_url: str, timeout: float = 5.0, username: str | None = None, password: str | None = None):
        # Cette méthode permet de mémoriser l'URL de base, le délai d'attente et l'identifiant éventuel des requêtes.
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.headers = basic_auth_header(username, password)

    def query(self, expr: str, at: float | None = None) -> float:
        # Cette méthode permet d'exécuter une requête instantanée et de renvoyer un scalaire (NaN si aucune donnée).
        params = {"query": expr}
        if at is not None:
            params["time"] = f"{at:.3f}"
        data = _get_json(f"{self.base_url}/api/v1/query?" + urllib.parse.urlencode(params), self.timeout, self.headers)
        if data.get("status") != "success":
            raise SourceUnavailable(f"Prometheus a répondu : {data.get('error', 'statut inconnu')}")
        return _scalar_from_vector(data.get("data", {}).get("result", []))

    def query_range(self, expr: str, start: float, end: float, step: float) -> dict[float, float]:
        # Cette méthode permet de récupérer une série temporelle agrégée sous forme {timestamp: valeur}.
        params = {"query": expr, "start": f"{start:.3f}", "end": f"{end:.3f}", "step": f"{step:g}s"}
        data = _get_json(f"{self.base_url}/api/v1/query_range?" + urllib.parse.urlencode(params), self.timeout, self.headers)
        if data.get("status") != "success":
            raise SourceUnavailable(f"Prometheus a répondu : {data.get('error', 'statut inconnu')}")
        result = data.get("data", {}).get("result", [])
        if not result:
            return {}
        return {round(float(ts)): float(val) for ts, val in result[0].get("values", [])}


class LokiClient:
    """Interroge l'API HTTP de Loki (requêtes métriques LogQL : `count_over_time`, etc.)."""

    def __init__(self, base_url: str, timeout: float = 5.0, username: str | None = None, password: str | None = None):
        # Cette méthode permet de mémoriser l'URL de base, le délai d'attente et l'identifiant éventuel des requêtes.
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.headers = basic_auth_header(username, password)

    def query(self, expr: str, at: float | None = None) -> float:
        # Cette méthode permet d'exécuter une requête métrique LogQL instantanée et de renvoyer un scalaire.
        params = {"query": expr}
        if at is not None:
            params["time"] = str(int(at * 1e9))  # Loki attend des nanosecondes
        data = _get_json(f"{self.base_url}/loki/api/v1/query?" + urllib.parse.urlencode(params), self.timeout, self.headers)
        if data.get("status") != "success":
            raise SourceUnavailable(f"Loki a répondu : {data.get('status')}")
        return _scalar_from_vector(data.get("data", {}).get("result", []))

    def query_range(self, expr: str, start: float, end: float, step: float) -> dict[float, float]:
        # Cette méthode permet de récupérer une série métrique LogQL sous forme {timestamp: valeur}.
        params = {
            "query": expr,
            "start": str(int(start * 1e9)),
            "end": str(int(end * 1e9)),
            "step": f"{step:g}s",
        }
        data = _get_json(f"{self.base_url}/loki/api/v1/query_range?" + urllib.parse.urlencode(params), self.timeout, self.headers)
        if data.get("status") != "success":
            raise SourceUnavailable(f"Loki a répondu : {data.get('status')}")
        result = data.get("data", {}).get("result", [])
        if not result:
            return {}
        # Loki renvoie une série par combinaison de labels : on additionne (la requête agrège déjà, mais par sécurité).
        # Les horodatages des requêtes métriques sont en SECONDES (comme Prometheus), même si start/end sont en ns.
        merged: dict[float, float] = {}
        for stream in result:
            for ts, val in stream.get("values", []):
                key = round(float(ts))
                merged[key] = merged.get(key, 0.0) + float(val)
        return merged


def now() -> float:
    # Cette méthode permet d'obtenir l'horodatage courant (secondes epoch), isolée pour faciliter les tests.
    return time.time()
