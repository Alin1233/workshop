"""Définition et calcul des variables (features) du détecteur d'anomalies.

Ce module est le **contrat unique** entre l'entraînement (`ml/`) et l'inférence (service) : les mêmes
requêtes PromQL/LogQL et les mêmes règles de nettoyage servent à constituer le jeu de données et à
scorer en direct. Toute modification ici se répercute donc des deux côtés sans duplication.

Chaque variable est décrite par :
- `source` : "prom" (Prometheus) ou "loki" (journaux) ;
- `query`  : la requête qui renvoie **une** valeur agrégée (on somme/max côté requête) ;
- `nan_fill` : que faire en l'absence de donnée — "zero" (pas d'activité ⇒ 0) ou "median"
  (valeur neutre : on réutilisera la médiane apprise, pour que l'absence de trafic ne crée pas d'anomalie).

Toutes les variables sont orientées « une hausse est suspecte » : seuls les écarts positifs à la
normale comptent (un trafic faible ou nul — période creuse — n'est jamais une anomalie).
"""

from dataclasses import dataclass
from math import isnan


@dataclass(frozen=True)
class Feature:
    name: str
    source: str  # "prom" | "loki"
    query: str
    nan_fill: str = "zero"  # "zero" | "median"


# Correspondance service Compose -> label `service` des sondes blackbox (cf. infra/prometheus/prometheus.yml).
_PROBE_LABEL = {"auth-service": "auth", "payment-api": "payments", "frontend": "frontend"}


def _probe_fail(service: str) -> str:
    # Cette méthode permet d'exprimer « la sonde de bout en bout est en échec » (1 si KO, 0 si OK, 0 si inconnue).
    # `or vector(1)` : sonde absente ⇒ on suppose le service joignable (probe_failed = 0), pas d'anomalie inventée.
    return f'1 - (max(probe_success{{service="{_PROBE_LABEL[service]}"}}) or vector(1))'


# Les débits ne comptent que le trafic utilisateur (sondes /health exclues) : une plateforme inactive vaut 0.
# Les variables sont regroupées par service : chaque service a son propre vecteur et son propre modèle,
# car les ordres de grandeur diffèrent (req/s d'une API vs lignes de log/min du frontal).
FEATURES: dict[str, list[Feature]] = {
    "auth-service": [
        Feature("req_rate", "prom", '(sum(rate(http_requests_total{service="auth-service",route!="/health"}[1m])) or vector(0))'),
        Feature(
            "error_ratio_5xx", "prom",
            '(sum(rate(http_requests_total{service="auth-service",status=~"5.."}[1m])) or vector(0))'
            ' / clamp_min(sum(rate(http_requests_total{service="auth-service"}[1m])) or vector(0.001), 0.001)',
        ),
        Feature(
            "latency_p95", "prom",
            'histogram_quantile(0.95, sum by (le) ('
            'rate(http_request_duration_seconds_bucket{service="auth-service",route!="/health"}[1m])))',
            nan_fill="median",
        ),
        Feature("login_failures_per_min", "prom", '(sum(rate(auth_login_attempts_total{result="failure"}[1m])) or vector(0)) * 60'),
        Feature("client_errors_4xx_rate", "prom", '(sum(rate(http_requests_total{service="auth-service",status=~"4.."}[1m])) or vector(0))'),
        Feature("probe_failed", "prom", _probe_fail("auth-service")),
    ],
    "payment-api": [
        Feature("req_rate", "prom", '(sum(rate(http_requests_total{service="payment-api",route!="/health"}[1m])) or vector(0))'),
        Feature(
            "error_ratio_5xx", "prom",
            '(sum(rate(http_requests_total{service="payment-api",status=~"5.."}[1m])) or vector(0))'
            ' / clamp_min(sum(rate(http_requests_total{service="payment-api"}[1m])) or vector(0.001), 0.001)',
        ),
        Feature(
            "latency_p95", "prom",
            'histogram_quantile(0.95, sum by (le) ('
            'rate(http_request_duration_seconds_bucket{service="payment-api",route!="/health"}[1m])))',
            nan_fill="median",
        ),
        # Jetons invalides en rafale : seul le journal les porte (event_type=auth_failure), pas de métrique dédiée.
        Feature("invalid_tokens_per_min", "loki", 'sum(count_over_time({service="payment-api", event_type="auth_failure"}[1m]))'),
        Feature("client_errors_4xx_rate", "prom", '(sum(rate(http_requests_total{service="payment-api",status=~"4.."}[1m])) or vector(0))'),
        Feature("probe_failed", "prom", _probe_fail("payment-api")),
    ],
    "frontend": [
        # Débit vu au frontal nginx (lignes de journal/min) : capte le trafic même quand le WAF bloque en amont.
        # Sondes blackbox et healthcheck Docker exclus : seul le trafic utilisateur compte (0 en période creuse).
        Feature(
            "req_rate_per_min", "loki",
            'sum(count_over_time({service="frontend"} != "resilience-alpha-probe" != "/healthz" [1m]))',
        ),
        # Requêtes bloquées par le WAF (HTTP 403 dans le journal d'audit) : rafales SQLi/XSS.
        Feature(
            "waf_blocks_per_min", "loki",
            'sum(count_over_time({service="waf"} |= "\\"transaction\\"" '
            '| json code="transaction.response.http_code" | code="403" [1m]))',
        ),
        Feature("probe_failed", "prom", _probe_fail("frontend")),
    ],
}

SERVICES: list[str] = list(FEATURES)


def _client_for(source: str, prom, loki):
    # Cette méthode permet de choisir le bon client selon la source déclarée par la variable.
    if source == "prom":
        return prom
    if source == "loki":
        return loki
    raise ValueError(f"Source inconnue : {source}")


def extract_instant(prom, loki, at: float | None = None) -> dict[str, dict[str, float]]:
    # Cette méthode permet de calculer, pour chaque service, le vecteur de variables à l'instant courant.
    # Les erreurs de source (Loki/Prometheus indisponible) remontent à l'appelant : c'est la boucle qui décide.
    observations: dict[str, dict[str, float]] = {}
    for service, specs in FEATURES.items():
        values: dict[str, float] = {}
        for spec in specs:
            client = _client_for(spec.source, prom, loki)
            values[spec.name] = client.query(spec.query, at)
        observations[service] = values
    return observations


def extract_range(prom, loki, start: float, end: float, step: float) -> list[dict]:
    # Cette méthode permet d'exporter l'historique des variables entre deux dates : une ligne par (timestamp, service).
    # La grille est calée sur un multiple du pas : Loki aligne ses points sur ces multiples, Prometheus suit `start`.
    # Sans ce calage, un point Loki postérieur de quelques secondes serait rapproché du mauvais échantillon.
    start = (int(start) // int(step)) * int(step)
    grid = [round(start + i * step) for i in range(int((end - start) / step) + 1)]
    rows: list[dict] = []
    for service, specs in FEATURES.items():
        series: dict[str, dict[float, float]] = {}
        for spec in specs:
            client = _client_for(spec.source, prom, loki)
            series[spec.name] = client.query_range(spec.query, start, end, step)
        for ts in grid:
            row = {"timestamp": ts, "service": service}
            for spec in specs:
                # On rapproche l'échantillon du point de grille le plus proche (tolérance d'un pas).
                row[spec.name] = _nearest(series[spec.name], ts, step)
            rows.append(row)
    return rows


def _nearest(series: dict[float, float], ts: float, step: float) -> float:
    # Cette méthode permet de retrouver la valeur d'une série au point de grille voulu (NaN si absent).
    # Tolérance d'un demi-pas seulement : Loki omet les points sans événement, et se rabattre sur le point
    # suivant (un pas plus tard) ferait « voir le futur » à l'échantillon (fuite temporelle).
    if ts in series:
        return series[ts]
    best, best_dist = float("nan"), step / 2
    for key, val in series.items():
        dist = abs(key - ts)
        if dist < best_dist:
            best, best_dist = val, dist
    return best


def feature_names(service: str) -> list[str]:
    # Cette méthode permet d'obtenir la liste ordonnée des noms de variables d'un service.
    return [spec.name for spec in FEATURES[service]]


def clean_vector(service: str, values: dict[str, float], medians: dict[str, float]) -> list[float]:
    # Cette méthode permet de remplacer les valeurs manquantes (NaN) selon la règle de chaque variable :
    # "zero" (absence d'activité) ou "median" (valeur neutre apprise, pour ne pas inventer une anomalie).
    cleaned: list[float] = []
    for spec in FEATURES[service]:
        value = values.get(spec.name, float("nan"))
        if value is None or isnan(value):
            value = medians.get(spec.name, 0.0) if spec.nan_fill == "median" else 0.0
        cleaned.append(float(value))
    return cleaned
