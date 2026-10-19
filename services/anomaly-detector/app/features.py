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

Deux situations « sans valeur » sont soigneusement distinguées :
- la requête a réussi mais ne renvoie rien (aucune activité) → NaN, puis comblé par `nan_fill` : c'est un
  comportement normal (plateforme au repos) ;
- la SOURCE est injoignable (Loki/Prometheus en panne, authentification refusée) → la variable est déclarée
  **manquante** (`Observation.missing`) et n'est jamais comblée : elle ne doit pas passer pour « normale ».
La dégradation est **par service** : Loki en panne n'empêche pas de scorer auth-service, dont toutes les
variables viennent de Prometheus ; seuls payment-api et frontend (qui lisent Loki) deviennent incomplets.
"""

from dataclasses import dataclass, field
from math import isnan

from .promclient import SourceUnavailable


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


@dataclass
class Observation:
    """Variables d'un service à un instant : valeurs obtenues et variables manquantes (source injoignable)."""

    values: dict[str, float] = field(default_factory=dict)  # NaN = requête réussie mais sans donnée
    missing: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        # Cette méthode permet de savoir si toutes les variables du service ont pu être interrogées.
        return not self.missing


def extract_instant(prom, loki, at: float | None = None) -> tuple[dict[str, Observation], dict[str, str]]:
    # Cette méthode permet de calculer, pour chaque service, les variables à l'instant courant, en dégradant
    # service par service : une source en échec rend « manquantes » ses variables, sans bloquer les autres services.
    # Dès qu'une source échoue, ses requêtes suivantes sont sautées pour ce cycle (pas d'empilement de délais).
    # Renvoie (observations par service, {source en échec: message d'erreur}).
    clients = {"prom": prom, "loki": loki}
    errors: dict[str, str] = {}
    observations: dict[str, Observation] = {}
    for service, specs in FEATURES.items():
        obs = Observation()
        for spec in specs:
            if spec.source not in clients:
                raise ValueError(f"Source inconnue : {spec.source}")
            if spec.source in errors:
                obs.missing.append(spec.name)
                continue
            try:
                obs.values[spec.name] = clients[spec.source].query(spec.query, at)
            except SourceUnavailable as exc:
                errors[spec.source] = str(exc)
                obs.missing.append(spec.name)
        observations[service] = obs
    return observations, errors


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


def clean_values(service: str, values: dict[str, float], medians: dict[str, float]) -> dict[str, float]:
    # Cette méthode permet de nettoyer les variables obtenues d'un service, associées par nom : une valeur NaN
    # (requête réussie, aucune donnée) est remplacée selon la règle de la variable — "zero" (absence d'activité)
    # ou "median" (valeur neutre apprise sur le normal d'entraînement). Une variable ABSENTE de `values` (source
    # injoignable) reste absente : elle n'est jamais comblée, pour ne pas la faire passer pour normale.
    # C'est la fonction utilisée à l'inférence ET à l'évaluation (ml/train.py) : prétraitement identique.
    cleaned: dict[str, float] = {}
    for spec in FEATURES[service]:
        if spec.name not in values:
            continue
        value = values[spec.name]
        if value is None or isnan(value):
            value = medians.get(spec.name, 0.0) if spec.nan_fill == "median" else 0.0
        cleaned[spec.name] = float(value)
    return cleaned


def expected_features() -> dict[str, list[str]]:
    # Cette méthode permet d'obtenir la liste des variables attendues par service (validation du modèle au chargement).
    return {service: feature_names(service) for service in SERVICES}
