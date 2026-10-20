"""Table de décision du moteur de remédiation : une ligne par alerte (alertname), sans logique cachée.

Elle couvre explicitement toutes les règles de infra/prometheus/rules/*.yml et infra/loki/rules/fake/soc.yml
(un test unitaire le vérifie) et sépare nettement deux familles de réponses :
- **disponibilité** (`availability`) : le service est en panne → on le **redémarre** (PostgreSQL d'abord s'il est en cause) ;
- **compromission** (`compromise`) : le service est attaqué ou ses données sont fausses → on **bloque** l'IP au WAF ou on
  **restaure** la base ; redémarrer ne corrigerait rien.
Les autres alertes ne déclenchent aucune action métier : `observe` (surveiller), `operator` (escalade vers un humain),
`self` (alerte sur la chaîne de remédiation elle-même, jamais traitée par le moteur : anti-boucle). `AnomalyDetected`
est triée (`triage`) selon la variable dominante du modèle ML.

Cette table est exposée en lecture seule par `GET /api/decision-table` et reprise dans le README et l'EBIOS RM.
"""

from dataclasses import asdict, dataclass
from enum import StrEnum


class Nature(StrEnum):
    AVAILABILITY = "availability"   # rétablir la disponibilité : redémarrage
    COMPROMISE = "compromise"       # corriger une compromission : blocage d'IP, restauration des données
    TRIAGE = "triage"               # nature décidée à l'exécution (anomalie ML : variable dominante)
    OBSERVE = "observe"             # surveiller, aucune action
    OPERATOR = "operator"           # escalade vers l'opérateur, aucune action automatique
    SELF = "self"                   # alerte sur le moteur lui-même : journalisée, jamais remédiée


class Strategy(StrEnum):
    RESTART = "restart"                              # redémarrer le service (diagnostic de la chaîne de dépendances)
    OBSERVE_THEN_RESTART = "observe_then_restart"    # observer, redémarrer seulement si l'alerte persiste
    INTEGRITY_RESTORE = "integrity_restore"          # confirmer la corruption (base saine + 409) puis restaurer
    BLOCK_ALERT_IP = "block_alert_ip"                # bloquer au WAF l'IP portée par l'alerte (label client_ip)
    BLOCK_TOP_IP = "block_top_ip"                    # retrouver l'IP la plus fautive dans Loki, puis la bloquer
    ANOMALY_TRIAGE = "anomaly_triage"                # router selon la variable dominante du modèle ML
    RESTART_DETECTOR = "restart_detector"            # un seul redémarrage du détecteur (sans état)
    OBSERVE = "observe"                              # surveiller jusqu'à la résolution
    ESCALATE = "escalate"                            # journaliser et escalader vers l'opérateur
    IGNORE_SELF = "ignore_self"                      # alerte du moteur lui-même : aucune action (anti-boucle)


@dataclass(frozen=True)
class Rule:
    alertname: str
    source: str                 # prometheus | loki | engine
    nature: Nature
    strategy: Strategy
    response: str               # réponse prévue, en clair (dashboard, README)
    ebios: str = ""             # scénario EBIOS RM (docs/governance/ebios-rm.md)
    upstream: bool = False      # la sonde traverse WAF → frontal : ils font partie de la chaîne diagnostiquée
    when_healthy: str = "restart"   # chaîne saine mais alerte active : "restart" le service, ou "verify" seulement
    symptom: str = ""           # PromQL : 1 quand le symptôme a disparu ({svc} et {probe} sont substitués)

    def describe(self) -> dict:
        # Cette méthode permet d'exposer la règle sous forme de dictionnaire JSON (API, documentation).
        return asdict(self)


_UP = 'max(up{{job="{svc}"}})'
_PROBE = 'min(probe_success{{job="blackbox-http",service="{probe}"}})'

RULES: tuple[Rule, ...] = (
    # ── Disponibilité : redémarrer ──
    Rule("ServiceDown", "prometheus", Nature.AVAILABILITY, Strategy.RESTART,
         "Redémarrer le service qui ne répond plus (PostgreSQL d'abord s'il est en panne)", "S3", symptom=_UP),
    Rule("EndToEndProbeFailed", "prometheus", Nature.AVAILABILITY, Strategy.RESTART,
         "Redémarrer le maillon en panne du parcours WAF → frontal → API → PostgreSQL (label auth/payments/frontend)",
         "S3", upstream=True, symptom=_PROBE),
    Rule("HighErrorRate", "prometheus", Nature.AVAILABILITY, Strategy.RESTART,
         "Redémarrer le service qui renvoie des 5xx (PostgreSQL d'abord s'il est en panne)", "S3"),
    Rule("DependencyFailures", "loki", Nature.AVAILABILITY, Strategy.RESTART,
         "Base injoignable : redémarrer PostgreSQL s'il est arrêté ou en échec, puis l'API si elle reste en échec",
         "S4", when_healthy="verify"),
    Rule("HighLatencyP95", "prometheus", Nature.AVAILABILITY, Strategy.OBSERVE_THEN_RESTART,
         "Observer ; redémarrer le service seulement si la latence reste élevée", "S3"),
    Rule("AnomalyDetectorDown", "prometheus", Nature.AVAILABILITY, Strategy.RESTART_DETECTOR,
         "Un seul redémarrage d'anomaly-detector (sans état), aucune action sur le SI métier"),
    # ── Compromission : restaurer les données ──
    Rule("LedgerIntegrityBroken", "prometheus", Nature.COMPROMISE, Strategy.INTEGRITY_RESTORE,
         "Confirmer la corruption (PostgreSQL sain et /internal/integrity en 409), puis restaurer la dernière "
         "sauvegarde saine par le pont hôte ; base injoignable = panne de disponibilité, pas de restauration", "S5"),
    Rule("LedgerIntegrityViolationLogged", "loki", Nature.COMPROMISE, Strategy.INTEGRITY_RESTORE,
         "Même réponse que LedgerIntegrityBroken (violation journalisée par payment-api)", "S5"),
    # ── Compromission : bloquer l'attaquant ──
    Rule("AuthBruteForce", "loki", Nature.COMPROMISE, Strategy.BLOCK_ALERT_IP,
         "Bloquer au WAF l'IP de la force brute (label client_ip)", "S1"),
    Rule("InvalidTokenFlood", "loki", Nature.COMPROMISE, Strategy.BLOCK_ALERT_IP,
         "Bloquer au WAF l'IP qui rejoue des jetons invalides (label client_ip)", "S1"),
    Rule("WafAttackBlocked", "loki", Nature.COMPROMISE, Strategy.BLOCK_ALERT_IP,
         "Bloquer au WAF l'IP qui enchaîne les injections (label client_ip)", "S2"),
    Rule("LoginFailureSpike", "prometheus", Nature.COMPROMISE, Strategy.BLOCK_TOP_IP,
         "Retrouver dans Loki l'IP la plus fautive (échecs de connexion, 2 min) et la bloquer si elle dépasse le "
         "seuil ; sinon observer (attaque distribuée)", "S1"),
    # ── Anomalie ML : tri par variable dominante ──
    Rule("AnomalyDetected", "prometheus", Nature.TRIAGE, Strategy.ANOMALY_TRIAGE,
         "Lire la variable dominante (journal anomaly_detected) : attaque → bloquer l'IP fautive ; panne → "
         "redémarrer le service ; co-alerte du frontal → rattacher ; sinon observer et escalader", "S1, S3"),
    # ── Sans action métier ──
    Rule("AnomalyDetectorBlind", "prometheus", Nature.OBSERVE, Strategy.OBSERVE,
         "Observer : une source du détecteur est injoignable, ni panne métier ni attaque"),
    Rule("LedgerIntegrityCheckStale", "prometheus", Nature.OPERATOR, Strategy.ESCALATE,
         "Journaliser et escalader : le contrôle d'intégrité ne tourne plus (aucune restauration à l'aveugle)"),
    Rule("HostDiskSpaceLow", "prometheus", Nature.OPERATOR, Strategy.ESCALATE,
         "Journaliser et escalader : espace disque du PC Hôte"),
    Rule("HostMemoryLow", "prometheus", Nature.OPERATOR, Strategy.ESCALATE,
         "Journaliser et escalader : mémoire du PC Hôte"),
    Rule("BackupMissing", "prometheus", Nature.OPERATOR, Strategy.ESCALATE,
         "Journaliser et escalader : sauvegarde PostgreSQL manquante (RPO dépassé)"),
    Rule("BackupFailed", "prometheus", Nature.OPERATOR, Strategy.ESCALATE,
         "Journaliser et escalader : dernière sauvegarde PostgreSQL en échec"),
    # ── Alertes du moteur lui-même (règles du groupe remediation) : jamais d'action, anti-boucle ──
    Rule("RemediationFailed", "prometheus", Nature.SELF, Strategy.IGNORE_SELF,
         "Journaliser uniquement : l'échec du moteur relève de l'opérateur"),
    Rule("RemediationEngineDown", "prometheus", Nature.SELF, Strategy.IGNORE_SELF,
         "Journaliser uniquement (reçue par Alertmanager, le moteur étant arrêté)"),
)

DECISION_TABLE: dict[str, Rule] = {rule.alertname: rule for rule in RULES}

# Alerte inconnue de la table : jamais d'action à l'aveugle, escalade.
UNKNOWN_RULE = Rule("*", "engine", Nature.OPERATOR, Strategy.ESCALATE,
                    "Alerte absente de la table de décision : aucune action automatique, escalade")
# Toute alerte visant la chaîne de remédiation elle-même (ex. HighErrorRate{service="remediation-engine"})
SELF_SERVICES = frozenset({"remediation-engine", "docker-socket-proxy"})
SELF_RULE = Rule("*self*", "engine", Nature.SELF, Strategy.IGNORE_SELF,
                 "Alerte sur le moteur de remédiation ou son proxy : journalisée, jamais remédiée (anti-boucle)")

# Label `service` des sondes blackbox → service Compose (infra/prometheus/prometheus.yml)
PROBE_SERVICES = {"auth": "auth-service", "payments": "payment-api", "frontend": "frontend"}
PROBE_LABELS = {service: probe for probe, service in PROBE_SERVICES.items()}
# Services que le moteur a le droit de redémarrer (tout le reste est refusé, même si le proxy l'autoriserait)
RESTARTABLE = frozenset({"postgres", "auth-service", "payment-api", "frontend", "waf", "anomaly-detector"})
# Dépendances internes : un service en panne à cause de sa base se répare en réparant la base d'abord.
DEPENDENCIES = {"auth-service": ["postgres"], "payment-api": ["postgres"]}
UPSTREAM = {"auth-service": ["frontend", "waf"], "payment-api": ["frontend", "waf"], "frontend": ["waf"]}
# La restauration recrée authdb et paydb : elle arrête puis relance les deux API (resilience-pg-restore).
RESTORE_SCOPE = ["postgres", "auth-service", "payment-api"]
API_SERVICES = frozenset({"auth-service", "payment-api"})

# Variables dominantes du détecteur ML (services/anomaly-detector/app/features.py)
SECURITY_FEATURES = frozenset({"login_failures_per_min", "invalid_tokens_per_min", "waf_blocks_per_min",
                               "client_errors_4xx_rate"})
AVAILABILITY_FEATURES = frozenset({"error_ratio_5xx", "latency_p95", "probe_failed"})

# Recherche de l'IP fautive dans Loki (fenêtre de 2 min, une valeur par client_ip)
_AUTH_FAILURES = ('sum by (client_ip) (count_over_time({service="auth-service", event_type="auth_failure"} '
                  '| json client_ip="client_ip" | client_ip!="" [2m]))')
_INVALID_TOKENS = ('sum by (client_ip) (count_over_time({service="payment-api", event_type="auth_failure"} '
                   '| json client_ip="client_ip" | client_ip!="" [2m]))')
_WAF_BLOCKS = ('sum by (client_ip) (count_over_time({service="waf"} |= "\\"transaction\\"" '
               '| json client_ip="transaction.client_ip", code="transaction.response.http_code" | code="403" [2m]))')
_CLIENT_ERRORS = ('sum by (client_ip) (count_over_time({{service="{service}"}} '
                  '| json client_ip="client_ip", status="status" | status=~"4.." | client_ip!="" [2m]))')
LOGIN_FAILURES_QUERY = _AUTH_FAILURES


def offender_query(feature: str, service: str) -> str | None:
    # Cette méthode permet de choisir la requête LogQL qui attribue une variable d'attaque à des IP clientes.
    if feature == "login_failures_per_min":
        return _AUTH_FAILURES
    if feature == "invalid_tokens_per_min":
        return _INVALID_TOKENS
    if feature == "waf_blocks_per_min":
        return _WAF_BLOCKS
    if feature == "client_errors_4xx_rate" and service in API_SERVICES:
        return _CLIENT_ERRORS.format(service=service)
    return None


def anomaly_log_query(service: str) -> str:
    # Cette méthode permet de construire la requête du dernier journal anomaly_detected visant un service.
    return ('{service="anomaly-detector", event_type="anomaly_detected"} '
            f'| json target_service="target_service" | target_service="{service}"')


def rule_for(labels: dict) -> Rule:
    # Cette méthode permet de trouver la règle d'une alerte : protection anti-boucle d'abord (alerte visant le moteur),
    # puis la table, puis la règle « inconnue » (escalade sans action).
    if labels.get("service") in SELF_SERVICES:
        return SELF_RULE
    return DECISION_TABLE.get(labels.get("alertname", ""), UNKNOWN_RULE)


def target_service(labels: dict) -> str | None:
    # Cette méthode permet de traduire le label `service` d'une alerte en service Compose (sondes auth/payments/frontend).
    service = labels.get("service")
    return PROBE_SERVICES.get(service, service) if service else None


def correlation_key(rule: Rule, labels: dict) -> str:
    # Cette méthode permet de regrouper en un seul incident les alertes qui appellent la même réponse sur la même cible
    # (ex. ServiceDown + EndToEndProbeFailed sur payment-api, AuthBruteForce + WafAttackBlocked depuis la même IP).
    service = target_service(labels) or "-"
    strategy = rule.strategy
    if strategy is Strategy.RESTART:
        return f"service:{service}"
    if strategy is Strategy.OBSERVE_THEN_RESTART:
        return f"latency:{service}"
    if strategy is Strategy.INTEGRITY_RESTORE:
        return "integrity:payment-api"
    if strategy is Strategy.BLOCK_ALERT_IP:
        return f"ip:{labels.get('client_ip', '-')}"
    if strategy is Strategy.BLOCK_TOP_IP:
        return f"login-spike:{service}"
    if strategy is Strategy.ANOMALY_TRIAGE:
        return f"anomaly:{service}"
    if strategy is Strategy.RESTART_DETECTOR:
        return "detector:anomaly-detector"
    return f"{rule.nature}:{labels.get('alertname', '-')}:{service}"


def chain_for(service: str, upstream: bool) -> list[str]:
    # Cette méthode permet de lister les conteneurs à diagnostiquer, dans l'ordre où réparer : dépendances (PostgreSQL),
    # puis le service, puis l'amont du parcours client (frontal, WAF) quand l'alerte vient d'une sonde de bout en bout.
    chain = [*DEPENDENCIES.get(service, []), service]
    if upstream:
        chain += [s for s in UPSTREAM.get(service, []) if s not in chain]
    return chain


def table_document() -> list[dict]:
    # Cette méthode permet de produire la table de décision complète (API d'état, README).
    return [rule.describe() for rule in RULES]
