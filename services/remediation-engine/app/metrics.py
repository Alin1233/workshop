"""Métriques Prometheus du moteur de remédiation (exposées sur /metrics, scrapées par le job remediation-engine).

Toutes les combinaisons de labels connues sont créées à zéro au démarrage : `increase()` voit ainsi le premier échec
(une série qui naît directement à 1 passerait inaperçue de la règle RemediationFailed).
"""

from prometheus_client import Counter, Gauge, Histogram

ACTIONS = ("restart", "start", "block_ip", "restore_db")
ACTION_RESULTS = ("success", "failure", "refused")
ESCALATION_REASONS = (
    "policy",                   # alerte sans action automatique par conception (hôte, sauvegardes, contrôle figé)
    "attempts_exhausted",       # anti-boucle : budget de tentatives épuisé
    "verification_failed",      # action faite mais service non rétabli
    "action_failed",            # action impossible (proxy, WAF, pont)
    "bridge_unavailable",       # corruption confirmée mais aucun pont de restauration actif
    "waf_unavailable",          # blocage impossible : module ou volume WAF indisponible
    "no_offender",              # attaque sans IP attribuable
    "triage_unknown",           # anomalie ML sans variable dominante exploitable
    "container_missing",        # conteneur absent : recréation hors du périmètre du proxy
    "unknown_alert",            # alerte absente de la table de décision
    "not_allowed",              # cible hors de la liste des services redémarrables
)

ACTIONS_TOTAL = Counter("remediation_actions_total", "Actions de remédiation exécutées", ["action", "result"])
DURATION = Histogram("remediation_duration_seconds", "Durée détection → rétablissement vérifié", ["nature"],
                     buckets=(5, 10, 20, 30, 45, 60, 90, 120, 180, 300, 600, 1200))
INCIDENTS_OPEN = Gauge("remediation_incidents_open", "Incidents de remédiation ouverts")
VERIFICATIONS = Counter("remediation_verification_total", "Vérifications après action", ["result"])
ESCALATIONS = Counter("remediation_escalations_total", "Incidents escaladés vers l'opérateur", ["reason"])
ALERTS = Counter("remediation_alerts_received_total", "Alertes reçues d'Alertmanager", ["status"])
WEBHOOK_REJECTED = Counter("remediation_webhook_rejected_total", "Appels du webhook refusés", ["reason"])
BLOCKS_ACTIVE = Gauge("remediation_blocked_ips", "IP actuellement bloquées au WAF par le moteur")
DEPENDENCY_UP = Gauge("remediation_dependency_up", "Dépendances du moteur joignables (1) ou non (0)", ["dependency"])


def initialise() -> None:
    # Cette méthode permet de créer à zéro toutes les séries attendues par les règles d'alerte et le dashboard.
    for action in ACTIONS:
        for result in ACTION_RESULTS:
            ACTIONS_TOTAL.labels(action, result)
    for result in ("success", "failure"):
        VERIFICATIONS.labels(result)
    for reason in ESCALATION_REASONS:
        ESCALATIONS.labels(reason)
    for status in ("firing", "resolved"):
        ALERTS.labels(status)
    for reason in ("unauthorized", "token_unavailable", "invalid_payload", "too_large"):
        WEBHOOK_REJECTED.labels(reason)
    for nature in ("availability", "compromise"):
        DURATION.labels(nature)
