"""Métriques Prometheus du moteur de remédiation (exposées sur /metrics, scrapées par le job remediation-engine).

Toutes les combinaisons de labels connues sont créées à zéro au démarrage : `increase()` voit ainsi le premier échec
(une série qui naît directement à 1 passerait inaperçue de la règle RemediationFailed).
"""

from prometheus_client import Counter, Gauge, Histogram

from .decisions import RESTARTABLE

ACTIONS = ("restart", "start", "block_ip", "restore_db")
ACTION_RESULTS = ("success", "failure", "refused")
# Label `target` des actions, borné par construction : un service Compose redémarrable, le WAF pour un blocage d'IP,
# la base pour une restauration. Jamais une IP ni une valeur reçue dans une alerte (cardinalité fixe, pas d'injection).
ACTION_TARGETS = {"restart": tuple(sorted(RESTARTABLE)), "start": tuple(sorted(RESTARTABLE)),
                  "block_ip": ("waf",), "restore_db": ("paydb",)}
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
NATURES = ("availability", "compromise")
# Seaux sous 5 s : un blocage d'IP ou une vérification seule se règlent en moins d'une seconde.
DURATION_BUCKETS = (0.5, 1, 2, 5, 10, 20, 30, 45, 60, 90, 120, 180, 300, 600, 1200)

ACTIONS_TOTAL = Counter("remediation_actions_total", "Actions de remédiation exécutées", ["action", "target", "result"])
# Les deux durées ne sont observées que pour un incident rétabli après une action du moteur lui-même : un incident
# rattaché (« déjà redémarré par… », « IP déjà bloquée ») ne mesure qu'une vérification et compterait deux fois la
# même panne, avec une durée artificiellement courte.
DURATION = Histogram("remediation_duration_seconds", "Durée détection (webhook reçu) → rétablissement vérifié, "
                     "incidents où le moteur a agi", ["nature"], buckets=DURATION_BUCKETS)
ALERT_TO_RECOVERY = Histogram("remediation_alert_to_recovery_seconds", "Durée déclenchement de l'alerte (startsAt) → "
                              "rétablissement vérifié, incidents où le moteur a agi", ["nature"], buckets=DURATION_BUCKETS)
INCIDENTS_OPEN = Gauge("remediation_incidents_open", "Incidents de remédiation ouverts")
VERIFICATIONS = Counter("remediation_verification_total", "Vérifications après action", ["result"])
ESCALATIONS = Counter("remediation_escalations_total", "Incidents escaladés vers l'opérateur", ["reason"])
ALERTS = Counter("remediation_alerts_received_total", "Alertes reçues d'Alertmanager", ["status"])
WEBHOOK_REJECTED = Counter("remediation_webhook_rejected_total", "Appels du webhook refusés", ["reason"])
BLOCKS_ACTIVE = Gauge("remediation_blocked_ips", "IP actuellement bloquées au WAF par le moteur")
DEPENDENCY_UP = Gauge("remediation_dependency_up", "Dépendances du moteur joignables (1) ou non (0)", ["dependency"])


def action_target(action: str, target: str | None) -> str:
    # Cette méthode permet de ramener la cible d'une action à une valeur de label bornée (jamais l'IP bloquée).
    allowed = ACTION_TARGETS.get(action, ())
    if len(allowed) == 1:
        return allowed[0]
    return target if target in allowed else "other"


def initialise() -> None:
    # Cette méthode permet de créer à zéro toutes les séries attendues par les règles d'alerte et le dashboard.
    for action in ACTIONS:
        for target in ACTION_TARGETS[action]:
            for result in ACTION_RESULTS:
                ACTIONS_TOTAL.labels(action, target, result)
    for result in ("success", "failure"):
        VERIFICATIONS.labels(result)
    for reason in ESCALATION_REASONS:
        ESCALATIONS.labels(reason)
    for status in ("firing", "resolved"):
        ALERTS.labels(status)
    for reason in ("unauthorized", "token_unavailable", "invalid_payload", "too_large"):
        WEBHOOK_REJECTED.labels(reason)
    for nature in NATURES:
        DURATION.labels(nature)
        ALERT_TO_RECOVERY.labels(nature)
