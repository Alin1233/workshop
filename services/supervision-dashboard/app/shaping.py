"""Mise en forme des données des sources pour l'écran de supervision (fonctions pures, testées sans réseau).

- `components` : carte des composants (ok / degraded / down / unknown / active) avec la raison, en français ;
- `global_status` : bandeau d'état (opérationnel, incident, remédiation, rétabli) avec l'étape courante et l'instant de
  début, à partir des incidents du moteur, des alertes et, avant toute alerte, de la carte des composants ;
- `shape_alerts`, `shape_events`, `shape_blocks`, `shape_incident` : panneaux d'alertes, fil d'événements, blocages
  d'IP et chronologie (champs en liste blanche, tailles bornées, aucun secret).
"""

import math
import re
from datetime import datetime, timezone
from typing import Any

OK, DEGRADED, DOWN, UNKNOWN, ACTIVE = "ok", "degraded", "down", "unknown", "active"
BUSINESS_COMPONENTS = ("waf", "frontend", "auth-service", "payment-api", "postgres")

NATURE_LABELS = {"availability": "Disponibilité", "compromise": "Compromission", "triage": "Tri ML",
                 "observe": "Observation", "operator": "Opérateur", "self": "Moteur"}
CHECK_LABELS = {"containers": "conteneurs", "probes": "sondes de bout en bout", "integrity": "intégrité du registre",
                "witness": "transaction témoin", "waf_block": "blocage effectif au WAF"}
# Alertes d'exploitation (hôte, sauvegardes, chaîne de supervision elle-même) : visibles dans les alertes et
# l'historique, mais elles ne pilotent pas le bandeau du service métier.
INFRA_ALERTS = frozenset({
    "HostDiskSpaceLow", "HostMemoryLow", "BackupMissing", "BackupFailed", "LedgerIntegrityCheckStale",
    "AnomalyDetectorBlind", "AnomalyDetectorDown", "RemediationFailed", "RemediationEngineDown"})
SOC_ALERTS = frozenset({"AuthBruteForce", "InvalidTokenFlood", "WafAttackBlocked", "LedgerIntegrityViolationLogged",
                        "DependencyFailures"})
STATE_PRIORITY = {"acting": 0, "verifying": 1, "failed": 2, "decided": 3, "detected": 4, "observing": 5,
                  "escalated": 6, "recovered": 7}
PROBE_OF = {"frontend": "frontend", "auth-service": "auth", "payment-api": "payments"}


# ─────────────────────────────── utilitaires ───────────────────────────────

def parse_ts(value: Any) -> float | None:
    # Cette méthode permet de lire un horodatage ISO 8601 (moteur, Alertmanager, Prometheus) en temps Unix.
    if not isinstance(value, str) or not value or value.startswith("0001-"):
        return None
    try:
        text = value.replace("Z", "+00:00")
        # Prometheus et Loki donnent des nanosecondes : Python n'accepte que 6 décimales
        text = re.sub(r"(\.\d{6})\d+", r"\1", text)
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def iso(ts: float | None) -> str | None:
    # Cette méthode permet de formater un temps Unix en ISO 8601 UTC (millisecondes).
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds") if ts is not None else None


def clip(value: Any, size: int = 160) -> str:
    # Cette méthode permet de borner un texte venu d'une source (journaux d'attaque compris) : une ligne, taille fixe.
    text = " ".join(str(value).split())
    return text if len(text) <= size else text[:size - 1] + "…"


def fmt_num(value: float, digits: int = 2) -> str:
    # Cette méthode permet d'écrire un nombre à la française (virgule décimale).
    return f"{value:.{digits}f}".replace(".", ",")


class Metrics:
    """Index d'une réponse vectorielle de Prometheus : valeur d'une série par nom et labels."""

    def __init__(self, result: list | None):
        # Cette méthode permet de convertir le résultat brut en liste (nom, labels, valeur).
        self.available = result is not None
        self.series: list[tuple[str, dict, float]] = []
        for item in result or []:
            if not isinstance(item, dict):
                continue
            labels = dict(item.get("metric") or {})
            name = labels.pop("__name__", "")
            try:
                value = float((item.get("value") or [0, "nan"])[1])
            except (TypeError, ValueError, IndexError):
                value = math.nan
            self.series.append((name, labels, value))

    def all(self, name: str, **match: str) -> list[tuple[dict, float]]:
        # Cette méthode permet de lister les séries d'une métrique dont les labels correspondent.
        return [(labels, value) for n, labels, value in self.series
                if n == name and all(labels.get(k) == v for k, v in match.items())]

    def get(self, name: str, **match: str) -> float | None:
        # Cette méthode permet de lire la valeur d'une série (la plus basse s'il y en a plusieurs : le pire cas).
        values = [value for _, value in self.all(name, **match) if not math.isnan(value)]
        return min(values) if values else None


def is_business(incident: dict) -> bool:
    # Cette méthode permet de distinguer un incident du service métier d'un incident d'exploitation (hôte, détecteur…).
    return (incident.get("nature") not in ("self", "operator")
            and incident.get("rule", incident.get("alertname")) not in INFRA_ALERTS)


def restore_in_progress(state: dict | None) -> bool:
    # Cette méthode permet de savoir si une restauration de la base est en cours (pont occupé ou incident en action).
    if not state:
        return False
    bridge = state.get("bridge") or {}
    if bridge.get("busy") or bridge.get("in_flight_request_id") or bridge.get("active_request_id"):
        return True
    return any(i.get("state") == "acting" and (i.get("decision") or {}).get("action") == "restore_db"
               for i in state.get("open_incidents") or [])


def comp(cid: str, label: str, role: str, state: str, reason: str) -> dict:
    # Cette méthode permet de construire une tuile de la carte des composants.
    return {"id": cid, "label": label, "role": role, "state": state, "reason": reason}


# ─────────────────────────────── carte des composants ───────────────────────────────

def components(result: list | None, state: dict | None, reach: dict[str, bool], now: float) -> list[dict]:
    # Cette méthode permet de déduire l'état de chaque maillon des métriques (up, sondes, intégrité, scores ML), de l'API
    # d'état du moteur et de l'accessibilité des sources ; « unknown » quand la source qui en témoigne est indisponible.
    m = Metrics(result)
    restoring = restore_in_progress(state)
    deps = (state or {}).get("dependencies") or {}
    items: list[dict] = []

    codes = {labels.get("service"): value for labels, value in m.all("probe_http_status_code", job="blackbox-http")}
    probes = {labels.get("service"): value for labels, value in m.all("probe_success", job="blackbox-http")}
    no_prom = "Prometheus indisponible : état inconnu"

    # WAF : il répond (n'importe quel code HTTP) ou non (code 0 = connexion refusée)
    waf_up: bool | None = None
    if not m.available:
        items.append(comp("waf", "WAF", "ModSecurity + OWASP CRS", UNKNOWN, no_prom))
    elif not codes:
        items.append(comp("waf", "WAF", "ModSecurity + OWASP CRS", UNKNOWN, "aucune sonde de bout en bout"))
    elif all((v or 0) <= 0 for v in codes.values()):
        waf_up = False
        items.append(comp("waf", "WAF", "ModSecurity + OWASP CRS", DOWN, "ne répond plus aux sondes (connexion refusée)"))
    else:
        waf_up = True
        blocks = len((state or {}).get("blocked_ips") or [])
        if deps.get("waf_blocklist") is False:
            items.append(comp("waf", "WAF", "ModSecurity + OWASP CRS", DEGRADED,
                              "filtre les requêtes, mais blocage d'IP indisponible"))
        else:
            reason = "filtre les requêtes · répond aux sondes"
            if blocks:
                reason = f"{blocks} IP bloquée{'s' if blocks > 1 else ''} par la remédiation · répond aux sondes"
            items.append(comp("waf", "WAF", "ModSecurity + OWASP CRS", OK, reason))

    # Frontal nginx : sonde de la page d'accueil à travers le WAF
    front_ok: bool | None = None
    if not m.available:
        items.append(comp("frontend", "Frontal web", "nginx + React", UNKNOWN, no_prom))
    elif waf_up is False:
        items.append(comp("frontend", "Frontal web", "nginx + React", UNKNOWN, "masqué : le WAF ne répond pas"))
    elif probes.get("frontend") is None:
        items.append(comp("frontend", "Frontal web", "nginx + React", UNKNOWN, "sonde absente"))
    elif probes["frontend"] >= 1:
        front_ok = True
        items.append(comp("frontend", "Frontal web", "nginx + React", OK, "page servie à travers le WAF"))
    else:
        front_ok = False
        code = int(codes.get("frontend") or 0)
        items.append(comp("frontend", "Frontal web", "nginx + React", DOWN,
                          f"parcours client en échec (HTTP {code})" if code else "parcours client en échec"))

    # API métier : scrape Prometheus (processus) + sonde /health à travers WAF → nginx (base comprise)
    api_probe: dict[str, bool | None] = {}
    for cid, label, role, job in (("auth-service", "auth-service", "authentification JWT", "auth-service"),
                                  ("payment-api", "payment-api", "virements et registre", "payment-api")):
        probe_name = PROBE_OF[cid]
        up = m.get("up", job=job)
        probe = probes.get(probe_name)
        code = int(codes.get(probe_name) or 0)
        api_probe[cid] = None if probe is None else probe >= 1
        if not m.available:
            items.append(comp(cid, label, role, UNKNOWN, no_prom))
            continue
        integrity = m.get("payment_ledger_integrity_ok") if cid == "payment-api" else None
        if restoring and (up == 0 or probe == 0):
            items.append(comp(cid, label, role, ACTIVE, "arrêtée volontairement pendant la restauration"))
        elif up == 0 and probe is not None and probe >= 1:
            # Juste après un redémarrage, la sonde (5 s) revient avant le scrape (10 s) : le parcours client fait foi
            items.append(comp(cid, label, role, DEGRADED, "parcours client OK · scrape Prometheus pas encore revenu"))
        elif up == 0:
            items.append(comp(cid, label, role, DOWN, "arrêtée ou injoignable (scrape Prometheus en échec)"))
        elif up is None and probe is None:
            items.append(comp(cid, label, role, UNKNOWN, "aucune métrique"))
        elif integrity == 0:
            items.append(comp(cid, label, role, DOWN, "registre incohérent : contrôle d'intégrité en échec"))
        elif probe is not None and probe >= 1:
            reason = "parcours client OK à travers le WAF"
            if cid == "payment-api" and integrity == 1:
                reason += " · registre cohérent"
            items.append(comp(cid, label, role, OK if up is not None else DEGRADED, reason))
        elif front_ok is False or waf_up is False:
            items.append(comp(cid, label, role, DEGRADED, "processus actif, parcours client coupé en amont"))
        else:
            items.append(comp(cid, label, role, DOWN,
                              f"/health en échec à travers le WAF (HTTP {code})" if code else "/health en échec"))

    # PostgreSQL : pas d'exporteur ; on le juge par les API (/health interroge la base)
    pg_role = "authdb + paydb"
    if restoring:
        items.append(comp("postgres", "PostgreSQL", pg_role, ACTIVE, "restauration de la dernière sauvegarde saine"))
    elif not m.available:
        items.append(comp("postgres", "PostgreSQL", pg_role, UNKNOWN, no_prom))
    elif any(api_probe.get(c) for c in ("auth-service", "payment-api")):
        items.append(comp("postgres", "PostgreSQL", pg_role, OK, "les API lisent la base"))
    elif (front_ok and all(m.get("up", job=j) == 1 for j in ("auth-service", "payment-api"))
          and all(int(codes.get(p) or 0) == 503 for p in ("auth", "payments"))):
        items.append(comp("postgres", "PostgreSQL", pg_role, DOWN, "les deux API signalent la base injoignable (503)"))
    else:
        items.append(comp("postgres", "PostgreSQL", pg_role, UNKNOWN, "non mesurable tant que les API sont coupées"))

    # Chaîne d'observation : sources lues par le back-for-front et cibles scrapées
    obs_role = "Prometheus · Alertmanager · Loki · Alloy"
    if not reach.get("prometheus"):
        items.append(comp("observability", "Observation", obs_role, DOWN, "Prometheus injoignable"))
    else:
        broken = [name for name, ok in (
            ("Alertmanager", reach.get("alertmanager") and m.get("up", job="alertmanager") != 0),
            ("Loki", reach.get("loki") and m.get("up", service="loki") != 0),
            ("Alloy", m.get("up", service="alloy") != 0),
            ("sondes blackbox", m.get("up", service="blackbox") != 0)) if not ok]
        if broken:
            items.append(comp("observability", "Observation", obs_role, DEGRADED, "en panne : " + ", ".join(broken)))
        else:
            items.append(comp("observability", "Observation", obs_role, OK, "métriques, journaux et alertes collectés"))

    # Détecteur d'anomalies ML
    ml_role = "z-score robuste calibré"
    threshold = m.get("anomaly_threshold")
    scores = [(labels.get("service", "?"), value) for labels, value in m.all("anomaly_score")]
    if not m.available:
        items.append(comp("anomaly-detector", "Détecteur ML", ml_role, UNKNOWN, no_prom))
    elif m.get("up", job="anomaly-detector") in (None, 0):
        items.append(comp("anomaly-detector", "Détecteur ML", ml_role, DOWN, "arrêté (aucun score publié)"))
    else:
        over = sorted(((svc, v) for svc, v in scores if threshold is not None and not math.isnan(v) and v >= threshold),
                      key=lambda item: -item[1])
        blind = [labels.get("source", "?") for labels, v in m.all("anomaly_detector_source_up") if v == 0]
        valid = [v for _, v in scores if not math.isnan(v)]
        if over:
            svc, value = over[0]
            items.append(comp("anomaly-detector", "Détecteur ML", ml_role, DEGRADED,
                              f"anomalie détectée : {svc} (score {fmt_num(value)} ≥ {fmt_num(threshold)})"))
        elif blind:
            items.append(comp("anomaly-detector", "Détecteur ML", ml_role, DEGRADED,
                              "aveugle : source " + ", ".join(blind) + " injoignable"))
        elif not valid:
            items.append(comp("anomaly-detector", "Détecteur ML", ml_role, UNKNOWN, "pas encore de score"))
        else:
            seuil = f" < seuil {fmt_num(threshold)}" if threshold is not None else ""
            items.append(comp("anomaly-detector", "Détecteur ML", ml_role, OK,
                              f"scores au repos (max {fmt_num(max(valid))}{seuil})"))

    # Moteur de remédiation
    engine_role = "décision → action → vérification"
    if not reach.get("engine") or state is None:
        items.append(comp("remediation-engine", "Moteur de remédiation", engine_role, DOWN, "API d'état injoignable"))
    else:
        working = [i for i in state.get("open_incidents") or [] if i.get("state") in ("acting", "verifying", "failed")]
        bad = sorted(k for k, v in deps.items() if v is False and k != "restore_bridge")
        opened = len(state.get("open_incidents") or [])
        if working:
            items.append(comp("remediation-engine", "Moteur de remédiation", engine_role, ACTIVE,
                              f"en action : {working[0].get('alertname')} ({working[0].get('service') or '—'})"))
        elif bad:
            items.append(comp("remediation-engine", "Moteur de remédiation", engine_role, DEGRADED,
                              "dépendance en défaut : " + ", ".join(bad)))
        else:
            suffix = f" · {opened} incident{'s' if opened > 1 else ''} ouvert{'s' if opened > 1 else ''}" if opened else ""
            items.append(comp("remediation-engine", "Moteur de remédiation", engine_role, OK,
                              "à l'écoute d'Alertmanager" + suffix))

    # Pont de restauration (runner de l'hôte)
    bridge_role = "resilience-pg-restore (hôte)"
    bridge = (state or {}).get("bridge")
    if state is None or bridge is None:
        items.append(comp("restore-bridge", "Pont de restauration", bridge_role, UNKNOWN, "état du moteur indisponible"))
    elif not bridge.get("configured"):
        items.append(comp("restore-bridge", "Pont de restauration", bridge_role, UNKNOWN, "non configuré"))
    elif restoring:
        items.append(comp("restore-bridge", "Pont de restauration", bridge_role, ACTIVE, "restauration en cours"))
    elif bridge.get("available"):
        age = bridge.get("heartbeat_age_s")
        beat = f" · signe de vie il y a {age:.0f} s" if isinstance(age, (int, float)) else ""
        items.append(comp("restore-bridge", "Pont de restauration", bridge_role, OK,
                          f"runner {bridge.get('runner') or 'hôte'} prêt{beat}"))
    else:
        age = bridge.get("heartbeat_age_s")
        when = f" (dernier signe il y a {age / 60:.0f} min)" if isinstance(age, (int, float)) else ""
        items.append(comp("restore-bridge", "Pont de restauration", bridge_role, DEGRADED,
                          f"runner absent{when} : une corruption serait escaladée"))
    return items


def integrity(result: list | None, now: float) -> dict:
    # Cette méthode permet de résumer le contrôle d'intégrité du registre (dernier résultat et son âge).
    m = Metrics(result)
    value = m.get("payment_ledger_integrity_ok")
    last = m.get("payment_ledger_integrity_last_check_timestamp")
    return {"ok": None if value is None else value >= 1,
            "last_check_age_s": round(now - last, 1) if last else None}


def anomaly(result: list | None) -> dict:
    # Cette méthode permet de lister les scores d'anomalie par service et le seuil du modèle.
    m = Metrics(result)
    scores = [{"service": labels.get("service", "?"), "score": None if math.isnan(v) else round(v, 3)}
              for labels, v in m.all("anomaly_score")]
    return {"threshold": m.get("anomaly_threshold"), "scores": sorted(scores, key=lambda s: s["service"])}


# ─────────────────────────────── bandeau d'état global ───────────────────────────────

FOLLOW_UP_WINDOW_S = 600


def follow_up_of(incident: dict, others: list[dict]) -> str | None:
    # Cette méthode permet de reconnaître un incident « rattaché » : une autre alerte de la même panne (souvent
    # AnomalyDetected après ServiceDown) que le moteur a seulement vérifiée, sans action propre, parce qu'un incident
    # ouvert peu avant avait déjà agi sur le même service. Il ne doit pas voler la chronologie de l'incident principal.
    # Un rattaché qui tourne mal (échec, escalade) n'en est plus un : il reste affiché.
    if incident.get("last_action") or not is_business(incident):
        return None
    if incident.get("state") not in ("verifying", "recovered"):
        return None
    if not incident.get("open") and incident.get("outcome") != "recovered":
        return None
    decision = incident.get("decision") or {}
    created = parse_ts(incident.get("created_at"))
    if created is None or decision.get("kind") not in ("verify", "act"):
        return None
    service, chain = incident.get("service"), set(decision.get("chain") or [])
    for other in others:
        action = other.get("last_action") or {}
        if other.get("id") == incident.get("id") or action.get("result") != "success":
            continue
        started = parse_ts(other.get("created_at"))
        if started is None or not 0 <= created - started <= FOLLOW_UP_WINDOW_S:
            continue
        if service and (other.get("service") == service or action.get("target") == service) or action.get("target") in chain:
            return other.get("id")
    return None


def focus_incident(state: dict | None) -> dict | None:
    # Cette méthode permet de choisir l'incident à raconter : l'incident métier ouvert le plus actif, sinon le dernier
    # incident métier clos (puis, à défaut, le dernier incident tout court) ; les incidents rattachés sont écartés.
    if not state:
        return None
    everything = (state.get("open_incidents") or []) + (state.get("recent_incidents") or [])
    opened = [i for i in state.get("open_incidents") or [] if is_business(i) and not follow_up_of(i, everything)]
    if opened:
        return sorted(opened, key=lambda i: (STATE_PRIORITY.get(i.get("state"), 9),
                                             -(parse_ts(i.get("created_at")) or 0)))[0]
    recent = state.get("recent_incidents") or []
    return next((i for i in recent if is_business(i) and not follow_up_of(i, everything)), recent[0] if recent else None)


def decision_label(decision: dict | None, nature: str | None = None) -> str:
    # Cette méthode permet d'écrire la décision en clair : nature de la réponse, puis action et cible.
    decision = decision or {}
    kind, action = decision.get("kind"), decision.get("action")
    target = decision.get("target") or decision.get("service") or "?"
    if kind == "act" and action == "restart":
        what = f"redémarrage de {target}"
    elif kind == "act" and action == "block_ip":
        what = f"blocage de {target} au WAF"
    elif kind == "act" and action == "restore_db":
        what = "restauration de la base (dernière sauvegarde saine)"
    elif kind == "verify":
        what = "vérification seule (chaîne saine)"
    elif kind == "wait":
        what = "attente d'un maillon en cours de démarrage"
    elif kind == "observe":
        what = "observation avant toute action"
    elif kind == "escalate":
        what = "escalade à l'opérateur"
    else:
        what = "en cours d'analyse"
    nature_label = NATURE_LABELS.get(decision.get("nature") or nature or "", "")
    return f"{nature_label} · {what}" if nature_label else what


def current_step(incident: dict, detail: dict | None) -> tuple[str, str]:
    # Cette méthode permet de décrire l'étape en cours d'un incident (clé d'icône, texte) à partir de son état et, si
    # elle est connue, de sa chronologie (contrôle de vérification en cours, attente d'un démarrage, nouvelle tentative).
    state = incident.get("state")
    timeline = (detail or {}).get("timeline") or []
    last = timeline[-1]["event"] if timeline and isinstance(timeline[-1], dict) else ""
    decision = incident.get("decision") or {}
    if state == "detected":
        return "detected", f"Alerte {incident.get('alertname')} reçue par le moteur"
    if state == "decided":
        if last == "wait:starting":
            return "acting", "Attente : un maillon redémarre, nouveau diagnostic ensuite"
        return "decided", "Décision : " + decision_label(decision, incident.get("nature"))
    if state == "observing":
        return "observing", "Observation : " + clip(decision.get("reason") or "alerte surveillée sans action", 90)
    if state == "acting":
        if last == "restore:requested":
            return "acting", "Action : restauration de la base par le pont de l'hôte"
        if last == "hold:restore_in_progress":
            return "acting", "Action suspendue : restauration de la base en cours"
        return "acting", "Action : " + decision_label(decision, incident.get("nature")).split(" · ")[-1]
    if state == "verifying":
        checks = decision.get("checks") or []
        done = {e["event"].split(":", 1)[1] for e in timeline
                if isinstance(e, dict) and str(e.get("event", "")).startswith("verification:")}
        pending = next((c for c in checks if c not in done), None)
        return "verifying", "Vérification : " + CHECK_LABELS.get(pending or "", "contrôles terminés")
    if state == "failed":
        return "failed", "Tentative en échec : nouvelle tentative sous anti-boucle"
    if state == "escalated":
        message = (incident.get("escalation") or {}).get("message") or "intervention requise"
        return "escalated", "Escaladé à l'opérateur : " + clip(message, 90)
    if state == "recovered":
        return "recovered", "Rétabli et vérifié : conteneurs, sondes et transaction témoin OK"
    return "detected", f"Incident {incident.get('alertname')}"


def business_alerts(prom_alerts: list | None, am_alerts: list | None) -> list[dict]:
    # Cette méthode permet de lister les alertes métier en attente ou actives (avant que le moteur ne les traite).
    found = []
    for alert in prom_alerts or []:
        labels = alert.get("labels") or {}
        if labels.get("alertname") not in INFRA_ALERTS:
            found.append({"name": labels.get("alertname"), "state": alert.get("state"),
                          "since": parse_ts(alert.get("activeAt"))})
    for alert in am_alerts or []:
        labels = alert.get("labels") or {}
        if labels.get("alertname") not in INFRA_ALERTS:
            found.append({"name": labels.get("alertname"), "state": "firing", "since": parse_ts(alert.get("startsAt"))})
    return found


class Episode:
    """Mémoire de la première anomalie observée (avant même l'alerte), pour dater l'incident depuis son début réel."""

    def __init__(self):
        # Cette méthode permet de partir d'un état « rien d'anormal ».
        self.started_at: float | None = None

    def observe(self, abnormal: bool, now: float, earliest: float | None = None) -> float | None:
        # Cette méthode permet de mémoriser le début de l'épisode (ou de l'oublier quand tout est revenu à la normale).
        if abnormal:
            start = min(x for x in (now, earliest, self.started_at) if x is not None)
            self.started_at = start
        return self.started_at

    def reset(self) -> None:
        # Cette méthode permet d'oublier l'épisode terminé.
        self.started_at = None


def global_status(state: dict | None, detail: dict | None, comps: list[dict], prom_alerts: list | None,
                  am_alerts: list | None, reach: dict[str, bool], episode: Episode, now: float,
                  restored_window_s: float) -> dict:
    # Cette méthode permet de calculer le bandeau : phase, étape en cours, début de l'épisode (pour le chronomètre) ou
    # durée figée d'un rétablissement, incident concerné et remarques (source injoignable, incidents d'exploitation).
    notes = []
    if not reach.get("engine"):
        notes.append("moteur de remédiation injoignable : la reprise n'est pas suivie")
    if not reach.get("prometheus"):
        notes.append("Prometheus injoignable : composants non mesurés")
    if state:
        infra = [i for i in state.get("open_incidents") or [] if not is_business(i)]
        if infra:
            notes.append(f"{len(infra)} incident{'s' if len(infra) > 1 else ''} d'exploitation ouvert"
                         f"{'s' if len(infra) > 1 else ''} ({', '.join(sorted({i.get('alertname', '?') for i in infra}))})")
    down = [c for c in comps if c["id"] in BUSINESS_COMPONENTS and c["state"] == DOWN]
    ml = next((c for c in comps if c["id"] == "anomaly-detector" and c["reason"].startswith("anomalie")), None)
    alerts = business_alerts(prom_alerts, am_alerts)
    abnormal = bool(down or ml or alerts)
    focus = focus_incident(state)
    everything = ((state or {}).get("open_incidents") or []) + ((state or {}).get("recent_incidents") or [])
    opened = [i for i in (state or {}).get("open_incidents") or [] if is_business(i) and not follow_up_of(i, everything)]
    base = {"incident_id": None, "alertname": None, "service": None, "nature": None, "decision": None,
            "since": None, "duration_s": None, "reaction_s": None, "escalated": False,
            "open_incidents": len(opened), "notes": notes}

    def describe(incident: dict) -> dict:
        # Cette méthode permet de recopier l'identité de l'incident suivi dans le bandeau.
        return {"incident_id": incident.get("id"), "alertname": incident.get("alertname"),
                "service": incident.get("service"), "nature": incident.get("nature"),
                "decision": decision_label(incident.get("decision"), incident.get("nature"))
                if incident.get("decision") else None}

    def start_of(incident: dict) -> float | None:
        # Cette méthode permet de dater le début de l'incident : première anomalie observée si elle le précède de peu,
        # sinon le déclenchement de l'alerte, sinon sa réception par le moteur.
        created = parse_ts(incident.get("created_at"))
        candidates = [parse_ts(incident.get("alert_started_at")), created]
        if episode.started_at is not None and created is not None and created - 600 <= episode.started_at <= created:
            candidates.append(episode.started_at)
        values = [c for c in candidates if c is not None]
        return min(values) if values else None

    if focus and focus.get("open") and is_business(focus) and focus.get("state") != "recovered":
        key, text = current_step(focus, detail if (detail or {}).get("id") == focus.get("id") else None)
        phase = "remediation" if key in ("acting", "verifying", "failed") else "incident"
        start = start_of(focus)
        episode.observe(True, now, start)
        return {**base, **describe(focus), "phase": phase, "step_key": key, "step": text, "since": iso(start),
                "escalated": focus.get("state") == "escalated"}

    if focus and focus.get("open") and is_business(focus):
        start = start_of(focus)
        recovered = parse_ts(focus.get("recovered_at"))
        return {**base, **describe(focus), "phase": "restored", "step_key": "recovered",
                "step": "Rétabli et vérifié — en attente de la retombée des alertes",
                "since": iso(start), "duration_s": round(recovered - start, 1) if recovered and start else None,
                "reaction_s": focus.get("duration_s")}

    if abnormal and (reach.get("prometheus") or reach.get("alertmanager")):
        pending = [a for a in alerts if a["state"] == "pending"]
        firing = [a for a in alerts if a["state"] == "firing"]
        earliest = min((a["since"] for a in alerts if a["since"]), default=None)
        start = episode.observe(True, now, earliest)
        if firing:
            names = ", ".join(sorted({a["name"] for a in firing}))
            text = f"Alerte {names} déclenchée : transmission au moteur de remédiation"
            key = "alert"
        elif pending:
            names = ", ".join(sorted({a["name"] for a in pending}))
            text = f"Anomalie détectée : {names} en cours de confirmation"
            key = "anomaly"
        elif down:
            text = "Anomalie détectée par les sondes : " + ", ".join(c["label"] for c in down) + " en échec"
            key = "anomaly"
        else:
            text = "Anomalie détectée par le modèle ML : " + ml["reason"].split(" : ", 1)[-1]
            key = "anomaly"
        return {**base, "phase": "incident", "step_key": key, "step": text, "since": iso(start)}

    if focus and not focus.get("open") and is_business(focus) and focus.get("outcome") == "recovered":
        closed = parse_ts(focus.get("closed_at"))
        if closed is not None and now - closed <= restored_window_s:
            start = start_of(focus)
            recovered = parse_ts(focus.get("recovered_at"))
            return {**base, **describe(focus), "phase": "restored", "step_key": "closed",
                    "step": "Service rétabli et vérifié · incident clos",
                    "since": iso(start), "duration_s": round(recovered - start, 1) if recovered and start else None,
                    "reaction_s": focus.get("duration_s")}

    episode.reset()
    if not reach.get("engine") and not reach.get("prometheus"):
        return {**base, "phase": "unknown", "step_key": "unknown", "step": "Sources de supervision indisponibles"}
    return {**base, "phase": "operational", "step_key": "operational",
            "step": "Tous les parcours clients répondent · aucune alerte métier"}


# ─────────────────────────────── alertes ───────────────────────────────

def _alert_key(labels: dict) -> tuple:
    # Cette méthode permet de reconnaître la même alerte vue par Prometheus et par Alertmanager (label externe ôté).
    return tuple(sorted((k, v) for k, v in labels.items() if k != "platform"))


def shape_alerts(am_alerts: list | None, prom_alerts: list | None, limit: int = 30) -> list[dict]:
    # Cette méthode permet de fusionner les alertes d'Alertmanager (Prometheus et SOC Loki) et celles encore en attente
    # de confirmation dans Prometheus, les plus graves et les plus récentes d'abord.
    items, seen = [], set()
    for alert in am_alerts or []:
        if not isinstance(alert, dict):
            continue
        labels = {str(k): str(v) for k, v in (alert.get("labels") or {}).items()}
        name = labels.get("alertname", "?")
        seen.add(_alert_key(labels))
        status = (alert.get("status") or {}).get("state")
        source = "loki" if name in SOC_ALERTS or ("platform" not in labels and "/graph" not in
                                                  str(alert.get("generatorURL") or "")) else "prometheus"
        items.append(_alert(labels, alert.get("annotations") or {}, "firing", alert.get("startsAt"), source,
                            silenced=status == "suppressed"))
    for alert in prom_alerts or []:
        if not isinstance(alert, dict):
            continue
        labels = {str(k): str(v) for k, v in (alert.get("labels") or {}).items()}
        if _alert_key(labels) in seen:
            continue
        state = "pending" if alert.get("state") == "pending" else "firing"
        items.append(_alert(labels, alert.get("annotations") or {}, state, alert.get("activeAt"), "prometheus"))
    rank = {"critical": 0, "warning": 1}
    items.sort(key=lambda a: (a["state"] != "firing", rank.get(a["severity"], 2), -(parse_ts(a["starts_at"]) or 0)))
    return items[:limit]


def _alert(labels: dict, annotations: dict, state: str, starts_at: Any, source: str, silenced: bool = False) -> dict:
    # Cette méthode permet de ne garder que les champs utiles et bornés d'une alerte.
    return {"name": clip(labels.get("alertname", "?"), 60), "severity": clip(labels.get("severity", ""), 20),
            "domain": clip(labels.get("domain", ""), 20), "service": clip(labels.get("service", ""), 40),
            "client_ip": clip(labels["client_ip"], 45) if labels.get("client_ip") else None,
            "summary": clip(annotations.get("summary") or annotations.get("description") or "", 200),
            "starts_at": starts_at if isinstance(starts_at, str) else None, "state": state, "source": source,
            "silenced": silenced, "business": labels.get("alertname") not in INFRA_ALERTS}


# ─────────────────────────────── fil d'événements ───────────────────────────────

EVENT_FIELDS = ("incident_id", "alertname", "nature", "state", "target_service", "client_ip", "action", "target",
                "result", "check", "reason", "outcome", "dominant_feature", "anomaly_score", "duration_s",
                "since_alert_s", "method", "uri", "status", "ip", "error", "explanation", "source")
ATTACK_EVENTS = frozenset({"auth_failure", "waf_remediation_block"})
EVENT_TYPE = re.compile(r"waf_remediation_block|remediation_[a-z_]+|anomaly_detected|anomaly_cleared|auth_failure"
                        r"|integrity_violation|dependency_failure")


def _parse_streams(result: list | None) -> list[dict]:
    # Cette méthode permet de convertir les flux Loki en événements (ligne JSON, champs en liste blanche).
    import json

    events = []
    for stream in result or []:
        if not isinstance(stream, dict):
            continue
        labels = stream.get("stream") or {}
        for value in stream.get("values") or []:
            try:
                ts_ns, line = int(value[0]), value[1]
            except (TypeError, ValueError, IndexError):
                continue
            try:
                body = json.loads(line)
                if not isinstance(body, dict):
                    body = {}
            except ValueError:
                body = {}
            event_type = str(body.get("event_type") or labels.get("event_type") or "")
            if not EVENT_TYPE.fullmatch(event_type) or event_type in ("remediation_webhook", "remediation_duplicate"):
                continue
            plan = body.get("plan") if isinstance(body.get("plan"), dict) else {}
            merged = {**{k: plan.get(k) for k in ("reason", "action", "target") if plan.get(k) is not None}, **body}
            event = {"ts": iso(ts_ns / 1e9), "event_type": event_type,
                     "service": clip(body.get("service") or labels.get("service") or "", 40),
                     "level": clip(body.get("level") or labels.get("level") or "info", 10), "count": 1}
            for key in EVENT_FIELDS:
                item = merged.get(key)
                if isinstance(item, (str, int, float, bool)) and item != "":
                    event[key] = clip(item, 120) if isinstance(item, str) else item
            events.append((ts_ns, event))
    return events


def shape_events(story: list | None, attack: list | None, limit: int) -> list[dict]:
    # Cette méthode permet de fusionner le récit et les attaques, du plus récent au plus ancien, en regroupant les
    # événements d'attaque consécutifs de même type et de même IP (« 37 échecs depuis 172.25.0.3 »).
    merged = sorted(_parse_streams(story) + _parse_streams(attack), key=lambda item: -item[0])
    out: list[dict] = []
    for _, event in merged:
        previous = out[-1] if out else None
        if (previous and event["event_type"] in ATTACK_EVENTS and previous["event_type"] == event["event_type"]
                and previous.get("client_ip") == event.get("client_ip") and previous["service"] == event["service"]):
            previous["count"] += 1
            previous["first_ts"] = event["ts"]
            continue
        if len(out) >= limit:
            break
        out.append(event)
    return out


# ─────────────────────────────── blocages et incidents ───────────────────────────────

def shape_blocks(state: dict | None, now: float) -> list[dict]:
    # Cette méthode permet de lister les IP bloquées avec leur échéance, la durée totale du blocage et l'incident.
    if not state:
        return []
    incidents = {i.get("id"): i for i in (state.get("open_incidents") or []) + (state.get("recent_incidents") or [])}
    blocks = []
    for entry in state.get("blocked_ips") or []:
        if not isinstance(entry, dict):
            continue
        expires = parse_ts(entry.get("expires_at"))
        action = (incidents.get(entry.get("incident_id")) or {}).get("last_action") or {}
        same = action.get("action") == "block_ip" and action.get("target") == entry.get("ip")
        blocks.append({
            "ip": clip(entry.get("ip", "?"), 45), "expires_at": entry.get("expires_at"),
            "remaining_s": round(max(0.0, expires - now), 1) if expires else None,
            "ttl_s": action.get("ttl_s") if same else None, "blocked_at": action.get("at") if same else None,
            "reason": clip(entry.get("reason") or "", 120), "incident_id": entry.get("incident_id")})
    return sorted(blocks, key=lambda b: b["remaining_s"] if b["remaining_s"] is not None else math.inf)


SENSITIVE = re.compile(r"pass|secret|token|authorization|cookie|credential", re.I)
MAX_TIMELINE = 200


def redact(value: Any, depth: int = 0) -> Any:
    # Cette méthode permet de recopier un document du moteur en retirant toute clé sensible (défense en profondeur :
    # le moteur n'en publie pas) et en bornant la profondeur.
    if depth > 8:
        return None
    if isinstance(value, dict):
        return {k: redact(v, depth + 1) for k, v in value.items() if not SENSITIVE.search(str(k))}
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value]
    return value


def shape_incident(incident: dict) -> dict:
    # Cette méthode permet de relayer un incident complet (chronologie bornée aux 200 dernières entrées).
    clean = redact(incident)
    if isinstance(clean.get("timeline"), list) and len(clean["timeline"]) > MAX_TIMELINE:
        clean["timeline"] = clean["timeline"][-MAX_TIMELINE:]
    return clean


SUMMARY_FIELDS = ("id", "alertname", "rule", "nature", "domain", "severity", "service", "state", "open", "outcome",
                  "attempts", "created_at", "closed_at", "recovered_at", "alert_started_at", "duration_s", "alerts",
                  "decision", "escalation", "last_action")


def shape_summary(incident: dict, others: list[dict] | None = None) -> dict:
    # Cette méthode permet de résumer un incident pour l'historique (champs utiles seulement), avec l'incident principal
    # auquel il est rattaché le cas échéant.
    summary = redact({k: incident.get(k) for k in SUMMARY_FIELDS})
    summary["follow_up_of"] = follow_up_of(incident, others or [])
    return summary
