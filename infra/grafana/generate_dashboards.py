"""Génère les tableaux de bord Grafana provisionnés (infra/grafana/dashboards/*.json).

Usage : python infra/grafana/generate_dashboards.py
Les JSON produits sont versionnés ; Grafana les recharge seul (provisioning), sans redémarrage.
"""

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dashboards"
PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}

UP_DOWN = {
    "defaults": {
        "mappings": [{"type": "value", "options": {"0": {"text": "KO", "color": "red"}, "1": {"text": "OK", "color": "green"}}}],
        "thresholds": {"mode": "absolute", "steps": [{"color": "red", "value": None}, {"color": "green", "value": 1}]},
    },
    "overrides": [],
}
STAT = {"colorMode": "background", "graphMode": "none", "reduceOptions": {"calcs": ["lastNotNull"]}, "textMode": "value_and_name"}
LOGS = {"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending"}
WAF_AUDIT = '{service="waf"} |= "\\"transaction\\""'
# Requêtes interrompues par le WAF (is_interrupted) : les 403 renvoyés par les API, journalisés aussi, sont écartés
# (même filtre que la règle SOC WafAttackBlocked).
WAF_BLOCKED = WAF_AUDIT + (' | json client_ip="transaction.client_ip", code="transaction.response.http_code",'
                           ' interrupted="transaction.is_interrupted" | __error__="" | code="403" | interrupted="true"')

# Moteur de remédiation (services/remediation-engine) : métriques remediation_*, journaux event_type=remediation_* et
# refus du WAF pour une IP bloquée par le moteur (event_type=waf_remediation_block, avant ModSecurity).
ENGINE_DEPENDENCIES = {"docker_proxy": "proxy Docker", "prometheus": "Prometheus", "loki": "Loki",
                       "waf_blocklist": "liste de blocage WAF", "restore_bridge": "pont de restauration", "state_store": "fichier d'état"}
REMEDIATION_BLOCKS = '{service="waf", event_type="waf_remediation_block"}'
# Les notifications répétées d'Alertmanager (remediation_webhook, remediation_duplicate) sont écartées : elles ne
# changent rien à l'incident. `| json` aplatit les objets imbriqués : le motif d'une décision devient plan_reason.
REMEDIATION_LOG = (
    '{service=~"remediation-engine|waf", event_type=~"remediation_.+|waf_remediation_block", event_type!~"remediation_(webhook|duplicate)"}'
    ' | json | line_format `'
    '{{ if eq .event_type "waf_remediation_block" }}waf_remediation_block · requête de {{ .client_ip }} refusée (403, IP bloquée)'
    ' — {{ .method }} {{ .uri }}{{ else }}{{ .event_type }}{{ with .incident_id }} · {{ . }}{{ end }}'
    '{{ with .alertname }} · {{ . }}{{ end }}{{ with .nature }} ({{ . }}){{ end }}{{ with .target_service }} → {{ . }}{{ end }}'
    '{{ with .action }} · {{ . }}{{ end }}{{ with .check }} · contrôle {{ . }}{{ end }}{{ with .result }} : {{ . }}{{ end }}'
    '{{ with .client_ip }} · IP {{ . }}{{ end }}{{ with .ip }} · IP {{ . }}{{ end }}{{ with .reason }} · {{ . }}{{ end }}'
    '{{ with .explanation }} — {{ . }}{{ end }}{{ with .plan_reason }} — {{ . }}{{ end }}{{ with .outcome }} · issue : {{ . }}{{ end }}'
    '{{ with .error }} — erreur : {{ . }}{{ end }}{{ with .duration_s }} · {{ . }} s{{ end }}'
    '{{ with .since_alert_s }} ({{ . }} s depuis l\'alerte){{ end }}{{ end }}`'
)
# Échecs : action en échec ou refusée, vérification en échec, escalade (le moteur les journalise en error / warning).
REMEDIATION_FAILURES = (
    '{service="remediation-engine", event_type=~"remediation_(escalated|action|action_failed|verification)", level=~"error|warning"}'
    ' | json | line_format `{{ .alertname }} → {{ .target_service }} ({{ .incident_id }}){{ with .reason }} · {{ . }}{{ end }}'
    '{{ with .explanation }} — {{ . }}{{ end }}{{ with .action }} · {{ . }}{{ end }}{{ with .check }} · contrôle {{ . }}{{ end }}'
    '{{ with .result }} : {{ . }}{{ end }}{{ with .error }} — {{ . }}{{ end }}`'
)
REMEDIATION_RECOVERED = (
    '{service="remediation-engine", event_type="remediation_recovered"}'
    ' | json | line_format `{{ .alertname }} → {{ .target_service }} rétabli et vérifié {{ .duration_s }} s après la détection'
    '{{ with .since_alert_s }} ({{ . }} s après le déclenchement de l\'alerte){{ end }} · {{ .nature }} · {{ .incident_id }}`'
)


class Dashboard:
    def __init__(self, uid: str, title: str, tags: list[str]):
        # Cette méthode permet d'initialiser un tableau de bord vide avec son identifiant stable et ses tags.
        self.uid, self.title, self.tags = uid, title, tags
        self.panels: list[dict] = []
        self.annotations: list[dict] = []
        self.y = 0

    def row(self, title: str) -> None:
        # Cette méthode permet d'ajouter une ligne de titre sur toute la largeur, sous les panneaux existants.
        self._add({"type": "row", "title": title, "collapsed": False, "panels": []}, 0, 24, 1)
        self.y += 1

    def panel(self, kind: str, title: str, x: int, w: int, h: int, datasource: dict, queries: list, **extra) -> None:
        # Cette méthode permet d'ajouter un panneau à la ligne courante ; chaque requête est un tuple (expr, légende[, options]).
        targets = []
        for index, query in enumerate(queries):
            expr, legend, *options = query
            target = {"refId": chr(65 + index), "datasource": datasource, "expr": expr, "legendFormat": legend}
            if datasource is LOKI and kind != "logs":
                target["queryType"] = "range"
            target.update(options[0] if options else {})
            targets.append(target)
        self._add({"type": kind, "title": title, "datasource": datasource, "targets": targets, **extra}, x, w, h)

    def annotation(self, name: str, datasource: dict, expr: str, color: str, **options) -> None:
        # Cette méthode permet d'ajouter une annotation à tous les graphiques temporels du tableau de bord ; la requête est
        # écrite à la fois à l'ancien emplacement (expr) et dans target, que Grafana lit selon la source de données.
        target = {"refId": f"Anno{len(self.annotations) + 1}", "expr": expr}
        self.annotations.append({"name": name, "datasource": datasource, "enable": True, "iconColor": color, "expr": expr,
                                 "target": target, **options})

    def next_line(self, h: int) -> None:
        # Cette méthode permet de passer à la ligne suivante de la grille après une rangée de panneaux de hauteur h.
        self.y += h

    def _add(self, panel: dict, x: int, w: int, h: int) -> None:
        # Cette méthode permet de positionner un panneau dans la grille et de lui attribuer un identifiant unique.
        panel["id"] = len(self.panels) + 1
        panel["gridPos"] = {"x": x, "y": self.y, "w": w, "h": h}
        self.panels.append(panel)

    def write(self) -> None:
        # Cette méthode permet de sérialiser le tableau de bord au format attendu par le provisioning Grafana.
        model = {
            "uid": self.uid, "title": self.title, "tags": self.tags, "timezone": "browser", "refresh": "5s",
            "schemaVersion": 41, "editable": False, "time": {"from": "now-30m", "to": "now"}, "panels": self.panels,
            "links": [{"type": "dashboards", "tags": ["resilience-alpha"], "asDropdown": False, "title": "Tableaux de bord"}],
        }
        if self.annotations:
            model["annotations"] = {"list": self.annotations}
        path = OUT / f"{self.uid.removeprefix('ra-')}.json"
        path.write_text(json.dumps(model, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"  + {path.relative_to(OUT.parent.parent.parent)}")


def red_above(value: float, unit: str | None = None) -> dict:
    # Cette méthode permet de construire des seuils « vert puis rouge à partir de value » pour un compteur, avec son unité.
    steps = [{"color": "green", "value": None}, {"color": "red", "value": value}]
    defaults = {"thresholds": {"mode": "absolute", "steps": steps}}
    if unit:
        defaults["unit"] = unit
    return {"defaults": defaults, "overrides": []}


def steps(*colors_and_values) -> dict:
    # Cette méthode permet de construire des seuils absolus à partir de (couleur de base, valeur, couleur, valeur, couleur…).
    base, *rest = colors_and_values
    pairs = [{"color": rest[i + 1], "value": rest[i]} for i in range(0, len(rest), 2)]
    return {"mode": "absolute", "steps": [{"color": base, "value": None}, *pairs]}


def colored(pattern: str, color: str, **properties) -> dict:
    # Cette méthode permet de forcer la couleur (et d'autres propriétés) des séries dont le nom correspond à une expression.
    props = [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}]
    props += [{"id": key, "value": value} for key, value in properties.items()]
    return {"matcher": {"id": "byRegexp", "options": pattern}, "properties": props}


def thresholds_for(pattern: str, *colors_and_values) -> dict:
    # Cette méthode permet d'appliquer des seuils propres aux séries dont le nom correspond à une expression.
    return {"matcher": {"id": "byRegexp", "options": pattern}, "properties": [{"id": "thresholds", "value": steps(*colors_and_values)}]}


def remediation(d: Dashboard) -> None:
    # Cette méthode permet de décrire la rangée du moteur de remédiation : incidents, actions, escalades, vérifications,
    # durée de reprise, IP bloquées, dépendances, entrées du webhook, journal ; et les annotations d'incident.
    d.row("Remédiation automatique (moteur : alerte → décision → action → vérification → rétabli ou escalade)")
    period = {**STAT, "textMode": "value"}
    bars = {"displayMode": "basic", "orientation": "horizontal", "showUnfilled": True, "sizing": "manual", "minVizHeight": 22,
            "maxVizHeight": 32, "namePlacement": "left", "valueMode": "color", "reduceOptions": {"calcs": ["lastNotNull"]}}
    d.panel("stat", "Incidents ouverts", 0, 3, 4, PROM, [("remediation_incidents_open", "")],
            description="Incidents du moteur non clos (en cours de traitement, rétablis en attente de la retombée des alertes, "
                        "escaladés ou observés). Orange dès qu'un incident est ouvert : détail dans le journal ci-dessous ou GET /api/incidents.",
            fieldConfig={"defaults": {"thresholds": steps("green", 1, "orange")}, "overrides": []}, options=period)
    d.panel("stat", "IP bloquées (WAF)", 3, 3, 4, PROM, [("remediation_blocked_ips", "")],
            description="IP actuellement refusées par le WAF sur décision du moteur (TTL 300 s par défaut, levée automatique). "
                        "Jauge mise à jour dès le blocage puis par la boucle de fond du moteur : une levée y apparaît au plus une "
                        "période (15 s) plus tard, plus l'intervalle de scrape. Détail : journaux remediation_waf_block / remediation_unblocked.",
            fieldConfig={"defaults": {"thresholds": steps("green", 1, "orange")}, "overrides": []}, options=period)
    d.panel("stat", "Actions en échec", 6, 3, 4, PROM,
            [('round(sum(increase(remediation_actions_total{result=~"failure|refused"}[$__range]))) or vector(0)', "")],
            description="Actions du moteur en échec ou refusées (anti-boucle, cible non autorisée) sur la période affichée. "
                        "Rouge dès la première : l'alerte RemediationFailed se déclenche, intervention humaine requise.",
            fieldConfig=red_above(1), options=period)
    d.panel("stat", "Escalades à traiter", 9, 3, 4, PROM,
            [('round(sum(increase(remediation_escalations_total{reason!="policy"}[$__range]))) or vector(0)', "")],
            description="Incidents escaladés vers l'opérateur sur la période, hors escalades « policy » prévues par conception "
                        "(hôte, sauvegardes). Rouge dès la première (alerte RemediationFailed). Motifs : panneau « Escalades par motif ».",
            fieldConfig=red_above(1), options=period)
    names = [{"matcher": {"id": "byName", "options": key}, "properties": [{"id": "displayName", "value": label}]}
             for key, label in ENGINE_DEPENDENCIES.items()]
    d.panel("stat", "Moteur et dépendances", 12, 12, 4, PROM,
            [('up{job="remediation-engine"}', "moteur"), ("remediation_dependency_up", "{{dependency}}")],
            description="Moteur scrapé par Prometheus, puis ce que sa boucle de fond (15 s) joint : proxy Docker (redémarrages), "
                        "Prometheus (sondes), Loki (attribution d'IP), liste de blocage du WAF, pont de restauration (runner de l'hôte : "
                        "KO en local tant que scripts/remediation_bridge_dev.py run ne tourne pas) et fichier d'état. KO = réponse dégradée.",
            fieldConfig={**UP_DOWN, "overrides": names}, options=STAT)
    d.next_line(4)
    d.panel("bargauge", "Actions sur la période, par type et résultat", 0, 9, 7, PROM,
            [("round(sum by (action, target, result) (increase(remediation_actions_total[$__range]))) > 0",
              "{{action}} {{target}} → {{result}}", {"instant": True, "range": False})],
            description="Actions exécutées sur la période affichée, avec leur cible : restart / start d'un service Compose "
                        "(disponibilité), block_ip au waf / restore_db de paydb (compromission ; l'IP bloquée n'est jamais un label). "
                        "Vert : réussie ; rouge : en échec ; orange : refusée (anti-boucle, cible hors liste).",
            fieldConfig={"defaults": {"min": 0, "decimals": 0, "noValue": "aucune action sur la période", "thresholds": steps("green")},
                         "overrides": [thresholds_for(".*failure$", "green", 1, "red"), thresholds_for(".*refused$", "green", 1, "orange")]},
            options=bars)
    d.panel("bargauge", "Escalades par motif (période)", 9, 8, 7, PROM,
            [("round(sum by (reason) (increase(remediation_escalations_total[$__range]))) > 0", "{{reason}}", {"instant": True, "range": False})],
            description="Incidents rendus à l'opérateur, par motif : attempts_exhausted (anti-boucle), verification_failed, action_failed, "
                        "bridge_unavailable, waf_unavailable, no_offender (attaque sans IP dominante), triage_unknown, container_missing, "
                        "unknown_alert, not_allowed. Orange : policy (escalade prévue par conception, sans alerte RemediationFailed).",
            fieldConfig={"defaults": {"min": 0, "decimals": 0, "noValue": "aucune escalade sur la période",
                                      "thresholds": steps("green", 1, "red")},
                         "overrides": [thresholds_for("^policy$", "green", 1, "orange")]},
            options=bars)
    d.panel("stat", "Vérifications après action (période)", 17, 7, 7, PROM,
            [(f'round(sum(increase(remediation_verification_total{{result="{result}"}}[$__range])))', label, {"instant": True, "range": False})
             for result, label in (("success", "réussies"), ("failure", "en échec"))],
            description="Preuves de rétablissement : conteneurs healthy, sondes de bout en bout, intégrité, puis transaction témoin "
                        "à travers le WAF. Une vérification en échec (rouge) relance une tentative sous anti-boucle, puis escalade.",
            fieldConfig={"defaults": {"decimals": 0, "thresholds": steps("green")},
                         "overrides": [thresholds_for("^en échec$", "green", 1, "red")]},
            options={**STAT, "orientation": "vertical"})
    d.next_line(7)
    # Deux durées, observées seulement pour un incident où le moteur a agi (une vérification seule ne compte pas) :
    # temps propre du moteur, et durée vue depuis l'alerte (ce que montre le Clip Chrono, panne → service vérifié).
    durations = [
        ("Détection → rétablissement vérifié (période)", "remediation_duration_seconds", 20, 40,
         "Temps propre du moteur : du webhook reçu au rétablissement vérifié (transaction témoin comprise). Le webhook arrivant "
         "~40 s après la panne (recette), vert < 20 s : la séquence tient dans la minute du Clip Chrono ; orange < 40 s."),
        ("Alerte → rétablissement vérifié (période)", "remediation_alert_to_recovery_seconds", 30, 60,
         "Du déclenchement de l'alerte (startsAt d'Alertmanager) au rétablissement vérifié : le moteur plus le délai de "
         "notification. L'alerte passant firing ~30 s après la panne (for: 15 s + scrape), vert < 30 s : la séquence tient dans "
         "la minute du Clip Chrono ; orange < 60 s."),
    ]
    instant = {"instant": True, "range": False}
    for index, (title, metric, green, orange, text) in enumerate(durations):
        bucket = f"sum by (nature, le) (increase({metric}_bucket[$__range]))"
        mean = f"sum by (nature) (increase({metric}_sum[$__range])) / sum by (nature) (increase({metric}_count[$__range])) >= 0"
        d.panel("stat", title, index * 6, 6, 8, PROM,
                [(f"histogram_quantile(0.5, {bucket}) >= 0", "p50 {{nature}}", instant),
                 (f"histogram_quantile(0.95, {bucket}) >= 0", "p95 {{nature}}", instant),
                 (mean, "moyenne {{nature}}", instant)],
                description=text + " Par nature : availability (redémarrage) ou compromise (blocage, restauration) ; incidents où "
                            "le moteur a agi seulement. p50 / p95 interpolés dans les seaux (0,5, 1, 2, 5, 10, 20, 30 s…), moyenne exacte.",
                fieldConfig={"defaults": {"unit": "s", "decimals": 1, "noValue": "aucun rétablissement sur la période",
                                          "thresholds": steps("green", green, "orange", orange, "red")}, "overrides": []},
                options={**STAT, "orientation": "horizontal"})
    d.panel("timeseries", "Alertes reçues et refus du webhook (par min)", 12, 6, 8, PROM,
            [("sum by (status) (rate(remediation_alerts_received_total[1m])) * 60", "alertes {{status}}"),
             ("sum(rate(remediation_webhook_rejected_total[1m])) * 60", "refus du webhook")],
            description="Alertes transmises par Alertmanager au webhook POST /alerts (firing, resolved ; notifications répétées "
                        "comprises), et appels refusés (jeton absent ou faux, corps invalide ou trop gros) : un refus peut signaler une "
                        "tentative de fausses alertes (EBIOS S6). Motif et IP source : journal remediation_webhook_rejected.",
            fieldConfig={"defaults": {"min": 0}, "overrides": [colored("^refus du webhook$", "red", **{"custom.lineWidth": 2}),
                                                             colored("^alertes firing$", "orange"), colored("^alertes resolved$", "green")]})
    d.panel("timeseries", "Refus du blocage WAF, par IP (par min)", 18, 6, 8, LOKI,
            [(f'sum by (client_ip) (count_over_time({REMEDIATION_BLOCKS} | json client_ip="client_ip" [1m]))', "{{client_ip}}")],
            description="Requêtes d'une IP bloquée par le moteur, refusées par le WAF avant ModSecurity (403 blocked_by_remediation, "
                        "journal waf_remediation_block). Elles n'atteignent plus les API : c'est ce qui fait retomber les alertes SOC.",
            fieldConfig={"defaults": {"min": 0, "noValue": "aucune requête refusée sur la période",
                                      "custom": {"drawStyle": "bars", "fillOpacity": 60}}, "overrides": []})
    d.next_line(8)
    d.panel("logs", "Journal du moteur de remédiation et refus du blocage WAF", 0, 24, 10, LOKI, [(REMEDIATION_LOG, "")],
            description="Une ligne par événement : remediation_detected, decided (motif de la décision), action, verification, recovered, "
                        "escalated, closed… avec l'incident, l'alerte, la nature et la cible ; plus les refus waf_remediation_block. "
                        "Notifications répétées (webhook, duplicate) écartées. Tous les champs restent visibles en dépliant une ligne.",
            options=LOGS)
    d.next_line(10)
    d.annotation("Incident de remédiation ouvert", PROM, "remediation_incidents_open > 0", "orange", step="10s",
                 titleFormat="Incident de remédiation ouvert", textFormat="", tagKeys="", useValueForTime=False)
    d.annotation("Échec de remédiation ou escalade", LOKI, REMEDIATION_FAILURES, "red",
                 titleFormat="{{event_type}}", textFormat="", tagKeys="nature,target_service")
    d.annotation("Rétabli et vérifié", LOKI, REMEDIATION_RECOVERED, "green",
                 titleFormat="Rétabli et vérifié", textFormat="", tagKeys="nature,target_service")


def service_health() -> Dashboard:
    # Cette méthode permet de décrire le tableau de bord de santé : utilisabilité réelle, trafic, métier, alertes.
    d = Dashboard("ra-service-health", "Resilience-Alpha — Santé du service", ["resilience-alpha"])
    d.row("Le service est-il utilisable ? (sondes de bout en bout à travers le WAF)")
    d.panel("stat", "Parcours client", 0, 12, 4, PROM, [('probe_success{job="blackbox-http"}', "{{service}}")], fieldConfig=UP_DOWN, options=STAT)
    d.panel("stat", "Intégrité du registre", 12, 4, 4, PROM, [("payment_ledger_integrity_ok", "registre")], fieldConfig=UP_DOWN, options=STAT)
    d.panel("stat", "Processus API", 16, 4, 4, PROM, [('up{job=~"auth-service|payment-api"}', "{{service}}")], fieldConfig=UP_DOWN, options=STAT)
    d.panel("stat", "Alertes actives", 20, 4, 4, PROM, [('count(ALERTS{alertstate="firing"}) or vector(0)', "alertes")],
            fieldConfig=red_above(1), options={**STAT, "textMode": "value"})
    d.next_line(4)
    d.panel("state-timeline", "Disponibilité avant / pendant / après l'incident", 0, 24, 5, PROM,
            [('probe_success{job="blackbox-http"}', "{{service}}")], fieldConfig=UP_DOWN, options={"showValue": "never", "mergeValues": True})
    d.next_line(5)
    remediation(d)
    d.row("Trafic et performances")
    d.panel("timeseries", "Requêtes / s par service et code", 0, 12, 8, PROM,
            [('sum by (service, status) (rate(http_requests_total{route!="/health"}[1m]))', "{{service}} {{status}}")])
    d.panel("timeseries", "Latence p95", 12, 12, 8, PROM,
            [('histogram_quantile(0.95, sum by (service, le) (rate(http_request_duration_seconds_bucket{route!="/health"}[1m])))', "{{service}}")],
            fieldConfig={"defaults": {"unit": "s"}, "overrides": []})
    d.next_line(8)
    d.row("Métier")
    d.panel("timeseries", "Virements / min par résultat", 0, 8, 7, PROM, [("sum by (result) (rate(payment_transfers_total[1m])) * 60", "{{result}}")])
    d.panel("timeseries", "Connexions / min par résultat", 8, 8, 7, PROM, [("sum by (result) (rate(auth_login_attempts_total[1m])) * 60", "{{result}}")])
    d.panel("stat", "Comptes / virements enregistrés", 16, 8, 7, PROM,
            [("payment_accounts", "comptes"), ("payment_transfers_stored", "virements")], options={**STAT, "colorMode": "none"})
    d.next_line(7)
    d.row("PC Hôte et sauvegardes (node-exporter, timer resilience-pg-backup)")
    host = [
        ("CPU", '100 * (1 - avg(rate(node_cpu_seconds_total{mode="idle"}[1m])))', 85, "percent"),
        ("Mémoire utilisée", "100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)", 90, "percent"),
        ("Disque / utilisé", '100 * (1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"})', 85, "percent"),
        ("Âge de la dernière sauvegarde", "time() - resilience_backup_last_success_timestamp_seconds", 1800, "s"),
    ]
    for index, (title, expr, threshold, unit) in enumerate(host):
        d.panel("stat", title, index * 4, 4, 4, PROM, [(expr, "")], fieldConfig=red_above(threshold, unit), options={**STAT, "textMode": "value"})
    d.panel("stat", "Registre dans la dernière sauvegarde", 16, 4, 4, PROM, [("resilience_backup_last_integrity_ok", "")],
            fieldConfig=UP_DOWN, options={**STAT, "textMode": "value"})
    d.panel("stat", "Dernière restauration", 20, 4, 4, PROM,
            [("resilience_restore_last_duration_seconds", "durée"), ("resilience_restore_last_backup_age_seconds", "données perdues ≤")],
            fieldConfig={"defaults": {"unit": "s"}, "overrides": []}, options={**STAT, "colorMode": "none"})
    d.next_line(4)
    d.row("Alertes et journaux")
    d.panel("table", "Alertes Prometheus en cours", 0, 10, 8, PROM,
            [('ALERTS{alertstate="firing"}', "", {"instant": True, "range": False, "format": "table"})],
            transformations=[{"id": "organize", "options": {"excludeByName": {"Time": True, "Value": True, "__name__": True, "alertstate": True, "platform": True}}}])
    d.panel("logs", "Erreurs et avertissements", 10, 14, 8, LOKI, [('{compose_project=~".+", level=~"error|warning"}', "")], options=LOGS)
    return d


def soc() -> Dashboard:
    # Cette méthode permet de décrire le tableau de bord SOC : compteurs d'événements, sources, journaux d'audit.
    d = Dashboard("ra-soc", "Resilience-Alpha — SOC", ["resilience-alpha", "security"])
    d.row("Événements de sécurité (règles d'alerte : infra/loki/rules/fake/soc.yml)")
    counters = [
        ("Échecs d'authentification (15 min)", '{event_type="auth_failure"}', 20),
        ("Requêtes bloquées par le WAF (15 min)", WAF_BLOCKED, 5),
        ("Violations d'intégrité (15 min)", '{event_type="integrity_violation"}', 1),
        ("Pannes de dépendance (15 min)", '{event_type="dependency_failure"}', 1),
    ]
    for index, (title, selector, threshold) in enumerate(counters):
        d.panel("stat", title, index * 6, 6, 4, LOKI, [(f"sum(count_over_time({selector} [15m])) or vector(0)", "")],
                fieldConfig=red_above(threshold), options={**STAT, "textMode": "value"})
    d.next_line(4)
    d.panel("timeseries", "Échecs d'authentification par IP source", 0, 12, 8, LOKI,
            [('sum by (client_ip) (count_over_time({event_type="auth_failure"} | json client_ip="client_ip" [1m]))', "{{client_ip}}")])
    d.panel("timeseries", "Blocages WAF par IP source", 12, 12, 8, LOKI,
            [(f"sum by (client_ip) (count_over_time({WAF_BLOCKED} [1m]))", "{{client_ip}}")])
    d.next_line(8)
    d.panel("timeseries", "Codes HTTP servis par le frontal", 0, 12, 7, LOKI,
            [('sum by (status) (count_over_time({service="frontend"} | json status="status" | __error__="" [1m]))', "{{status}}")])
    d.panel("bargauge", "Top 10 des IP sources (15 min)", 12, 12, 7, LOKI,
            [('topk(10, sum by (client_ip) (count_over_time({service="frontend"} | json client_ip="client_ip" | __error__="" [15m])))', "{{client_ip}}",
              {"queryType": "instant"})],
            options={"displayMode": "basic", "orientation": "horizontal", "reduceOptions": {"calcs": ["lastNotNull"]}})
    d.next_line(7)
    d.panel("logs", "Événements de sécurité applicatifs", 0, 12, 10, LOKI,
            [('{event_type=~"auth_failure|integrity_violation|dependency_failure"}', "")], options=LOGS)
    d.panel("logs", "Journal d'audit du WAF (ModSecurity)", 12, 12, 10, LOKI, [(WAF_AUDIT, "")], options={**LOGS, "prettifyLogMessage": True})
    return d


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    service_health().write()
    soc().write()
