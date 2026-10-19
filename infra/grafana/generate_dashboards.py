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
WAF_BLOCKED = WAF_AUDIT + ' | json client_ip="transaction.client_ip", code="transaction.response.http_code" | code="403"'


class Dashboard:
    def __init__(self, uid: str, title: str, tags: list[str]):
        # Cette méthode permet d'initialiser un tableau de bord vide avec son identifiant stable et ses tags.
        self.uid, self.title, self.tags = uid, title, tags
        self.panels: list[dict] = []
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
        path = OUT / f"{self.uid.removeprefix('ra-')}.json"
        path.write_text(json.dumps(model, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"  + {path.relative_to(OUT.parent.parent.parent)}")


def red_above(value: float) -> dict:
    # Cette méthode permet de construire des seuils « vert puis rouge à partir de value » pour un compteur.
    steps = [{"color": "green", "value": None}, {"color": "red", "value": value}]
    return {"defaults": {"thresholds": {"mode": "absolute", "steps": steps}}, "overrides": []}


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
            [('sum by (status) (count_over_time({service="frontend"} | json status="status" [1m]))', "{{status}}")])
    d.panel("bargauge", "Top 10 des IP sources (15 min)", 12, 12, 7, LOKI,
            [('topk(10, sum by (client_ip) (count_over_time({service="frontend"} | json client_ip="client_ip" [15m])))', "{{client_ip}}",
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
