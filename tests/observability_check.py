"""Vérifie la chaîne d'observation et de défense : WAF, Prometheus, Loki, règles SOC, Alertmanager, Grafana.

Usage (sur le PC Hôte, les interfaces de gestion n'étant publiées que sur 127.0.0.1) :
    python tests/observability_check.py
Les URL se surchargent par variables d'environnement (RA_FRONT_URL, RA_PROMETHEUS_URL, RA_LOKI_URL,
RA_ALERTMANAGER_URL, RA_GRAFANA_URL), par exemple pour viser la stack d'un worktree.
Code de sortie 0 si toutes les vérifications passent. Bibliothèque standard uniquement.
"""

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

FRONT = os.environ.get("RA_FRONT_URL", "http://127.0.0.1:8080")
PROMETHEUS = os.environ.get("RA_PROMETHEUS_URL", "http://127.0.0.1:9090")
LOKI = os.environ.get("RA_LOKI_URL", "http://127.0.0.1:3100")
ALERTMANAGER = os.environ.get("RA_ALERTMANAGER_URL", "http://127.0.0.1:9093")
GRAFANA = os.environ.get("RA_GRAFANA_URL", "http://127.0.0.1:3000")
SECRETS = Path(__file__).resolve().parent.parent / "secrets"

results: list[bool] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    # Cette méthode permet d'afficher le résultat d'une vérification et de le mémoriser pour le bilan final.
    results.append(ok)
    print(f"  {'OK' if ok else 'KO'}  {label}" + (f" — {detail}" if detail and not ok else ""))
    return ok


def http(url: str, headers: dict | None = None) -> tuple[int, str]:
    # Cette méthode permet d'effectuer un GET et de renvoyer (code, corps), y compris pour les réponses d'erreur.
    request = urllib.request.Request(url, headers={"User-Agent": "resilience-alpha-check/1.0", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except OSError as exc:
        return 0, str(exc)


def get_json(url: str, headers: dict | None = None) -> dict:
    # Cette méthode permet de récupérer une réponse JSON, ou un dictionnaire vide si le service est injoignable.
    status, body = http(url, headers)
    try:
        return json.loads(body) if status else {}
    except json.JSONDecodeError:
        return {}


def prom_query(expr: str) -> list:
    # Cette méthode permet d'exécuter une requête PromQL instantanée et de renvoyer la liste des séries.
    data = get_json(f"{PROMETHEUS}/api/v1/query?" + urllib.parse.urlencode({"query": expr}))
    return data.get("data", {}).get("result", [])


def loki_lines(query: str, since_s: int = 300) -> list[str]:
    # Cette méthode permet de récupérer les lignes de journaux Loki correspondant à une requête LogQL récente.
    params = {"query": query, "limit": 200, "start": str(int((time.time() - since_s) * 1e9))}
    data = get_json(f"{LOKI}/loki/api/v1/query_range?" + urllib.parse.urlencode(params))
    return [line for stream in data.get("data", {}).get("result", []) for _, line in stream.get("values", [])]


def wait_for(predicate, timeout_s: int = 30) -> bool:
    # Cette méthode permet d'attendre qu'une condition devienne vraie (ingestion des journaux, scrape) dans un délai borné.
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(2)
    return False


def main() -> int:
    # Cette méthode permet d'enchaîner les vérifications de chaque maillon de la chaîne d'observation.
    marker = f"obscheck{int(time.time())}"

    print("\n[WAF]")
    status, _ = http(f"{FRONT}/")
    check("le front est servi à travers le WAF", status == 200, f"HTTP {status}")
    status, _ = http(f"{FRONT}/api/payments/accounts?id=1%27%20OR%20%271%27=%271&{marker}=1")
    check("une injection SQL est bloquée (403)", status == 403, f"HTTP {status}")
    status, _ = http(f"{FRONT}/api/payments/metrics")
    check("les endpoints internes restent masqués", status == 404, f"HTTP {status}")

    print("\n[Prometheus]")
    targets = get_json(f"{PROMETHEUS}/api/v1/targets").get("data", {}).get("activeTargets", [])
    down = [t["labels"].get("instance") for t in targets if t.get("health") != "up"]
    check(f"{len(targets)} cibles scrapées, toutes « up »", bool(targets) and not down, f"en échec : {down}")
    probes = prom_query('probe_success{job="blackbox-http"}')
    check("sondes de bout en bout en succès", len(probes) == 3 and all(p["value"][1] == "1" for p in probes),
          str([(p["metric"].get("service"), p["value"][1]) for p in probes]))
    rules = get_json(f"{PROMETHEUS}/api/v1/rules").get("data", {}).get("groups", [])
    check("règles d'alerte Prometheus chargées", sum(len(g["rules"]) for g in rules) >= 7)

    print("\n[Loki / Alloy]")
    labels = get_json(f"{LOKI}/loki/api/v1/label/service/values").get("data", [])
    expected = {"waf", "frontend", "auth-service", "payment-api"}
    check("journaux des services reçus", expected <= set(labels), f"services vus : {labels}")
    blocked = []
    check("le blocage WAF apparaît dans le journal d'audit",
          wait_for(lambda: blocked.extend(loki_lines(f'{{service="waf"}} |= "\\"transaction\\"" |= "{marker}"')) or bool(blocked)))
    if blocked:
        audit = json.loads(blocked[0]).get("transaction", {})
        client_ip = audit.get("client_ip", "")
        check("IP source réelle conservée par le WAF", bool(client_ip) and not client_ip.startswith("172.31.250."), client_ip)
    login = urllib.request.Request(f"{FRONT}/api/auth/login", method="POST", headers={"Content-Type": "application/json"},
                                   data=json.dumps({"email": f"{marker}@resilience.local", "password": "x"}).encode())
    try:
        urllib.request.urlopen(login, timeout=10)
    except OSError:
        pass  # 401 attendu : seul compte l'événement auth_failure journalisé
    failures = []
    if check("un échec de connexion produit un événement auth_failure",
             wait_for(lambda: failures.extend(loki_lines(f'{{service="auth-service", event_type="auth_failure"}} |= "{marker}"')) or bool(failures))):
        client_ip = json.loads(failures[0]).get("client_ip", "")
        check("IP réelle propagée jusqu'aux API (X-Real-IP)", bool(client_ip) and not client_ip.startswith("172.31.250."), client_ip)
    soc = get_json(f"{LOKI}/prometheus/api/v1/rules").get("data", {}).get("groups", [])
    check("règles SOC chargées dans le ruler Loki", sum(len(g["rules"]) for g in soc) >= 5)

    print("\n[Alertmanager / Grafana]")
    status, _ = http(f"{ALERTMANAGER}/-/ready")
    check("Alertmanager prêt", status == 200, f"HTTP {status}")
    password_file = SECRETS / "grafana_admin_password"
    auth = base64.b64encode(f"admin:{password_file.read_text().strip()}".encode()).decode() if password_file.exists() else ""
    headers = {"Authorization": f"Basic {auth}"}
    sources = get_json(f"{GRAFANA}/api/datasources", headers)
    check("sources de données Grafana provisionnées", isinstance(sources, list) and {s.get("uid") for s in sources} >= {"prometheus", "loki", "alertmanager"})
    for uid in ("prometheus", "loki"):
        health = get_json(f"{GRAFANA}/api/datasources/uid/{uid}/health", headers)
        check(f"Grafana joint {uid}", health.get("status") == "OK", health.get("message", ""))
    dashboards = get_json(f"{GRAFANA}/api/search?tag=resilience-alpha", headers)
    check("tableaux de bord provisionnés", isinstance(dashboards, list) and len(dashboards) >= 2)

    print(f"\n{sum(results)}/{len(results)} vérifications OK")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
