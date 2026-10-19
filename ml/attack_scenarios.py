"""Scénarios d'incident/attaque ÉTIQUETÉS contre la stack LOCALE uniquement (bibliothèque standard).

Chaque scénario vise exclusivement le SI fictif local (http://127.0.0.1:8080 par défaut) et consigne ses
bornes temporelles (début/fin) dans `ml/data/labels.csv` : ce sont les étiquettes qui serviront à mesurer
précision/rappel/délai de détection lors de l'entraînement. Rien ici ne sort du laboratoire.

Scénarios (tous observables par la supervision) et services impactés (étiquetés) :
- brute_force        : rafale de connexions échouées (force brute d'identifiants)      → auth-service, frontend
- invalid_token_flood: rafale d'appels paiement avec des jetons invalides               → payment-api, frontend
- transfer_abuse     : virements répétés à cadence anormale (bénéficiaire inconnu)      → payment-api, frontend
- waf_probe          : charges SQLi/XSS bloquées par le WAF (403)                        → frontend
- stop_payment       : arrêt bref du conteneur payment-api (option --allow-docker)       → payment-api

Une attaque qui traverse le WAF et le frontal nginx y provoque un pic de trafic réel : le frontal est donc
étiqueté comme impacté (vérité terrain), pas seulement le service visé. Une ligne d'étiquette par service.

Usage :
    python ml/attack_scenarios.py --base http://127.0.0.1:8080 --scenario all --gap 40
"""

import argparse
import csv
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

LABELS = Path(__file__).resolve().parent / "data" / "labels.csv"


def _request(base, method, path, body=None, headers=None, timeout=6):
    # Cette méthode permet d'émettre une requête et d'ignorer proprement les erreurs (on veut seulement produire la charge).
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(base + path, data=data, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status
    except urllib.error.HTTPError as err:
        return err.code
    except OSError:
        return 0


def record_label(scenario, services, start, end, labels=LABELS):
    # Cette méthode permet d'ajouter les lignes d'étiquette (fenêtre temporelle de l'incident, une par service impacté).
    labels.parent.mkdir(parents=True, exist_ok=True)
    new_file = not labels.exists()
    with labels.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if new_file:
            writer.writerow(["scenario", "service", "start", "end", "start_iso", "end_iso"])
        for service in services:
            writer.writerow([
                scenario, service, f"{start:.0f}", f"{end:.0f}",
                datetime.fromtimestamp(start, timezone.utc).isoformat(),
                datetime.fromtimestamp(end, timezone.utc).isoformat(),
            ])
    print(f"  étiquette : {scenario} {list(services)} {end - start:.0f}s", flush=True)


def brute_force(base, duration):
    # Cette méthode permet de simuler une force brute : connexions répétées avec de mauvais mots de passe.
    email = "victime@demo.local"
    _request(base, "POST", "/api/auth/register",
             body=f'{{"email":"{email}","full_name":"Victime","password":"Demo-password-2026"}}',
             headers={"Content-Type": "application/json"})
    deadline = time.time() + duration
    n = 0
    while time.time() < deadline:
        _request(base, "POST", "/api/auth/login",
                 body=f'{{"email":"{email}","password":"mauvais-{n}"}}',
                 headers={"Content-Type": "application/json"})
        n += 1
        time.sleep(0.05)
    return n


def invalid_token_flood(base, duration):
    # Cette méthode permet de simuler une rafale d'appels paiement avec des jetons invalides (jetons forgés).
    deadline = time.time() + duration
    n = 0
    while time.time() < deadline:
        _request(base, "GET", "/api/payments/accounts/me",
                 headers={"Authorization": f"Bearer invalide.{uuid.uuid4().hex}.{n}"})
        n += 1
        time.sleep(0.05)
    return n


def transfer_abuse(base, duration):
    # Cette méthode permet de simuler un usage anormal de virements : cadence élevée, dont des soldes insuffisants.
    email = f"abus-{uuid.uuid4().hex[:8]}@demo.local"
    _request(base, "POST", "/api/auth/register",
             body=f'{{"email":"{email}","full_name":"Abus","password":"Demo-password-2026"}}',
             headers={"Content-Type": "application/json"})
    import json as _json
    req = urllib.request.Request(base + "/api/auth/login", method="POST",
                                 data=_json.dumps({"email": email, "password": "Demo-password-2026"}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=6) as res:
            token = _json.loads(res.read()).get("access_token", "")
    except OSError:
        token = ""
    deadline = time.time() + duration
    n = 0
    while time.time() < deadline:
        _request(base, "POST", "/api/payments/transfers",
                 body=_json.dumps({"to_account_number": "RA0000000001", "amount_cents": 999999, "label": "x"}),
                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}",
                          "Idempotency-Key": uuid.uuid4().hex})
        n += 1
        time.sleep(0.04)
    return n


# Charges applicatives classiques que le WAF (OWASP CRS) doit bloquer en 403 — inoffensives pour notre stack locale.
_WAF_PAYLOADS = [
    "/api/payments/accounts?id=1%27%20OR%20%271%27=%271",
    "/api/payments/transfers?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/api/auth/login?u=admin%27--",
    "/api/payments/accounts?id=1%20UNION%20SELECT%20password%20FROM%20users",
]


def waf_probe(base, duration):
    # Cette méthode permet de simuler des charges SQLi/XSS qui seront bloquées par le WAF (journal d'audit en 403).
    deadline = time.time() + duration
    n = 0
    while time.time() < deadline:
        _request(base, "GET", _WAF_PAYLOADS[n % len(_WAF_PAYLOADS)])
        n += 1
        time.sleep(0.08)
    return n


def stop_payment(duration, project):
    # Cette méthode permet d'arrêter brièvement le conteneur payment-api (incident de disponibilité), puis de le relancer.
    name = f"{project}-payment-api-1"
    subprocess.run(["docker", "stop", name], capture_output=True)
    time.sleep(duration)
    subprocess.run(["docker", "start", name], capture_output=True)
    return 1


SCENARIOS = {
    "brute_force": (("auth-service", "frontend"), brute_force),
    "invalid_token_flood": (("payment-api", "frontend"), invalid_token_flood),
    "transfer_abuse": (("payment-api", "frontend"), transfer_abuse),
    "waf_probe": (("frontend",), waf_probe),
}


def run_one(base, name, duration, project, allow_docker, labels=LABELS):
    # Cette méthode permet de lancer un scénario, d'enregistrer ses bornes temporelles et d'afficher un suivi.
    print(f"[{name}] démarrage ({duration}s)…", flush=True)
    start = time.time()
    if name == "stop_payment":
        if not allow_docker:
            print("  ignoré (nécessite --allow-docker)", flush=True)
            return
        stop_payment(duration, project)
        services = ("payment-api",)
    else:
        services, func = SCENARIOS[name]
        func(base, duration)
    end = time.time()
    record_label(name, services, start, end, labels)


def main():
    # Cette méthode permet d'enchaîner un ou plusieurs scénarios d'attaque étiquetés, séparés par des pauses.
    parser = argparse.ArgumentParser(description="Scénarios d'attaque étiquetés (stack locale).")
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--scenario", default="all", help="all ou un nom de scénario")
    parser.add_argument("--duration", type=int, default=60, help="durée de chaque scénario (s)")
    parser.add_argument("--gap", type=int, default=40, help="pause entre scénarios (s), redevient normal")
    parser.add_argument("--project", default="resilience-alpha", help="nom du projet Compose (pour stop_payment)")
    parser.add_argument("--allow-docker", action="store_true", help="autorise l'arrêt de conteneur (stop_payment)")
    parser.add_argument("--labels", default=str(LABELS), help="fichier d'étiquettes (ex. session de test séparée)")
    args = parser.parse_args()
    base = args.base.rstrip("/")

    order = list(SCENARIOS) + (["stop_payment"] if args.allow_docker else [])
    names = order if args.scenario == "all" else [args.scenario]
    for i, name in enumerate(names):
        run_one(base, name, args.duration, args.project, args.allow_docker, Path(args.labels))
        if i < len(names) - 1:
            print(f"  pause {args.gap}s (retour à la normale)…", flush=True)
            time.sleep(args.gap)
    print("Scénarios terminés.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
