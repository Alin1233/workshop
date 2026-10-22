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

Une étiquette n'est écrite que si le scénario a réellement eu lieu : chaque scénario vérifie avoir obtenu les
réponses attendues (401, 403, 404/422…) sur au moins la moitié de ses requêtes, `transfer_abuse` s'arrête sans
jeton valide, `stop_payment` vérifie le résultat de `docker stop`. Sinon : erreur affichée, aucune étiquette,
code de sortie 1 (une fenêtre étiquetée sans attaque fausserait le rappel et les délais mesurés).

Usage :
    python ml/attack_scenarios.py --base http://127.0.0.1:8080 --scenario all --gap 40
"""

import argparse
import csv
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Mot de passe des comptes fictifs créés par les scénarios, tiré à chaque exécution (aucun secret dans le dépôt).
DEMO_PASSWORD = secrets.token_urlsafe(16)

LABELS = Path(__file__).resolve().parent / "data" / "labels.csv"
MIN_EXPECTED_SHARE = 0.5  # part minimale des réponses attendues pour considérer que l'attaque a bien eu lieu


class ScenarioFailed(RuntimeError):
    """Le scénario n'a pas produit l'incident attendu : aucune étiquette ne doit être enregistrée."""


def check_responses(name, statuses, expected):
    # Cette méthode permet de vérifier qu'un scénario a bien produit les réponses attendues (sinon ScenarioFailed).
    total = sum(statuses.values())
    matching = sum(count for code, count in statuses.items() if code in expected)
    if total == 0 or matching / total < MIN_EXPECTED_SHARE:
        raise ScenarioFailed(f"{name} : {matching}/{total} réponses attendues {sorted(expected)} (reçu {dict(statuses)})")
    return statuses


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
    # Cette méthode permet de simuler une force brute : connexions répétées avec de mauvais mots de passe (401 attendus).
    email = "victime@demo.local"
    _request(base, "POST", "/api/auth/register",
             body=json.dumps({"email": email, "full_name": "Victime", "password": DEMO_PASSWORD}),
             headers={"Content-Type": "application/json"})
    deadline = time.time() + duration
    statuses = Counter()
    while time.time() < deadline:
        wrong = secrets.token_urlsafe(12)  # mauvais mot de passe aléatoire
        statuses[_request(base, "POST", "/api/auth/login", body=json.dumps({"email": email, "password": wrong}),
                          headers={"Content-Type": "application/json"})] += 1
        time.sleep(0.05)
    return check_responses("brute_force", statuses, {401})


def invalid_token_flood(base, duration):
    # Cette méthode permet de simuler une rafale d'appels paiement avec des jetons invalides (401 attendus).
    deadline = time.time() + duration
    statuses = Counter()
    while time.time() < deadline:
        statuses[_request(base, "GET", "/api/payments/accounts/me",
                          headers={"Authorization": f"Bearer invalide.{uuid.uuid4().hex}"})] += 1
        time.sleep(0.05)
    return check_responses("invalid_token_flood", statuses, {401})


def transfer_abuse(base, duration):
    # Cette méthode permet de simuler un usage anormal de virements : cadence élevée vers un bénéficiaire inconnu
    # (404/422 attendus). Sans jeton valide, le scénario échoue au lieu d'envoyer des requêtes anonymes.
    email = f"abus-{uuid.uuid4().hex[:8]}@demo.local"
    _request(base, "POST", "/api/auth/register",
             body=json.dumps({"email": email, "full_name": "Abus", "password": DEMO_PASSWORD}),
             headers={"Content-Type": "application/json"})
    req = urllib.request.Request(base + "/api/auth/login", method="POST",
                                 data=json.dumps({"email": email, "password": DEMO_PASSWORD}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=6) as res:
            token = json.loads(res.read()).get("access_token", "")
    except (OSError, ValueError) as exc:
        raise ScenarioFailed(f"transfer_abuse : connexion impossible ({exc})") from exc
    if not token:
        raise ScenarioFailed("transfer_abuse : aucun jeton obtenu")
    deadline = time.time() + duration
    statuses = Counter()
    while time.time() < deadline:
        statuses[_request(base, "POST", "/api/payments/transfers",
                          body=json.dumps({"to_account_number": "RA0000000001", "amount_cents": 999999, "label": "x"}),
                          headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}",
                                   "Idempotency-Key": uuid.uuid4().hex})] += 1
        time.sleep(0.04)
    return check_responses("transfer_abuse", statuses, {404, 422})


# Charges applicatives classiques que le WAF (OWASP CRS) doit bloquer en 403 — inoffensives pour notre stack locale.
_WAF_PAYLOADS = [
    "/api/payments/accounts?id=1%27%20OR%20%271%27=%271",
    "/api/payments/transfers?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/api/auth/login?u=admin%27--",
    "/api/payments/accounts?id=1%20UNION%20SELECT%20password%20FROM%20users",
]


def waf_probe(base, duration):
    # Cette méthode permet de simuler des charges SQLi/XSS qui seront bloquées par le WAF (403 attendus).
    deadline = time.time() + duration
    statuses = Counter()
    n = 0
    while time.time() < deadline:
        statuses[_request(base, "GET", _WAF_PAYLOADS[n % len(_WAF_PAYLOADS)])] += 1
        n += 1
        time.sleep(0.08)
    return check_responses("waf_probe", statuses, {403})


def resolve_container(project, service, run=subprocess.run):
    # Cette méthode permet de retrouver le conteneur d'un service Compose par ses labels (indépendant du nommage).
    result = run(["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}",
                  "--filter", f"label=com.docker.compose.service={service}"], capture_output=True, text=True)
    ids = result.stdout.split() if result.returncode == 0 else []
    if len(ids) != 1:
        raise ScenarioFailed(f"conteneur {service} du projet {project} introuvable ou ambigu ({ids or result.stderr.strip()})")
    return ids[0]


def stop_payment(duration, container, run=subprocess.run, sleep=time.sleep):
    # Cette méthode permet d'arrêter brièvement le conteneur payment-api (incident de disponibilité), puis de le relancer.
    # Un `docker stop` en échec ⇒ ScenarioFailed (pas d'incident, pas d'étiquette). Un `docker start` en échec est
    # signalé à l'appelant : l'incident a bien eu lieu (étiquette), mais le service reste arrêté.
    stopped = run(["docker", "stop", container], capture_output=True, text=True)
    if stopped.returncode != 0:
        raise ScenarioFailed(f"docker stop {container} a échoué : {stopped.stderr.strip()}")
    sleep(duration)
    started = run(["docker", "start", container], capture_output=True, text=True)
    return started.returncode == 0, started.stderr.strip()


SCENARIOS = {
    "brute_force": (("auth-service", "frontend"), brute_force),
    "invalid_token_flood": (("payment-api", "frontend"), invalid_token_flood),
    "transfer_abuse": (("payment-api", "frontend"), transfer_abuse),
    "waf_probe": (("frontend",), waf_probe),
}


def run_one(base, name, duration, container, allow_docker, labels=LABELS):
    # Cette méthode permet de lancer un scénario et de n'enregistrer ses bornes temporelles que s'il a réellement eu lieu.
    # Renvoie True si le scénario s'est déroulé normalement, False sinon (erreur affichée).
    print(f"[{name}] démarrage ({duration}s)…", flush=True)
    start = time.time()
    try:
        if name == "stop_payment":
            if not allow_docker:
                print("  ignoré (nécessite --allow-docker)", flush=True)
                return True
            restarted, error = stop_payment(duration, container)
            record_label(name, ("payment-api",), start, time.time(), labels)
            if not restarted:
                print(f"  ERREUR : docker start {container} a échoué ({error}) — payment-api reste arrêté", file=sys.stderr, flush=True)
            return restarted
        services, func = SCENARIOS[name]
        statuses = func(base, duration)
    except ScenarioFailed as exc:
        print(f"  ERREUR : {exc} — aucune étiquette enregistrée", file=sys.stderr, flush=True)
        return False
    record_label(name, services, start, time.time(), labels)
    print(f"  réponses : {dict(statuses)}", flush=True)
    return True


def main():
    # Cette méthode permet d'enchaîner un ou plusieurs scénarios d'attaque étiquetés, séparés par des pauses.
    parser = argparse.ArgumentParser(description="Scénarios d'attaque étiquetés (stack locale).")
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--scenario", default="all", help="all ou un nom de scénario")
    parser.add_argument("--duration", type=int, default=60, help="durée de chaque scénario (s)")
    parser.add_argument("--gap", type=int, default=40, help="pause entre scénarios (s), redevient normal")
    parser.add_argument("--project", default=os.getenv("COMPOSE_PROJECT_NAME", "resilience-alpha"),
                        help="nom du projet Compose (pour retrouver le conteneur payment-api)")
    parser.add_argument("--payment-container", default=None,
                        help="nom ou id du conteneur payment-api (défaut : déduit des labels du projet Compose)")
    parser.add_argument("--allow-docker", action="store_true", help="autorise l'arrêt de conteneur (stop_payment)")
    parser.add_argument("--labels", default=str(LABELS), help="fichier d'étiquettes (ex. session de test séparée)")
    args = parser.parse_args()
    base = args.base.rstrip("/")

    order = list(SCENARIOS) + (["stop_payment"] if args.allow_docker else [])
    names = order if args.scenario == "all" else [args.scenario]
    container = args.payment_container
    if "stop_payment" in names and args.allow_docker and not container:
        try:
            container = resolve_container(args.project, "payment-api")
        except ScenarioFailed as exc:
            print(f"ERREUR : {exc}", file=sys.stderr)
            return 1
    failures = []
    for i, name in enumerate(names):
        if not run_one(base, name, args.duration, container, args.allow_docker, Path(args.labels)):
            failures.append(name)
        if i < len(names) - 1:
            print(f"  pause {args.gap}s (retour à la normale)…", flush=True)
            time.sleep(args.gap)
    print(f"Scénarios terminés{' — en échec : ' + ', '.join(failures) if failures else '.'}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
