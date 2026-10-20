#!/usr/bin/env python3
"""Outils d'attaque reproductibles contre le SI Resilience-Alpha (bibliothèque standard uniquement).

Rejoue, depuis n'importe quelle machine et SANS Docker, les tentatives de compromission à travers la chaîne
d'alertes : chaque sous-commande vise `--target http://<hôte>:<port>` (le WAF, point d'entrée unique) et produit
les journaux/métriques que Prometheus, Loki (SOC) et le détecteur ML transforment en alertes, puis que le moteur de
remédiation traite (blocage d'IP au WAF). On n'appelle jamais directement le moteur : tout passe par le WAF.

Aucun mot de passe n'est écrit en dur : le compte fictif « victime » utilise un mot de passe tiré à l'exécution
(`secrets.token_urlsafe`) ; les tentatives de connexion utilisent, elles, de mauvais mots de passe aléatoires. Les
charges d'injection sont des chaînes OWASP classiques (SQLi/XSS), inoffensives pour notre stack : le WAF les bloque
en 403 avant d'atteindre les API.

Sous-commandes (et l'alerte visée) :
  brute-force     force brute sur /api/auth/login      → auth_failure(auth-service) → AuthBruteForce (> 10/min, 1 IP)
  injections      SQLi/XSS à travers le WAF            → audit ModSecurity 403      → WafAttackBlocked (> 5/2 min, 1 IP)
  invalid-tokens  jetons porteurs invalides sur /api/payments → auth_failure(payment-api) → InvalidTokenFlood (> 20/min)
                  ou, à cadence plus basse, une anomalie ML (variable invalid_tokens_per_min) sous le seuil SOC.

La dernière ligne de la sortie standard est un résumé JSON, pour l'orchestrateur :
  {"scenario", "target", "started_at", "ended_at", "duration_s", "requests", "statuses": {code: n}, "rate_per_min"}

Exemples :
  python3 attack.py brute-force    --target http://127.0.0.1:8088 --duration 30 --rate 25
  python3 attack.py injections     --target http://127.0.0.1:8088 --duration 30 --rate 25
  python3 attack.py invalid-tokens --target http://127.0.0.1:8088 --duration 90 --rate 15   # sous le seuil SOC
"""

import argparse
import json
import secrets
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections import Counter
from datetime import datetime, timezone

# Charges applicatives classiques (OWASP CRS) que le WAF doit bloquer en 403 — inoffensives pour notre stack locale.
WAF_PAYLOADS = [
    "/api/payments/accounts?id=1%27%20OR%20%271%27=%271",
    "/api/payments/transfers?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/api/auth/login?u=admin%27--",
    "/api/payments/accounts?id=1%20UNION%20SELECT%20null%20FROM%20accounts",
]


def _request(target, method, path, body=None, headers=None, timeout=6):
    # Cette méthode permet d'émettre une requête et de renvoyer le code HTTP (0 si le réseau échoue) : on ne veut
    # que produire la charge et observer la réponse, jamais faire échouer le scénario sur une erreur réseau ponctuelle.
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(target + path, data=data, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status, res.read(4096)
    except urllib.error.HTTPError as err:
        return err.code, err.read(4096) if hasattr(err, "read") else b""
    except OSError:
        return 0, b""


def _loop(target, duration, rate, make_request):
    # Cette méthode permet de répéter une requête à cadence fixe (rate requêtes/min) pendant `duration` secondes.
    interval = 60.0 / rate if rate > 0 else 0.0
    deadline = time.time() + duration
    statuses = Counter()
    n = 0
    while time.time() < deadline:
        code, _ = make_request(n)
        statuses[code] += 1
        n += 1
        if interval:
            time.sleep(interval)
    return statuses


def brute_force(target, duration, rate):
    # Cette méthode permet de simuler une force brute : connexions répétées avec de mauvais mots de passe (401 attendus).
    email = f"victime-{uuid.uuid4().hex[:8]}@recette.local"
    password = secrets.token_urlsafe(16)   # mot de passe réel du compte victime, jamais réutilisé
    _request(target, "POST", "/api/auth/register",
             body=json.dumps({"email": email, "full_name": "Victime Recette", "password": password}),
             headers={"Content-Type": "application/json"})

    def attempt(_n):
        wrong = secrets.token_urlsafe(12)  # mauvais mot de passe aléatoire → 401
        return _request(target, "POST", "/api/auth/login",
                        body=json.dumps({"email": email, "password": wrong}),
                        headers={"Content-Type": "application/json"})
    return _loop(target, duration, rate, attempt)


def injections(target, duration, rate):
    # Cette méthode permet de simuler des injections SQLi/XSS bloquées par le WAF (403 attendus, audit ModSecurity).
    def attempt(n):
        return _request(target, "GET", WAF_PAYLOADS[n % len(WAF_PAYLOADS)])
    return _loop(target, duration, rate, attempt)


def invalid_tokens(target, duration, rate):
    # Cette méthode permet de simuler une rafale de jetons porteurs invalides sur l'API de paiement (401 attendus).
    def attempt(_n):
        return _request(target, "GET", "/api/payments/accounts/me",
                        headers={"Authorization": f"Bearer invalide.{uuid.uuid4().hex}"})
    return _loop(target, duration, rate, attempt)


SCENARIOS = {"brute-force": brute_force, "injections": injections, "invalid-tokens": invalid_tokens}
EXPECTED = {"brute-force": {401}, "injections": {403}, "invalid-tokens": {401}}


def main():
    # Cette méthode permet de lancer une attaque reproductible et d'afficher son résumé JSON (dernière ligne).
    parser = argparse.ArgumentParser(description="Attaques reproductibles (chaîne d'alertes Resilience-Alpha).")
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--target", required=True, help="URL du WAF, ex. http://127.0.0.1:8088")
    parser.add_argument("--duration", type=int, default=30, help="durée de l'attaque (s)")
    parser.add_argument("--rate", type=int, default=25, help="cadence (requêtes/min) — règle l'intensité")
    args = parser.parse_args()
    target = args.target.rstrip("/")

    print(f"[{args.scenario}] {target} pendant {args.duration}s à {args.rate}/min…", file=sys.stderr, flush=True)
    started = time.time()
    statuses = SCENARIOS[args.scenario](target, args.duration, args.rate)
    ended = time.time()
    total = sum(statuses.values())
    expected = EXPECTED[args.scenario]
    matching = sum(c for code, c in statuses.items() if code in expected)
    summary = {
        "scenario": args.scenario, "target": target,
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
        "ended_at": datetime.fromtimestamp(ended, timezone.utc).isoformat(),
        "started_epoch": round(started, 3), "ended_epoch": round(ended, 3),
        "duration_s": round(ended - started, 1), "requests": total,
        "statuses": {str(k): v for k, v in sorted(statuses.items())},
        "rate_per_min": round(total / ((ended - started) / 60.0), 1) if ended > started else 0.0,
        "expected_share": round(matching / total, 2) if total else 0.0,
    }
    print(f"  réponses : {dict(statuses)} ({matching}/{total} attendues {sorted(expected)})", file=sys.stderr, flush=True)
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
