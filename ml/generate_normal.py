"""Générateur de trafic NORMAL contre la stack locale, à travers le WAF (bibliothèque standard uniquement).

Simule des utilisateurs réalistes : inscription, connexion, consultation de compte, virements de faibles
montants entre comptes fictifs. Le débit varie dans le temps (profil sinusoïdal) et comporte des périodes
creuses (aucun trafic), pour que le modèle apprenne aussi que « peu ou pas d'activité » est normal.

Usage :
    python ml/generate_normal.py --base http://127.0.0.1:8080 --duration 900 [--seed 42]

Toutes les données sont fictives et tout le trafic reste strictement local (laboratoire). S'inspire de
tests/smoke_test.py pour piloter l'API avec urllib.
"""

import argparse
import json
import math
import random
import sys
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor


def call(base, method, path, body=None, token=None, headers=None, timeout=8):
    # Cette méthode permet d'envoyer une requête HTTP JSON et de renvoyer (statut, corps) sans lever sur 4xx/5xx.
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status, json.loads(res.read() or b"null")
    except urllib.error.HTTPError as err:
        try:
            return err.code, json.loads(err.read() or b"null")
        except ValueError:
            return err.code, None
    except OSError:
        return 0, None


class Population:
    """Maintient un petit vivier de comptes fictifs partagés par les utilisateurs simulés."""

    def __init__(self, base):
        # Cette méthode permet d'initialiser le vivier de comptes utilisés par les virements.
        self.base = base
        self.accounts = []  # liste de (numéro de compte, jeton)

    def register_user(self):
        # Cette méthode permet de créer un nouvel utilisateur fictif, de le connecter et de mémoriser son compte.
        email = f"user-{uuid.uuid4().hex[:10]}@demo.local"
        password = "Demo-password-2026"
        status, _ = call(self.base, "POST", "/api/auth/register", {"email": email, "full_name": "Utilisateur Démo", "password": password})
        if status not in (201, 409):
            return
        status, body = call(self.base, "POST", "/api/auth/login", {"email": email, "password": password})
        if status != 200 or not isinstance(body, dict):
            return
        token = body.get("access_token", "")
        status, account = call(self.base, "GET", "/api/payments/accounts/me", token=token)
        if status == 200 and isinstance(account, dict):
            self.accounts.append((account["account_number"], token))

    def random_action(self, rng):
        # Cette méthode permet d'exécuter une action utilisateur plausible choisie au hasard.
        if len(self.accounts) < 3 or rng.random() < 0.12:
            self.register_user()
            return
        number, token = rng.choice(self.accounts)
        roll = rng.random()
        if roll < 0.45:
            call(self.base, "GET", "/api/payments/accounts/me", token=token)
        elif roll < 0.65:
            call(self.base, "GET", "/api/payments/transfers?limit=20", token=token)
        else:
            target = rng.choice([a for a in self.accounts if a[0] != number])[0]
            call(self.base, "POST", "/api/payments/transfers",
                 {"to_account_number": target, "amount_cents": rng.randint(50, 5000), "label": "Achat"},
                 token=token, headers={"Idempotency-Key": uuid.uuid4().hex})


def load_profile(elapsed, total, rng_phase):
    # Cette méthode permet de calculer le nombre de requêtes à lancer cette seconde (débit variable + périodes creuses).
    # Périodes creuses : ~25 s toutes les ~150 s, pour apprendre que l'inactivité est normale.
    if (elapsed % 150) >= 125:
        return 0
    base = 4.0 + 3.0 * math.sin(2 * math.pi * (elapsed / 90.0) + rng_phase)
    return max(0, int(round(base)))


def main():
    # Cette méthode permet de dérouler la génération de trafic normal pendant la durée demandée.
    parser = argparse.ArgumentParser(description="Génère du trafic normal contre la stack locale.")
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--duration", type=int, default=900, help="durée en secondes")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    phase = rng.uniform(0, 2 * math.pi)
    population = Population(args.base.rstrip("/"))
    for _ in range(4):
        population.register_user()

    print(f"Trafic normal vers {args.base} pendant {args.duration}s (seed={args.seed})", flush=True)
    start = time.time()
    fired = 0
    with ThreadPoolExecutor(max_workers=24) as pool:
        while time.time() - start < args.duration:
            tick = time.time()
            elapsed = int(tick - start)
            count = load_profile(elapsed, args.duration, phase)
            for _ in range(count):
                pool.submit(population.random_action, rng)
                fired += 1
            if elapsed % 30 == 0:
                print(f"  t={elapsed}s débit≈{count}/s comptes={len(population.accounts)} requêtes={fired}", flush=True)
            # On cale sur la seconde suivante.
            time.sleep(max(0.0, 1.0 - (time.time() - tick)))
    print(f"Terminé : {fired} requêtes générées en {int(time.time() - start)}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
