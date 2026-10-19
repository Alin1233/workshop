"""Générateur de trafic NORMAL contre la stack locale, à travers le WAF (bibliothèque standard uniquement).

Simule des utilisateurs réalistes : inscription, connexion, consultation de compte, virements de faibles
montants entre comptes fictifs. Le débit varie dans le temps (profil sinusoïdal) et comporte des périodes
creuses (aucun trafic), pour que le modèle apprenne aussi que « peu ou pas d'activité » est normal.

Usage :
    python ml/generate_normal.py --base http://127.0.0.1:8080 --duration 900 [--seed 42] [--max-in-flight 24]

Reproductibilité et maîtrise de la charge :
- toutes les décisions aléatoires (type d'action, compte, bénéficiaire, montant) sont tirées dans le thread
  ordonnanceur, dans un ordre fixe : la suite aléatoire ne dépend que de `--seed`, pas de l'ordre d'exécution
  des threads (l'effet sur un vivier de comptes qui évolue reste, lui, dépendant du temps réel) ;
- le travail en vol est borné (`--max-in-flight`) : si les requêtes ralentissent, les actions en trop sont
  ignorées et comptées, jamais empilées — les périodes creuses restent donc réellement creuses ;
- l'arrêt est net à `--duration` : plus aucune action lancée, seules les requêtes en cours (délai borné) s'achèvent.

Toutes les données sont fictives et tout le trafic reste strictement local (laboratoire). S'inspire de
tests/smoke_test.py pour piloter l'API avec urllib.
"""

import argparse
import json
import math
import random
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor


REQUEST_TIMEOUT = 5  # s : borne aussi la durée de l'arrêt final (requêtes en vol)


def call(base, method, path, body=None, token=None, headers=None, timeout=REQUEST_TIMEOUT):
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
        self._lock = threading.Lock()

    def register_user(self):
        # Cette méthode permet de créer un nouvel utilisateur fictif, de le connecter et de mémoriser son compte.
        email = f"user-{uuid.uuid4().hex[:10]}@demo.local"
        password = secrets.token_urlsafe(16)  # compte fictif jetable : aucun mot de passe écrit dans le dépôt
        status, _ = call(self.base, "POST", "/api/auth/register", {"email": email, "full_name": "Utilisateur Démo", "password": password})
        if status not in (201, 409):
            return
        status, body = call(self.base, "POST", "/api/auth/login", {"email": email, "password": password})
        if status != 200 or not isinstance(body, dict):
            return
        token = body.get("access_token", "")
        status, account = call(self.base, "GET", "/api/payments/accounts/me", token=token)
        if status == 200 and isinstance(account, dict):
            with self._lock:
                self.accounts.append((account["account_number"], token))

    def act(self, decision):
        # Cette méthode permet d'exécuter une action utilisateur à partir d'une décision tirée À L'AVANCE par
        # l'ordonnanceur (aucun tirage aléatoire ici : la suite aléatoire reste reproductible).
        with self._lock:
            accounts = list(self.accounts)
        if len(accounts) < 3 or decision["new_user"] < 0.12:
            self.register_user()
            return
        number, token = accounts[int(decision["account"] * len(accounts))]
        if decision["kind"] < 0.45:
            call(self.base, "GET", "/api/payments/accounts/me", token=token)
        elif decision["kind"] < 0.65:
            call(self.base, "GET", "/api/payments/transfers?limit=20", token=token)
        else:
            others = [a for a in accounts if a[0] != number]
            target = others[int(decision["target"] * len(others))][0]
            call(self.base, "POST", "/api/payments/transfers",
                 {"to_account_number": target, "amount_cents": decision["amount"], "label": "Achat"},
                 token=token, headers={"Idempotency-Key": uuid.uuid4().hex})


def draw_decision(rng):
    # Cette méthode permet de tirer, dans un ordre fixe, toutes les valeurs aléatoires d'une action utilisateur.
    return {"new_user": rng.random(), "account": rng.random(), "kind": rng.random(),
            "target": rng.random(), "amount": rng.randint(50, 5000)}


def load_profile(elapsed, total, rng_phase):
    # Cette méthode permet de calculer le nombre de requêtes à lancer cette seconde (débit variable + périodes creuses).
    # Périodes creuses : ~25 s toutes les ~150 s, pour apprendre que l'inactivité est normale.
    if (elapsed % 150) >= 125:
        return 0
    base = 4.0 + 3.0 * math.sin(2 * math.pi * (elapsed / 90.0) + rng_phase)
    return max(0, int(round(base)))


class Scheduler:
    """Lance les actions dans des threads en bornant le travail en vol (aucune file d'attente)."""

    def __init__(self, action, max_in_flight):
        # Cette méthode permet de préparer l'ordonnanceur : `action(decision)` est exécutée dans un thread dédié.
        self.action = action
        self.slots = threading.BoundedSemaphore(max_in_flight)
        self.threads = []
        self.started = 0
        self.skipped = 0

    def submit(self, decision):
        # Cette méthode permet de lancer une action si un emplacement est libre, sinon de l'ignorer (et la compter).
        if not self.slots.acquire(blocking=False):
            self.skipped += 1
            return False

        def run():
            try:
                self.action(decision)
            finally:
                self.slots.release()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.threads = [t for t in self.threads if t.is_alive()] + [thread]
        self.started += 1
        return True

    def drain(self, timeout):
        # Cette méthode permet d'attendre la fin des seules requêtes déjà en vol, dans un délai borné.
        deadline = time.time() + timeout
        for thread in self.threads:
            thread.join(max(0.0, deadline - time.time()))


def main():
    # Cette méthode permet de dérouler la génération de trafic normal pendant la durée demandée.
    parser = argparse.ArgumentParser(description="Génère du trafic normal contre la stack locale.")
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--duration", type=int, default=900, help="durée en secondes")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-in-flight", type=int, default=24, help="actions simultanées au plus (au-delà : ignorées)")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    phase = rng.uniform(0, 2 * math.pi)
    population = Population(args.base.rstrip("/"))
    for _ in range(4):
        population.register_user()

    print(f"Trafic normal vers {args.base} pendant {args.duration}s (seed={args.seed})", flush=True)
    scheduler = Scheduler(population.act, args.max_in_flight)
    start = time.time()
    while time.time() - start < args.duration:
        tick = time.time()
        elapsed = int(tick - start)
        count = load_profile(elapsed, args.duration, phase)
        for _ in range(count):
            scheduler.submit(draw_decision(rng))  # tirage dans l'ordonnanceur, même si l'action est ignorée
        if elapsed % 30 == 0:
            print(f"  t={elapsed}s débit≈{count}/s comptes={len(population.accounts)} "
                  f"lancées={scheduler.started} ignorées={scheduler.skipped}", flush=True)
        # On cale sur la seconde suivante, sans dépasser la durée demandée.
        time.sleep(max(0.0, min(1.0 - (time.time() - tick), args.duration - (time.time() - start))))
    scheduler.drain(REQUEST_TIMEOUT * 4)
    print(f"Terminé : {scheduler.started} actions lancées, {scheduler.skipped} ignorées (saturation) "
          f"en {int(time.time() - start)}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
