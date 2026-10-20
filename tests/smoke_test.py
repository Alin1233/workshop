"""Test de bout en bout du SI de paiement, à lancer contre la stack démarrée (stdlib uniquement).

Usage : python tests/smoke_test.py [http://127.0.0.1:8080]
Sert aussi de « transaction témoin » pour prouver que le service est rétabli après une remédiation.
"""

import json
import secrets
import sys
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080").rstrip("/")
# 127.0.0.1 plutôt que localhost : sous Windows, « localhost » tente d'abord IPv6 (≈1 s perdue par requête).
ADMIN_PASSWORD_FILE = Path(__file__).resolve().parent.parent / "secrets" / "admin_password"
RESULTS: list[tuple[bool, str]] = []


def call(method: str, path: str, body: dict | None = None, token: str | None = None, headers: dict | None = None):
    # Cette méthode permet d'envoyer une requête HTTP JSON et de renvoyer (statut, corps décodé) sans lever sur 4xx/5xx.
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return res.status, json.loads(res.read() or b"null")
    except urllib.error.HTTPError as err:
        raw = err.read()
        try:
            return err.code, json.loads(raw)
        except ValueError:
            return err.code, raw.decode(errors="replace")


def check(condition: bool, label: str) -> None:
    # Cette méthode permet d'enregistrer et d'afficher le résultat d'une vérification.
    RESULTS.append((condition, label))
    print(f"  {'OK ' if condition else 'KO '} {label}")


def new_user(prefix: str) -> tuple[str, str]:
    # Cette méthode permet de créer un utilisateur fictif unique puis de renvoyer son jeton et son numéro de compte.
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@demo.local"
    password = secrets.token_urlsafe(18)   # tiré à chaque exécution : aucun mot de passe écrit dans le dépôt
    status, _ = call("POST", "/api/auth/register", {"email": email, "full_name": prefix.capitalize(), "password": password})
    check(status == 201, f"inscription {prefix} -> 201 (reçu {status})")
    status, body = call("POST", "/api/auth/login", {"email": email, "password": password})
    check(status == 200 and "access_token" in body, f"connexion {prefix} -> jeton")
    token = body.get("access_token", "") if isinstance(body, dict) else ""
    status, account = call("GET", "/api/payments/accounts/me", token=token)
    opened = status == 200 and isinstance(account, dict) and account["balance_cents"] == 100_000
    check(opened, f"compte {prefix} ouvert avec 1 000,00 € (statut {status})")
    if not opened:
        sys.exit(f"Arrêt : impossible de préparer le compte {prefix} ({status} {account})")
    return token, account["account_number"]


def balance(token: str) -> int:
    # Cette méthode permet de lire le solde courant d'un utilisateur.
    return call("GET", "/api/payments/accounts/me", token=token)[1]["balance_cents"]


def main() -> int:
    # Cette méthode permet de dérouler le scénario métier complet et de renvoyer 0 si tout est conforme.
    print(f"Cible : {BASE}")
    started = time.perf_counter()

    print("\n[Disponibilité]")
    for service in ("auth", "payments"):
        status, body = call("GET", f"/api/{service}/health")
        check(status == 200 and body.get("status") == "ok", f"/api/{service}/health -> ok")

    print("\n[Comptes]")
    alice, alice_acc = new_user("alice")
    bob, bob_acc = new_user("bob")

    print("\n[Virement et idempotence]")
    key = uuid.uuid4().hex
    status, transfer = call("POST", "/api/payments/transfers", {"to_account_number": bob_acc, "amount_cents": 2550, "label": "Test"},
                            alice, {"Idempotency-Key": key})
    check(status == 201, f"virement alice -> bob 25,50 € -> 201 (reçu {status})")
    status, replay = call("POST", "/api/payments/transfers", {"to_account_number": bob_acc, "amount_cents": 2550, "label": "Test"},
                          alice, {"Idempotency-Key": key})
    check(status == 200 and replay.get("id") == transfer.get("id"), "même clé rejouée -> même virement, pas de second débit")
    check(balance(alice) == 100_000 - 2550 and balance(bob) == 100_000 + 2550, "soldes cohérents après rejeu")
    status, body = call("POST", "/api/payments/transfers", {"to_account_number": bob_acc, "amount_cents": 999}, alice, {"Idempotency-Key": key})
    check(status == 422 and body.get("code") == "idempotency_key_reused", "même clé, autre montant -> 422")

    print("\n[Règles métier]")
    status, body = call("POST", "/api/payments/transfers", {"to_account_number": bob_acc, "amount_cents": 1_000_000},
                        alice, {"Idempotency-Key": uuid.uuid4().hex})
    check(status == 422 and body.get("code") == "insufficient_funds", "solde insuffisant -> 422")
    status, body = call("POST", "/api/payments/transfers", {"to_account_number": "RA0000000000", "amount_cents": 100},
                        alice, {"Idempotency-Key": uuid.uuid4().hex})
    check(status == 404, "bénéficiaire inconnu -> 404")
    status, body = call("POST", "/api/payments/transfers", {"to_account_number": alice_acc, "amount_cents": 100},
                        alice, {"Idempotency-Key": uuid.uuid4().hex})
    check(status == 422 and body.get("code") == "same_account", "virement vers soi-même -> 422")
    status, _ = call("POST", "/api/payments/transfers", {"to_account_number": bob_acc, "amount_cents": -5},
                     alice, {"Idempotency-Key": uuid.uuid4().hex})
    check(status == 422, "montant négatif -> 422")

    print("\n[Contrôle d'accès]")
    check(call("GET", "/api/payments/accounts/me")[0] == 401, "sans jeton -> 401")
    check(call("GET", "/api/payments/accounts/me", token=alice[:-4] + "AAAA")[0] == 401, "jeton altéré -> 401")
    check(call("GET", "/api/payments/admin/integrity", token=alice)[0] == 403, "client sur route admin -> 403")
    check(call("GET", f"/api/payments/transfers/{transfer['id']}", token=bob)[0] == 200, "bénéficiaire voit le virement")
    check(call("POST", "/api/auth/login", {"email": "inconnu@demo.local", "password": "bad"})[0] == 401, "mauvais identifiants -> 401")
    check(call("GET", "/api/payments/metrics")[0] == 404, "/metrics non exposé publiquement")
    check(call("GET", "/api/payments/internal/integrity")[0] == 404, "/internal non exposé publiquement")

    print("\n[Concurrence : 40 virements croisés simultanés]")

    def cross(i: int) -> int:
        # Cette méthode permet d'émettre un virement de 1 € dans un sens ou dans l'autre selon la parité.
        sender, target = (alice, bob_acc) if i % 2 else (bob, alice_acc)
        return call("POST", "/api/payments/transfers", {"to_account_number": target, "amount_cents": 100},
                    sender, {"Idempotency-Key": uuid.uuid4().hex})[0]

    with ThreadPoolExecutor(max_workers=20) as pool:
        statuses = list(pool.map(cross, range(40)))
    check(all(s == 201 for s in statuses), f"40/40 virements acceptés (statuts : {sorted(set(statuses))})")
    check(balance(alice) + balance(bob) == 200_000, "masse monétaire alice + bob conservée")
    status, history = call("GET", "/api/payments/transfers?limit=100", token=alice)
    check(status == 200 and len(history) == 1 + 1 + 40, f"historique alice complet ({len(history)} lignes)")

    print("\n[Intégrité du registre]")
    if ADMIN_PASSWORD_FILE.exists():
        status, body = call("POST", "/api/auth/login", {"email": "admin@resilience.local", "password": ADMIN_PASSWORD_FILE.read_text().strip()})
        check(status == 200, "connexion admin")
        status, report = call("GET", "/api/payments/admin/integrity", token=body.get("access_token"))
        check(status == 200 and report.get("ok") is True, f"registre cohérent : {report.get('checks')}")
    else:
        print("  -- secrets/admin_password absent : contrôle admin ignoré")

    failed = [label for ok, label in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} vérifications OK en {time.perf_counter() - started:.1f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
