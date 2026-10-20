"""Test de bout en bout du SI de paiement, à lancer contre la stack démarrée (stdlib uniquement).

Usage : python tests/smoke_test.py [http://127.0.0.1:8080]
Sert aussi de « transaction témoin » pour prouver que le service est rétabli après une remédiation.
"""

import base64
import hashlib
import hmac
import json
import secrets
import struct
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
# Secret TOTP du compte admin (double authentification imposée), généré par scripts/init_secrets.py.
ADMIN_TOTP_FILE = Path(__file__).resolve().parent.parent / "secrets" / "admin_totp_secret"
RESULTS: list[tuple[bool, str]] = []
# Capture JPEG 16 × 16 unie, sans visage : vérifie que le WAF laisse passer l'envoi multipart de la reconnaissance faciale
# et que les modèles tournent (refus métier face_not_detected, et non un 403 du WAF).
BLANK_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDABsSFBcUERsXFhceHBsgKEIrKCUlKFE6PTBCYFVlZF9VXVtqeJmBanGQc1tdhbWGkJ6jq62rZ4C8ybqmx5mo"
    "q6T/2wBDARweHigjKE4rK06kbl1upKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKT/wAARCAAQABADASIAAhEB"
    "AxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS"
    "0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKz"
    "tLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgEC"
    "BAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpj"
    "ZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6"
    "/9oADAMBAAIRAxEAPwAooooA/9k=")


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


def post_frames(path: str, fields: dict, frames: list[bytes], token: str | None = None):
    # Cette méthode permet d'envoyer des captures JPEG en multipart/form-data, comme le navigateur (champ « frames »),
    # et de renvoyer (statut, corps décodé) sans lever sur 4xx/5xx.
    boundary = uuid.uuid4().hex
    crlf = "\r\n"
    parts = [f'--{boundary}{crlf}Content-Disposition: form-data; name="{name}"{crlf}{crlf}{value}{crlf}'.encode()
             for name, value in fields.items()]
    for i, frame in enumerate(frames):
        head = (f'--{boundary}{crlf}Content-Disposition: form-data; name="frames"; filename="pose-{i + 1}.jpg"{crlf}'
                f"Content-Type: image/jpeg{crlf}{crlf}")
        parts.append(head.encode() + frame + crlf.encode())
    body = b"".join(parts) + f"--{boundary}--{crlf}".encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
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


def totp(secret: str, offset_steps: int = 0) -> str:
    # Cette méthode permet de calculer le code TOTP (RFC 6238 : HMAC-SHA1, pas de 30 s, 6 chiffres) d'un secret base32,
    # comme l'afficherait l'appli d'authentification, sans dépendance hors stdlib.
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time() // 30) + offset_steps), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def login_with_totp(email: str, password: str, secret: str) -> tuple[int, dict]:
    # Cette méthode permet de se connecter à un compte à double authentification ; si le code du pas courant a déjà servi
    # (exécution rapprochée), elle attend le pas suivant et recommence avec une nouvelle étape.
    for attempt in range(2):
        status, challenge = call("POST", "/api/auth/login", {"email": email, "password": password})
        if status != 200 or not challenge.get("mfa_required"):
            return status, challenge
        status, body = call("POST", "/api/auth/login/mfa", {"mfa_token": challenge["mfa_token"], "code": totp(secret)})
        if status == 200 or attempt or body.get("code") != "mfa_invalid_code":
            return status, body
        time.sleep(30 - time.time() % 30 + 0.5)
    return status, body


def mfa_scenario() -> None:
    # Cette méthode permet de vérifier la double authentification d'un client de bout en bout : activation,
    # connexion en deux étapes, refus d'un mauvais code, code de secours à usage unique, désactivation.
    email = f"mfa-{uuid.uuid4().hex[:8]}@demo.local"
    password = secrets.token_urlsafe(18)
    call("POST", "/api/auth/register", {"email": email, "full_name": "Mfa", "password": password})
    token = call("POST", "/api/auth/login", {"email": email, "password": password})[1].get("access_token")
    status, setup = call("POST", "/api/auth/mfa/setup", token=token)
    check(status == 200 and setup.get("qr_code", "").startswith("data:image/svg+xml"), "secret TOTP et QR code générés")
    # Activation avec le code du pas précédent (toléré) : celui du pas courant reste libre pour la connexion.
    status, activated = call("POST", "/api/auth/mfa/activate", {"code": totp(setup["secret"], -1)}, token)
    codes = activated.get("recovery_codes", []) if isinstance(activated, dict) else []
    check(status == 200 and len(codes) == 10, "activation -> 10 codes de secours")
    status, challenge = call("POST", "/api/auth/login", {"email": email, "password": password})
    check(status == 200 and challenge.get("mfa_required") and "access_token" not in challenge, "mot de passe seul -> étape « code », sans jeton")
    status, body = call("POST", "/api/auth/login/mfa", {"mfa_token": challenge["mfa_token"], "code": "000000"})
    check(status == 401 and body.get("code") == "mfa_invalid_code", "mauvais code -> 401")
    status, body = call("POST", "/api/auth/login/mfa", {"mfa_token": challenge["mfa_token"], "code": totp(setup["secret"])})
    check(status == 200 and "access_token" in body, "code TOTP valide -> jeton")
    challenge = call("POST", "/api/auth/login", {"email": email, "password": password})[1]
    status, body = call("POST", "/api/auth/login/mfa", {"mfa_token": challenge["mfa_token"], "code": codes[0]})
    check(status == 200, "code de secours -> jeton")
    token = body.get("access_token")
    face_scenario(token, codes[2])
    status, _ = call("POST", "/api/auth/mfa/disable", {"password": password, "code": codes[0]}, token)
    check(status == 400, "code de secours déjà utilisé -> refusé")
    status, _ = call("POST", "/api/auth/mfa/disable", {"password": password, "code": codes[1]}, token)
    check(status == 204 and "access_token" in call("POST", "/api/auth/login", {"email": email, "password": password})[1],
          "désactivation -> connexion par mot de passe seul")


def face_scenario(token: str, code: str) -> None:
    # Cette méthode permet de vérifier la chaîne de la reconnaissance faciale à travers le WAF : défi de pose tiré par
    # l'auth-service après le code, envoi multipart des trois captures accepté par le WAF et nginx, analyse par les
    # modèles (refus).
    status, challenge = call("POST", "/api/auth/mfa/face/challenge", {"code": code, "consent": True}, token=token)
    poses = challenge.get("poses", []) if isinstance(challenge, dict) else []
    check(status == 200 and len(poses) == 3 and poses[0] == "center", f"visage : défi de pose tiré {poses}")
    status, body = post_frames("/api/auth/mfa/face", {"challenge_id": challenge.get("challenge_id", "")},
                               [BLANK_JPEG] * 3, token)
    check(status == 400 and isinstance(body, dict) and body.get("code") == "face_not_detected",
          f"visage : captures sans visage -> 400 face_not_detected, multipart accepté par le WAF (reçu {status})")
    status, body = call("GET", "/api/auth/mfa/face", token=token)
    check(status == 200 and body.get("enrolled") is False, "visage : rien d'enregistré après un refus")


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

    print("\n[Double authentification]")
    mfa_scenario()

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
    if ADMIN_PASSWORD_FILE.exists() and ADMIN_TOTP_FILE.exists():
        password = ADMIN_PASSWORD_FILE.read_text().strip()
        status, challenge = call("POST", "/api/auth/login", {"email": "admin@resilience.local", "password": password})
        check(status == 200 and challenge.get("mfa_required") is True, "admin : mot de passe seul -> code exigé")
        status, body = login_with_totp("admin@resilience.local", password, ADMIN_TOTP_FILE.read_text().strip())
        check(status == 200, "connexion admin (mot de passe + TOTP)")
        status, report = call("GET", "/api/payments/admin/integrity", token=body.get("access_token"))
        check(status == 200 and report.get("ok") is True, f"registre cohérent : {report.get('checks')}")
    else:
        print("  -- secrets/admin_password ou secrets/admin_totp_secret absent : contrôle admin ignoré")

    failed = [label for ok, label in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} vérifications OK en {time.perf_counter() - started:.1f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
