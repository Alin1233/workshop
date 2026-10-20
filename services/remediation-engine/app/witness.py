"""Transaction témoin : la preuve qu'un client réel peut de nouveau utiliser le service, à travers le WAF.

Même parcours que tests/smoke_test.py, réduit à l'essentiel : deux utilisateurs neufs s'inscrivent et se connectent,
l'un vire 1,00 € à l'autre avec une clé d'idempotence, puis les deux soldes sont contrôlés. Les identifiants sont générés
à chaque exécution (aucun mot de passe écrit en dur) et les comptes, marqués « temoin-… », ne servent qu'une fois.
"""

import json
import secrets
import time
import urllib.error
import urllib.request
import uuid

OPENING_BALANCE = 100_000   # 1 000,00 € à l'ouverture du compte (services/payment-api)
AMOUNT = 100                 # 1,00 €
USER_AGENT = "resilience-alpha-temoin/1.0 (remediation-engine)"


class WitnessError(RuntimeError):
    """La transaction témoin a échoué : le service n'est pas rétabli du point de vue d'un client."""

    def __init__(self, message: str, steps: list[dict]):
        super().__init__(message)
        self.steps = steps


class Witness:
    """Client HTTP du parcours témoin (inscription, connexion, virement, soldes) à travers le WAF."""

    def __init__(self, base_url: str = "http://waf:8080", timeout: float = 10.0):
        # Cette méthode permet de mémoriser l'adresse du WAF (réseau dmz) et le délai par requête.
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _call(self, method: str, path: str, body: dict | None = None, token: str | None = None,
              headers: dict | None = None) -> tuple[int, object]:
        # Cette méthode permet d'envoyer une requête JSON et de renvoyer (statut, corps décodé) sans lever sur 4xx/5xx.
        request = urllib.request.Request(self.base_url + path, method=method,
                                         data=json.dumps(body).encode() if body is not None else None)
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", USER_AGENT)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, json.loads(response.read() or b"null")
        except urllib.error.HTTPError as err:
            raw = err.read()
            try:
                return err.code, json.loads(raw)
            except ValueError:
                return err.code, raw[:200].decode(errors="replace")
        except (urllib.error.URLError, OSError, ValueError) as err:
            return 0, str(err)

    def run(self) -> dict:
        # Cette méthode permet de dérouler la transaction témoin ; renvoie le détail des étapes, ou lève WitnessError.
        steps: list[dict] = []
        started = time.perf_counter()

        def step(label: str, ok: bool, status: int, **extra) -> None:
            # Cette méthode permet de consigner une étape et d'interrompre le parcours au premier échec.
            steps.append({"step": label, "ok": ok, "status": status, **extra})
            if not ok:
                raise WitnessError(f"transaction témoin en échec à l'étape « {label} » (HTTP {status})", steps)

        def user(role: str) -> tuple[str, str]:
            # Cette méthode permet de créer un utilisateur neuf et de renvoyer (jeton, numéro de compte).
            email = f"temoin-{role}-{uuid.uuid4().hex[:10]}@remediation.local"
            password = secrets.token_urlsafe(18)
            status, _ = self._call("POST", "/api/auth/register",
                                   {"email": email, "full_name": f"Témoin {role}", "password": password})
            step(f"inscription {role}", status == 201, status)
            status, body = self._call("POST", "/api/auth/login", {"email": email, "password": password})
            token = body.get("access_token", "") if isinstance(body, dict) else ""
            step(f"connexion {role}", status == 200 and bool(token), status)
            status, account = self._call("GET", "/api/payments/accounts/me", token=token)
            opened = status == 200 and isinstance(account, dict) and account.get("balance_cents") == OPENING_BALANCE
            step(f"compte {role}", opened, status)
            return token, account["account_number"]

        sender, _ = user("emetteur")
        receiver, receiver_account = user("beneficiaire")
        status, transfer = self._call("POST", "/api/payments/transfers",
                                      {"to_account_number": receiver_account, "amount_cents": AMOUNT,
                                       "label": "Transaction témoin"},
                                      sender, {"Idempotency-Key": uuid.uuid4().hex})
        transfer_id = transfer.get("id") if isinstance(transfer, dict) else None
        step("virement", status == 201 and bool(transfer_id), status, transfer_id=transfer_id)
        balances = {}
        for role, token in (("emetteur", sender), ("beneficiaire", receiver)):
            status, account = self._call("GET", "/api/payments/accounts/me", token=token)
            balances[role] = account.get("balance_cents") if isinstance(account, dict) else None
        ok = balances == {"emetteur": OPENING_BALANCE - AMOUNT, "beneficiaire": OPENING_BALANCE + AMOUNT}
        step("soldes", ok, status, balances=balances)
        return {"transfer_id": transfer_id, "duration_ms": round((time.perf_counter() - started) * 1000), "steps": steps}
