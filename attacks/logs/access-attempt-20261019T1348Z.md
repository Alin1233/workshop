# Access-attempt report — RESILIENCE-ALPHA (own SI)

- **Date (UTC):** 2026-10-19, 13:42–13:48
- **Target (authorized, own SI):** `http://172.16.147.10:8080`
- **Scope:** own SI only, web entry point `:8080`, non-destructive except the already-recorded L7 windows below. Guard `attacks/_lib/guard.sh` in force (`192.168.137.0/24`, `172.16.147.0/24`).
- **Question asked:** can an attacker on the group LAN reach the application source code or the PostgreSQL data through the published surface?
- **Short answer:** **No.** The published surface is hardened; no code/DB access was obtained. The only open ports are SSH (publickey-only) and the WAF. The DB, Docker API, management ports and internal endpoints are not reachable. No SQLi, IDOR, auth bypass, path traversal or race condition was found. This is a hardening result, not a compromise.

> If `172.16.147.10` is **not** your own group's Hôte, stop here: the workshop subject and `attacks/README.md` put other groups and third-party systems out of scope.

---

## 1. Baseline and evidence

| Step | UTC | Result | Evidence |
|---|---|---|---|
| Recon (ping, HTTP headers, nmap `-Pn`) | 13:42:20–13:42:24 | Host up; `22/tcp` open (OpenSSH 10.0p2 Debian), `8080/tcp` open (WAF/nginx); all other probed ports filtered | `attacks/logs/recon-20261019-154220/` |
| Witness baseline (`tests/smoke_test.py`) | 13:42:5x | **26/26 OK** (auth, accounts, transfer, idempotence, authz, 40 concurrent transfers, ledger integrity) | console output |
| Business-logic/BOLA (`05-business-logic/abuse.sh`) | 13:43:11–13:43:13 | **12 blocked, 0 potential issues** | `attacks/logs/bizlogic-20261019-154311/abuse.log` |
| SQLi (`03-sqli/sqli.sh`, real `limit` parameter) | 13:46:29–13:46:32 | sqlmap: no injectable parameter; **403 × 90** from WAF | `attacks/logs/sqli-20261019-154629/sqli.log` |
| Login brute force (`02-bruteforce-login/`) | 13:46:35–13:46:46 | 20/20 → **401**, no 429/403/lockout; no credential hit | `attacks/logs/bruteforce-20261019-154635/bruteforce.log` |
| Extended port scan | 13:47 | Only `22` and `8080`; `2375/2376` (Docker), `5432` (Postgres), `3000/3100/9090/9093` (mgmt), `8000`, `11434` all filtered | this report |
| SSH key check | 13:48 | `publickey` only; local default key → **Permission denied** | this report |

### L7 DoS already landed earlier (for context, not re-run)
Two reproducible slow-read windows, attacker-side evidence only:
- W3: attack 13:28:35–13:29:34, outage 13:28:52–13:29:28, smoke 26/26 after.
- W4: attack 13:30:18–13:31:17, outage 13:30:35–13:31:14, smoke 26/26 after.
See `attacks/logs/dos-demo-report-20261019T133216Z.md` and `dos-W3-*`, `dos-W4-*`.

---

## 2. Additional checks performed (all held)

### 2.1 Internal endpoints and path normalization
Tried, through the WAF, all returned **404** (nginx block):
`/api/payments/internal/integrity`, `//internal/integrity`, `/./internal/integrity`, `/%2e/internal/integrity`, `/%69nternal/integrity`, `/internal%2fintegrity`, `/internal/integrity/`, `/../payments/internal/integrity`, `/%2e%2e/payments/internal/integrity`; same for `/metrics` variants.
**Result:** internal integrity/metrics stay unreachable from the attacker PC. `GET /api/payments/admin/integrity` without a token → **401**, with a client token → **403**.

### 2.2 Auth and authorization
- `alg=none` + `role=admin` forgery → **401**.
- Client token on `/admin/integrity` → **403**, even with spoofed `X-User`, `X-Role`, `X-Remote-User`, `Host`, or `X-Forwarded-For`/`X-Real-IP` headers.
- `GET /api/payments/accounts/me?foo=bar` → 200 (extra query ignored); `limit=1'` → **422** (integer parsing before DB); `limit=1 OR 1=1` → **403** (WAF); transfer UUID with `'` → **422**; no SQL string concatenation in the services.
- `OPTIONS /api/payments/transfers` → 405; `TRACE /` → 405.

### 2.3 Concurrency / money integrity (custom probe)
- 12 parallel first accesses on a fresh account → exactly **one** 1 000,00 € welcome credit.
- Two concurrent 60 000-cent transfers from a 100 000-cent account → one 201 + one 422 `insufficient_funds`; balance 40 000, never negative.
- Same idempotency key, concurrent identical transfers → 201 + 200, **one** debit, same transfer id.
- Same key, concurrent different amounts → 201 + 422, one debit.
**Result:** no double-spend, no minting, no race-induced balance corruption.

### 2.4 Read-only recon of the DB/code path
- PostgreSQL `5432`, Docker API `2375/2376`, app port `8000`, and all management/LLM ports are **filtered** from the attacker PC.
- The DB is on an `internal` Docker network, one role/database per service (`db/init/01-create-service-databases.sh`); `auth_svc` cannot read `paydb` and vice versa.
- No secrets are tracked in Git (`secrets/*` and `.env` ignored; no private key in history). The JWT private key is a Docker secret; only the public JWKS is published.
- No path in the app exposes files or executes shell commands.

---

## 3. Findings (hardening, not compromise)

| # | Finding | Severity | Evidence / note |
|---|---|---|---|
| V1 | Plain HTTP only, no TLS/HSTS on a payment SI | Medium | `:8080` is HTTP; credentials and JWTs transit in clear on the LAN. Terminate TLS at the WAF and add HSTS. |
| V2 | No login rate limiting / account lockout | Medium | 20 failed admin logins → 20×401, no 429/403/lockout. WAF/CRS is detection-only here. Add per-IP/per-account throttling; argon2id + random admin password mitigate. |
| V3 | OpenAPI/Swagger publicly exposed | Low | `/api/auth/docs`, `/api/auth/openapi.json`, `/api/payments/docs`, `/api/payments/openapi.json` → 200. Disable or gate. |
| V4 | Missing CSP | Low | `X-Frame-Options`, `nosniff`, `Referrer-Policy` present; no `Content-Security-Policy`. |
| V5 | Open self-registration + automatic welcome credit | Low | Public `/register`, 1 000 € per new account; 409 vs 201 enables email enumeration. Add verification/rate limit. |
| V6 | `ollama/ollama:latest` unpinned | Low | Profile `ai` only, not published; hardening/supply-chain item. |
| V7 | Python dependency ranges, no lockfile/hashes | Low | `requirements.txt` ranges; builds non-deterministic. Pin/lock + SCA. |
| V8 | `Access-Control-Allow-Headers: *` without ACAO | Info | Not exploitable as-is; remove or configure CORS explicitly. |
| V9 | SSH exposed on the group LAN | Low | `22/tcp` open, publickey-only, no host access with the local key. Restrict to management network / firewall if not needed. |

---

## 3bis. Admin brute-force attempt (extended wordlist) — no compromise

- **Run:** 14:09:26–14:10:16Z, `attacks/02-bruteforce-login/bruteforce.sh` with an 85-entry curated wordlist (team/workshop-themed + common passwords) against `admin@resilience.local`.
- **Result:** **85/85 → HTTP 401**, no 200, no lockout, no 429 (details: `attacks/logs/bruteforce-20261019-160926/bruteforce.log`).
- **Why this cannot succeed by design:** `scripts/init_secrets.py` sets the admin password to `secrets.token_urlsafe(24)` (~192 bits of entropy). A wordlist of any realistic size has a negligible hit probability; unbounded brute force is a self-inflicted DoS with no expected payoff.
- **Legitimate admin access (operator path, Hôte only):** read `secrets/admin_password` in the deployment directory, or from the container where permitted: `docker compose exec auth-service cat /run/secrets/admin_password`.
- **Expected detection for this run:** `AuthBruteForce` (Loki, >10 failures/min per IP) and `LoginFailureSpike` (Prometheus) — confirm on the Hôte.

### Auth-service outage observed during the session (13:58–14:09Z)

- `GET /api/auth/health` hung and nginx returned 503 after 15s; `/api/auth/docs` (static) stayed 200; `/api/auth/.well-known/jwks.json` timed out. `/api/payments/health` stayed 200 throughout, so Postgres/payment API were fine.
- `tests/smoke_test.py` failed at that moment (exit 1, timeout on `/api/auth/health`).
- **Self-recovered by 14:09:00Z** (`auth_health=200`, watch log `/tmp/opencode/auth_watch.log`); smoke test 26/26 immediately before and after.
- Last attacker-side auth activity before the outage was the 20-request brute-force run at 13:46:46Z; the outage was first observed ~12 minutes later. Whether it was caused by that run, a host-side action, or an auth-service/DB issue is **not established** — check `auth-service` and `postgres` logs on the Hôte before attributing it.

## 4. What could not be confirmed from the attacker PC

- **Named alert / oracle.** Prometheus `:9090`, Alertmanager `:9093`, Loki `:3100`, Grafana `:3000` are bound to `127.0.0.1` on the Hôte and filtered from here. The SQLi run (403×90) and brute-force run (20×401) *should* trip `WafAttackBlocked` and `AuthBruteForce`/`LoginFailureSpike`, but this must be confirmed on the Hôte:

```bash
curl -s http://127.0.0.1:9090/api/v1/alerts | grep -o '"alertname":"[^"]*"' | sort -u
curl -s http://127.0.0.1:9093/api/v2/alerts | grep -o '"alertname":"[^"]*"' | sort -u
```

- **CVE/SCA.** `trivy`/`grype` must run on the Hôte against the built images; no running-image inventory is available from the attacker PC. No CVE was assumed or exploited.
- **Source/DB access.** Not obtained; the only open host service is SSH with publickey auth, and the local key is not authorized.

---

## 5. Recommended next steps

1. On the Hôte, confirm the alerts for the 13:46Z runs (SQLi/brute force) and the 13:28/13:30Z DoS windows.
2. Fix V1/V2 first: TLS + HSTS at the WAF, and login rate limiting/lockout with an automated block response.
3. Then V3–V7: disable public docs, add CSP, gate registration, pin Ollama by digest, lock Python deps and run SCA.
4. For a **data-compromise** demo, use the Hôte-only `attacks/04-integrity-violation/corrupt-ledger.sh` (backup-first) — the DB is intentionally not attacker-reachable, so a web-only scenario cannot honestly demonstrate DB exfiltration without adding a vulnerability.
