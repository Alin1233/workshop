# Red Team Report — RESILIENCE-ALPHA (workshop EPSI)

- **Operator:** alin.herciu@leasecom.fr (Red Team, authorized workshop)
- **Target (authorized, own SI):** http://172.16.147.10:8080
- **Date (UTC):** 2026-10-19T13:20:14Z
- **Scope:** ONLY 172.16.147.10, each active run ≤60s, non-destructive. Enforced by `attacks/_lib/guard.sh` (nets `192.168.137.` + `172.16.147.`).
- **Raw evidence:** `attacks/logs/recon-curl-*`, `attacks/logs/probe-*`, `attacks/logs/bruteforce-20261019-151844/`, `attacks/logs/sqli-20261019-151903/`, `attacks/logs/redteam-run-20261019T132014Z/`

---

## 1. Executive summary

The published attack surface (the single WAF-fronted entry point on `:8080`) is **well hardened**. Active probing found **no exploitable high/critical flaw reachable from the attacker PC**. The OWASP CRS WAF reliably blocks SQLi, XSS and command-injection (403), all management/observability ports are unreachable from the attacker (bound to `127.0.0.1` on the Hôte), the API enforces JWT (RS256, audience/issuer checked), IDOR ownership checks, and admin role-gating, and the database layer is fully parameterized (no injectable parameter — sqlmap 403×90).

The real findings are **configuration / defense-in-depth gaps**, the two most significant being **plaintext HTTP only (no TLS)** on a payment SI and **no login rate-limiting / account lockout** (brute-force defense is detection-only, which could not be confirmed from the attacker side). All other findings are Low/Info (exposed OpenAPI docs, missing CSP, open self-registration, image/dependency version hygiene).

**Bottom line: the SI is holding under the authorized envelope.** The honest result is a short list of hardening items, not a compromise.

---

## 2. What was run (commands + tooling)

### Tool availability (correction to the brief)
| Tool | State | Note |
|---|---|---|
| curl, sqlmap, docker, npm, python3, git | **present** | used |
| **nmap, ffuf, hydra, hping3** | **present** (brief said missing) | available, but flood/DoS deliberately NOT run against the live service |
| slowhttptest | **missing** | L7 DoS vector not runnable here |
| trivy, grype | **missing** | SCA not runnable; also no local image access (remote target) |

### Active runs (all ≤60s, against 172.16.147.10 only)
1. `curl` recon — root headers, `/health`, OpenAPI enumeration, management-port reachability, TLS check.
2. `curl` authz/CORS/error-verbosity/method probes (`scratchpad/probe2.sh`).
3. `curl` WAF efficacy probes — SQLi / XSS / cmd-injection / traversal payloads (`scratchpad/waf.sh`).
4. `attacks/02-bruteforce-login/bruteforce.sh` (MODE=json, 20-pw default wordlist, ~2 req/s).
5. `attacks/03-sqli/sqli.sh "http://172.16.147.10:8080/api/payments/accounts?id=1"` (sqlmap `--level 1 --risk 1`, capped 65s).
6. Static review of repo: `docker-compose.yml`, service source (`services/*`), `nginx.conf`, WAF config, `requirements.txt`, `package.json`, secrets handling.

### API surface discovered (via exposed OpenAPI)
- **auth-service** `/api/auth`: `POST /register`, `POST /login`, `GET /me`, `GET /health`, `GET /.well-known/jwks.json`
- **payment-api** `/api/payments`: `GET /accounts/me`, `POST /transfers`, `GET /transfers`, `GET /transfers/{transfer_id}`, `GET /admin/integrity`, `GET /health` (+ internal `/internal/integrity`, `/metrics` — blocked at nginx)

---

## 3. Vulnerabilities / weaknesses found

> Severity reflects the context: a fictional lab payment SI on an internal net. On a real production payment system several of these would rate higher.

### V1 — Plaintext HTTP only; no TLS, no HSTS — **Medium**
- **Evidence:** `curl https://172.16.147.10:8080/` → connection fails (`000`); `:8080` serves plaintext `HTTP/1.1 200 OK`. No `Strict-Transport-Security` header on any response.
- **Affected:** WAF published entry point (`waf` service, `FRONT_PORT 8080`).
- **Impact:** Credentials (POST `/login`) and Bearer JWTs transit in cleartext — interceptable on the LAN (MITM/sniffing). No HSTS to force TLS.
- **Remediation:** Terminate TLS at the WAF (or a fronting proxy), redirect 80/8080→HTTPS, add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.

### V2 — No login rate-limiting / account lockout (detection-only defense) — **Medium**
- **Evidence:** `bruteforce.sh` sent 20 failed logins for `admin@resilience.local`; **all returned HTTP 401**, with **no 429, no 403, no lockout** from the attacker side (`attacks/logs/bruteforce-20261019-151844/bruteforce.log`). No application- or WAF-layer throttling observed at ~2 req/s.
- **Affected:** `POST /api/auth/login`.
- **Impact:** Credential stuffing / brute force is feasible; the only defense is downstream detection (Loki `AuthBruteForce`, Prometheus `LoginFailureSpike`) which **could not be confirmed from the attacker side** (oracle bound to 127.0.0.1 on Hôte). Mitigating factors: argon2id slow hashing and a strong seeded admin password.
- **Remediation:** Add per-IP / per-account rate limiting + temporary lockout (WAF rate rule or app-level, e.g. `limit_req`/a login throttle). Verify the SIEM alert actually fires and routes to the remediation engine.

### V3 — OpenAPI / Swagger UI publicly exposed — **Low**
- **Evidence:** `GET /api/auth/docs` → 200 (Swagger UI); `GET /api/auth/openapi.json`, `GET /api/payments/openapi.json` → 200. Full endpoint map (incl. `GET /admin/integrity`) is disclosed without auth.
- **Affected:** both FastAPI services through the WAF.
- **Impact:** Free reconnaissance — exact routes, parameters, validation rules and admin endpoints handed to an attacker.
- **Remediation:** Disable `/docs` + `/openapi.json` in the published environment (FastAPI `docs_url=None, openapi_url=None`), or gate them behind auth / bind to the internal/mgmt network only (same pattern already used for `/metrics` and `/internal`).

### V4 — Missing Content-Security-Policy header — **Low**
- **Evidence:** root and app responses carry `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` but **no `Content-Security-Policy`**.
- **Affected:** frontend (`nginx.conf`).
- **Impact:** Weaker defense-in-depth against XSS/content injection (React auto-escaping + WAF still apply).
- **Remediation:** Add a restrictive CSP (`default-src 'self'`, explicit `script-src`/`style-src`, etc.) via `add_header` in `nginx.conf`.

### V5 — Open self-registration with auto welcome-credit — **Low**
- **Evidence:** `POST /api/auth/register` is public (code: `services/auth-service/app/main.py`); each new account auto-opens with a 1 000,00 € fictional welcome credit (`services/payment-api/app/ledger.py`, `WELCOME_CREDIT_CENTS = 100_000`). `409` vs `201` distinguishes existing vs new emails (enumeration).
- **Affected:** `/api/auth/register`, account bootstrap.
- **Impact:** Unlimited unverified account creation (resource/ledger inflation), and email-existence enumeration via status code.
- **Remediation:** Require email verification / invite, add registration rate limiting, and return a uniform response for existing vs new emails.

### V6 — Unpinned container image `ollama/ollama:latest` — **Low** (not attacker-reachable → hardening)
- **Evidence:** `docker-compose.yml:227` `image: ollama/ollama:latest`; commented `tecnativa/docker-socket-proxy:latest` also unpinned. All **other** third-party images are version-pinned (postgres:17-alpine, `owasp/modsecurity-crs:4.25-...`, `prom/prometheus:v3.15.0`, `grafana/grafana:13.2.4`, `grafana/loki:3.7.8`, `grafana/alloy:v1.20.1`, `prom/alertmanager:v0.34.1`, `prom/blackbox-exporter:v0.29.0`).
- **Impact:** Tag drift / supply-chain risk on rebuild. Note: Ollama runs only under `--profile ai`, on the internal `ai` network, **not published** — so **not reachable from the attacker** (the known CVE lead on this stack is therefore hardening-only, not exploitable here).
- **Remediation:** Pin Ollama (and docker-socket-proxy when enabled) to a specific tag or digest; scan with trivy/grype before enabling the `ai` profile.

### V7 — Non-reproducible dependency specs (version ranges / `:latest` app tags) — **Low**
- **Evidence:** `services/*/requirements.txt` are ranges (`fastapi>=0.115,<1`, `uvicorn[standard]>=0.30,<1`, `pyjwt[crypto]>=2.9,<3`, …) with no lockfile/hashes; locally built app images tagged `:latest` (`resilience-alpha/*:latest`). Frontend uses caret ranges but ships a `package-lock.json` (pinned at `npm ci`).
- **Impact:** Builds are non-deterministic; a transitive update could silently introduce a vulnerable version; no SCA baseline.
- **Remediation:** Pin Python deps with a lockfile + hashes (pip-tools/uv) and tag app images with an immutable version; run SCA in CI.

### V8 — `Access-Control-Allow-Headers: *` on all responses — **Info**
- **Evidence:** every response (200 and 405) carries `Access-Control-Allow-Headers: *` but **no `Access-Control-Allow-Origin`** is reflected (tested with `Origin: https://evil.example`).
- **Impact:** Misconfiguration/noise only — without an ACAO header browsers will not grant cross-origin reads, so not exploitable as-is.
- **Remediation:** Remove the stray header or configure CORS explicitly with a strict origin allowlist.

### V9 — Minor info disclosure: validation errors echo input — **Info**
- **Evidence:** `POST /api/auth/login` with `{"email":123}` → 422 with the offending `input` value echoed (standard FastAPI/pydantic). No stack traces; errors are clean JSON; DB-down returns a homogeneous 503.
- **Impact:** Negligible.
- **Remediation:** Optional — strip `input` echo from 422 responses in production.

---

## 4. Hardening confirmed (tested, holding)

- **SQL injection:** fully parameterized queries in all services (`%s` / named params, psycopg) **and** WAF 403 — sqlmap reported `GET parameter 'id' does not seem to be injectable`, `403 (Forbidden) - 90 times`.
- **WAF (OWASP CRS, PARANOIA 1, anomaly 5):** SQLi (UNION / `OR 1=1` / in POST body), XSS, and command-injection payloads all → **403**.
- **JWT:** RS256, decoded with explicit `algorithms=["RS256"]`, `audience`, `issuer` — no alg-confusion / `none` bypass. Private key mounted as Docker secret; JWKS public key exposure is by-design.
- **Authorization:** all protected endpoints → 401 without token; `GET /admin/integrity` role-gated (403 for non-admin); `GET /transfers/{id}` enforces sender/recipient ownership (IDOR-safe in code).
- **Password handling:** argon2id + constant-time dummy-hash to avoid user-enumeration timing; min length 10.
- **Management plane isolation:** ports 9090/9093/3100/3000/11434/5432/12345 all **unreachable** from the attacker (connection refused) — bound to `127.0.0.1` (Hôte) per compose.
- **Internal endpoints:** `/api/*/metrics` and `/api/*/internal*` → **404** at nginx (regex block).
- **Log-spoofing defense:** nginx **overwrites** `X-Forwarded-For` with `$remote_addr` and only trusts `X-Real-IP` from the WAF subnet (172.31.250.0/24) — attacker cannot forge the logged client IP.
- **Container hardening:** `no-new-privileges`, `cap_drop: ALL`, `read_only` rootfs + tmpfs, non-root UID 10001, `internal` networks, Docker secrets, SOPS/age-encrypted secrets, nothing sensitive committed to git.
- **Headers/banners:** `server_tokens off`, `SERVER_HEADER ""` (no server/version banner), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`; TRACE → 405.
- **Service stayed healthy** throughout testing (`/api/auth/health` and `/api/payments/health` → `{"status":"ok","checks":{"database":true}}` after all runs).

---

## 5. What could NOT be tested (and why)

- **Observability oracle (the completion criterion's "Detected" step):** Prometheus (9090), Alertmanager (9093), Loki (3100), Grafana (3000) are bound to `127.0.0.1` on the **remote Hôte** — unreachable from the attacker PC. **Cannot confirm** that `AuthBruteForce` / `LoginFailureSpike` (brute force) or `WafAttackBlocked` (SQLi) alerts actually fired. Confirm on the Hôte.
- **SCA / CVE inventory:** `trivy`/`grype` not installed, and the target is remote (no local image access). Cannot enumerate CVEs in the **running** image versions. **No CVEs were fabricated.** Run SCA on the Hôte against the built images.
- **CVE exploit path:** without a running-image inventory and a confirmed reachable+PoC-backed CVE, no exploit was authored (per skill discipline). The `ollama:latest` lead is profile-gated and unpublished → not reachable.
- **L7 DoS (headline vector):** `slowhttptest` not installed. `hping3`/`nmap` ARE present, but flooding a live shared service was deliberately avoided (scope: "do not disrupt the live service"). Not run.

---

## 6. Next steps for the Hôte-side operator

1. **Confirm the oracle** for the runs already executed: on the Hôte, query
   `curl -s http://127.0.0.1:9093/api/v2/alerts | grep -o '"alertname":"[^"]*"' | sort -u`
   and Prometheus `:9090/api/v1/alerts` / Loki `:3100` — verify `AuthBruteForce`/`LoginFailureSpike` (from the brute-force run at 13:18Z) and `WafAttackBlocked` (SQLi run at 13:19Z) fired. A vector that fires **no** alert is itself a detection-gap finding.
2. **Run SCA:** `trivy image` / `grype` on `resilience-alpha/*:latest`, `owasp/modsecurity-crs:4.25-...`, `postgres:17-alpine`, `grafana/*`, `prom/*`, and `ollama/ollama:latest` — triage HIGH/CRITICAL with fixed-in versions; feed the real running versions back into the CVE path.
3. **Run the L7 DoS** once `slowhttptest` is installed (`attacks/01-dos-applicatif/dos.sh 172.16.147.10 8080 30`), confirm `HighLatencyP95`/`HighErrorRate`/`EndToEndProbeFailed`/`ServiceDown`, then `attacks/clip-chrono.sh` for the autonomous-recovery proof (smoke test green after incident).
4. **Fix V1/V2 first:** add TLS+HSTS at the WAF and login rate-limiting/lockout.
5. **Then V3–V7:** disable public OpenAPI docs, add CSP, gate/verify registration, pin `ollama` by digest, pin Python deps with a lockfile + hashes.
