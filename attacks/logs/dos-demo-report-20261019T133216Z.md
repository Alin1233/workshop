# RESILIENCE-ALPHA — L7 DoS Availability Demo Report

- **Run date (UTC):** 2026-10-19
- **Operator:** alin.herciu@leasecom.fr (Red Team, authorized workshop run)
- **Target (authorized, own SI):** http://172.16.147.10:8080
- **Scope:** ONLY 172.16.147.10, each active window ≤60s, single-source, L7 only. No SYN flood. Scope guard `attacks/_lib/guard.sh` in force.
- **Goal:** provoke a real but bounded availability incident, observe degradation, prove self-recovery, and give teammates the exact UTC windows to correlate against Grafana/Alertmanager.

## TL;DR

- **Incident achieved and reproduced (twice).** The vector that lands is slowhttptest **SLOW-READ (`-X`)** against a body-returning endpoint — **not** classic slowloris.
- Classic header-slowloris (`-H`) is **fully mitigated** here even at 4000 connections (front tier absorbs idle slow connections cheaply). That is itself a reportable hardening result.
- Both landed windows caused a **complete outage** (~36–39s of 100% connection timeouts across `/api/health`, `/`, and static assets), then the service **self-recovered with no manual intervention**. Smoke test (`tests/smoke_test.py`) returned 26/26 green after each window.
- **Correlate your alerts against these two windows (UTC):**
  - **Window 3 (first landed):** degraded/down **13:28:52Z → 13:29:28Z** (attack ran 13:28:35Z–13:29:34Z)
  - **Window 4 (reproduction):** degraded/down **13:30:35Z → 13:31:14Z** (attack ran 13:30:18Z–13:31:17Z)

> NOTE: The Prometheus/Alertmanager/Loki oracle is 127.0.0.1-bound on the Hôte and cannot be queried from the attacker PC. This report captures **attacker-side evidence** (timestamps, latency curve, status codes, `/health` transitions, slowhttptest "Service Available" counter) as proof the incident was real, plus the exact windows to match to the alerts that fired on the Hôte.

---

## Baseline (clean before-state)

- `13:24:10Z` — `GET /api/health` → 200 in ~13–20ms; `GET /` → 200 in ~12–15ms (3 samples each).
- `13:24:26Z` — `tests/smoke_test.py http://172.16.147.10:8080` → **26/26 OK in 1.0s** (full payment flow: auth, accounts, transfers, idempotence, authz, 40 concurrent transfers, ledger integrity).
- Note: `GET /health` is a frontend catch-all that serves the SPA `index.html` (200). The real backend liveness probe is **`GET /api/health`** (JSON-backed, ~15ms) — used as the primary health probe throughout.

Service confirmed healthy before attacking.

---

## Attack windows

Probe loop ran a separate curl every ~3s against `/api/health`, `/` (and the asset, W3/W4). `000 TIMEOUT` = connection timed out (curl `-m 8`). slowhttptest's own `Service Available` counter (0 or N of N) is included as an independent availability signal.

### Window 1 — dos.sh default slowloris (NO degradation)
- **Command:** `./01-dos-applicatif/dos.sh 172.16.147.10 8080 30` (slowhttptest `-H -c 300 -i 10 -r 30`, endpoint `/`)
- **Attack UTC:** 13:25:34Z → 13:26:08Z (30s)
- **Result:** no degradation. Latency flat ~11–30ms, all 200 throughout. slowhttptest `Service Available` = **300/300** every second; 0 closed, ~2 pending. Recovery: 0s.
- **Read:** front tier holds 300 slow header-connections with zero cost. Slowloris absorbed.

### Window 2 — escalated slowloris, 4000 conns / 55s (NO degradation)
- **Command:** `slowhttptest -H -c 4000 -i 10 -r 30 -t GET -u http://172.16.147.10:8080/` (= dos.sh vector, raised `-c`)
- **Attack UTC:** 13:26:46Z → 13:27:46Z (55s)
- **Result:** no degradation. Latency flat ~10–53ms, all 200. `Service Available` = **4000/4000** throughout; reached ~1593 concurrent (the `-r 30` ramp capped concurrency), 0 closed. Recovery: 0s.
- **Read:** even scaled up, header-slowloris does not land. Confirms the front tier is async/event-driven and neutralizes slow-header attacks.

### Window 3 — SLOW-READ, 8000 conns / rate 500 / heavy body (INCIDENT — LANDED)
- **Command:** `slowhttptest -X -r 500 -c 8000 -k 3 -n 5 -w 5 -y 15 -z 32 -t GET -u http://172.16.147.10:8080/assets/index-BP8UqdPZ.js`
  - `-X` slow-read (advertise tiny TCP window, drain 32 bytes every 5s), against a larger JS asset body to amplify server-side send-buffer exhaustion.
- **Attack UTC:** 13:28:35Z → 13:29:34Z (55s window)
- **Degradation curve:**
  - `13:28:35–13:28:42Z` (T0–T+7): still 200, asset latency rising 49ms → 118ms.
  - `~13:28:52Z` (T+17): slowhttptest `Service Available` → **0**; pending connections ballooned 807 → 4075.
  - `13:28:53Z → 13:29:25Z`: **all probes `000 TIMEOUT`** (`/api/health`, `/`, asset) — **complete outage ~36s**.
  - `13:29:28Z`: `/api/health`, `/`, asset all back to **200** — **while the attack was still running** (stop was 13:29:34Z). Signal of **auto-remediation under sustained load** (rate-limit / restart / connection shedding).
- **Post-stop recovery:** `/api/health` 200 within ~1s of stop.
- **Peak degradation:** total unavailability (100% timeouts, `Service Available`=0).

### Window 4 — SLOW-READ reproduction (INCIDENT — REPRODUCED)
- **Command:** identical to W3 (`-X -r 500 -c 8000 ...` on `/assets/index-BP8UqdPZ.js`)
- **Attack UTC:** 13:30:18Z → 13:31:17Z (59s window)
- **Degradation curve:**
  - `13:30:18–13:30:25Z` (T0–T+7): 200, latency climbing (asset 55ms → 112ms, `/` to 83ms).
  - `~13:30:35Z` (T+17): `Service Available` → **0**.
  - `13:30:36Z → 13:31:11Z`: **all probes `000 TIMEOUT`** — **complete outage ~39s**.
  - `13:31:14Z`: asset returns 200 but at **3.19s** (recovery transition / degraded).
  - `13:31:17Z`: `/api/health` → 200.
- **Post-stop recovery:** 0s (`/api/health` 200 immediately on stop).
- **Variance vs W3:** in W3 the service recovered to 200 ~6s *before* the attack stopped (clear self-heal under load); in W4 it stayed down until the attack wound down/stopped. Both recovered fully within ~1s of stop. **Teammates should check whether the remediation engine fired in both windows, or whether W3's early recovery was the proxy shedding slow-read connections rather than the remediation engine acting.**

---

## Recovery / self-healing verdict

- **Self-recovered: YES, both landed windows, no human intervention.**
- Between windows `13:30:04Z` — `/api/health` 200, `/` 200, **smoke 26/26 OK**.
- Final `13:31:38Z` — **smoke 26/26 OK in 1.0s** (full transactional recovery, idempotence + ledger integrity intact).
- Recovery time to `/api/health=200` after stopping the attack: **~0–1s** in both windows.
- No attack processes left running (`pgrep -x slowhttptest` / `hping3` → none). No SYN flood used.

The remediation axis looks healthy: service returned without manual action and the witness transaction flow passed. The only thing to confirm on the Hôte is **whether the remediation engine was the actor** (vs. the front proxy simply timing out slow-read sockets) — see the W3/W4 variance note.

---

## What your teammates should have seen (alerts to correlate)

Expected oracle for the L7 DoS vector: `HighLatencyP95`, `HighErrorRate`, `EndToEndProbeFailed`, `ServiceDown`. Match them to these UTC windows:

| Window | Attack ran (UTC) | Degraded / DOWN (UTC) | Expected alerts firing |
|---|---|---|---|
| **W3 (first incident)** | 13:28:35Z → 13:29:34Z | **13:28:52Z → 13:29:28Z** (~36s) | `HighLatencyP95` (asset latency climb pre-outage, 3s+ spikes), `HighErrorRate` / `EndToEndProbeFailed` (probe_success=0, 100% timeouts), `ServiceDown` (if `up`/scrape failed during the outage) |
| **W4 (reproduction)** | 13:30:18Z → 13:31:17Z | **13:30:35Z → 13:31:14Z** (~39s) | same set; `HighLatencyP95` especially visible (3.19s recovery-edge latency) |

Clean recovery gap to look for between the two incidents: **~13:29:28Z → 13:30:35Z** service healthy (alerts should resolve, then re-fire) — this gives the attack → recovery → attack shape on the dashboards.

- Windows that fired NO incident (useful negative controls): W1 `13:25:34Z–13:26:08Z`, W2 `13:26:46Z–13:27:46Z` — no alerts expected.

---

## Key technical finding (for the hardening/dossier)

1. **Header-slowloris (`slowhttptest -H`) is fully mitigated** even at 4000 connections — the front tier absorbs idle slow-header sockets at ~zero cost. The `dos.sh` default vector (`-H -c 300`) will **not** produce an incident here; teammates re-running the headline command as-is will see a false "defense holds".
2. **The effective L7 vector is slow-read (`slowhttptest -X`) against a body-returning endpoint** (static asset or any endpoint with a non-trivial response). It exhausts server-side send buffers / connection slots and takes the whole service to 100% timeouts in ~17s.
   - **Recommendation:** add a slow-read variant to `attacks/01-dos-applicatif/dos.sh` (or an `ENDPOINT`+`MODE=slowread` switch) so the headline scenario reliably lands, and so Blue team tests the mitigation that actually matters.
3. Onset was **consistent at T+17s** in both landed windows — a useful, repeatable timing for scheduled demo runs.

---

## Evidence (all under `attacks/logs/`)

- Probe curves (UTC, status, latency): `dos-demo-probe-W1.log`, `-W2.log`, `-W3.log`, `-W4.log`
- Orchestrator run logs: `dos-demo-W1-orchestrator.log` … `dos-demo-W4-orchestrator.log`
- W1 real `dos.sh` run log: `dos-demo-W1-dossh.log`
- slowhttptest stats (CSV + HTML, `Service Available` counter): `dos-W2-20261019-152646/`, `dos-W3-20261019-152835/`, `dos-W4-20261019-153018/`
- This report: `attacks/logs/dos-demo-report-20261019T133216Z.md`
