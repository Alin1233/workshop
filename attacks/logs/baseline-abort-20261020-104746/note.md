# Baseline abort — 2026-10-20 (UTC)

Target: 172.16.147.10:8080 (only host contacted). No attack process was started.

## Recon
- Command: `./00-recon/recon.sh 172.16.147.10 8080` — exit 0, 08:47:46–08:47:51Z.
- Script nmap (ports 1-100,8080): "Host seems down ... 0 hosts up" (host discovery false negative).
- Manual same-scope rescan `nmap -Pn -sV -T4 -p 1-100,8080` (saved as nmap-Pn.txt): 22/tcp open OpenSSH 10.0p2; 8080/tcp open nginx. Ports 2-100 filtered. SSH was not contacted.
- `GET /` -> 200; `GET /api/payments/health` -> 200 `{"service":"payment-api","status":"ok",...}`.

## Baseline smoke (FAILED, pre-existing)
- Command: `python3 tests/smoke_test.py http://172.16.147.10:8080`
- Exit: 1. Checks passed: 0 (crashed on the first check).
- Traceback: `TimeoutError: timed out` in `call("GET", "/api/auth/health")` after 10 s.

## Auth-service probes (persistent)
- 08:48:29, 08:48:42, 08:48:55: `/api/auth/health` -> 000 after 8 s.
- 08:49:22 .. 08:51:30 (9 probes, 10 s apart): all 000 after 6 s.
- 08:48:55 `/api/auth/login` -> 000 after 8 s.
- 08:52:30 `/api/auth/health` -> 000 after 6 s; `/api/payments/health` -> 200 in 0.017 s.
- Earlier evidence of the same fault: `attacks/logs/acctflood-20261020-102637/codes.txt` contains 503/000 from 10:26 local, before this run.

## 07 invalid-token drill (run; payment-only precondition)
- Command: `TARGET=172.16.147.10 ./07-invalid-token/invalid-token.sh`, 08:52:15–08:52:25Z, exit 0.
- 401: 40, other: 0. `/api/payments/health` 200 before and after.
- Evidence: attacks/logs/invalid-token-20261020-105215/.

## 01 L7 DoS (NOT run)
- Reason: required green baseline absent. Only auth is down while payment/root are up;
  recovery proof (smoke exit 0) is impossible, and attacking an already-degraded SI
  would confound attribution and risk worsening a live incident.
- No `slowhttptest` launched. `pgrep -af '[s]lowhttptest|[h]ping3|[h]ydra|[s]qlmap'` -> none at 08:52:30Z.

## Not verified
- Prometheus/Alertmanager/Loki alerts: bound to the remote host's 127.0.0.1, unreachable
  from this machine. No alert is claimed.
