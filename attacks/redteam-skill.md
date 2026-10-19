---
name: redteam
description: Red Team attack loop for the RESILIENCE-ALPHA payment SI — escalate attack vectors until one lands (a reproducible, detected incident) and capture the evidence. Use when asked to attack, pentest, or red-team the SI, provoke or reproduce a security incident, choose or escalate an attack vector, or drive the Clip Chrono demo. Lab scope only: the team's own SI on the authorized nets (192.168.137.0/24 and the deployment net 172.16.147.0/24). Current target: http://172.16.147.10:8080.
---

# Red Team attack loop — RESILIENCE-ALPHA

> Copie lisible du skill. La version chargée par Claude Code vit dans [`.claude/skills/redteam/SKILL.md`](../.claude/skills/redteam/SKILL.md) ; éditer celle-ci en priorité.

Drive the attacker side of the demonstrator: provoke a **reproducible, observed** security incident on the team's own payment SI, escalating vectors until one **lands**, so the detection + remediation chain has something real to react to. The vectors and their scripts live in [`attacks/`](.); this skill is the loop that runs them and decides when the work is done.

## Scope — the one hard rule

Attack **only** the team's own SI, reachable at `http://172.16.147.10:8080`, from the attacker PC, each run timed to **≤60s**, and coordinate start/stop with the Blue/infra operator. The scripts enforce the authorized lab nets (`192.168.137.0/24` and the deployment net `172.16.147.0/24`) through `attacks/_lib/guard.sh` — keep that guard; extend `RA_ALLOWED_NETS` if the deployment moves, never disable it. Campus network, other groups, the internet, and any real data stay strictly out of reach; if a run could touch them, stop and report.

## What "a result" means — the completion criterion

An attack **lands** only when all four hold. The loop is not done until then:

1. **Observable** — a visible anomaly on the attacker side (latency climb, 5xx, failed `/health`) during the run.
2. **Detected** — a **named alert fires** (the *oracle*, table below), confirmed on the Hôte, not merely "it looked slow".
3. **Reproducible** — the same vector lands **twice** with the same oracle.
4. **Evidence** — the run's `attacks/logs/<scenario>-<ts>/` dir, the alert name, and the before/during/after service state are captured for the dossier.

Stretch result: `attacks/clip-chrono.sh` then proves **autonomous recovery** — a fresh `tests/smoke_test.py` passes after the incident. A restarted container alone is not a result: the witness transaction must succeed.

## The loop

1. **Baseline.** Run `attacks/00-recon/recon.sh 172.16.147.10 8080`, then confirm the service is healthy: `python tests/smoke_test.py http://172.16.147.10:8080` exits 0. You need a green baseline to prove you broke something.
2. **Target an oracle.** Pick the vector whose named alert you intend to fire (table below). Start with the main one: **L7 DoS**.
3. **Launch**, scoped and timed, from `attacks/` (e.g. `./01-dos-applicatif/dos.sh 172.16.147.10 8080 30`).
4. **Check the oracle** on the Hôte while/just after the run fires:
   - Prometheus: `curl -s http://127.0.0.1:9090/api/v1/alerts | grep -o '"alertname":"[^"]*"' | sort -u`
   - Alertmanager: `curl -s http://127.0.0.1:9093/api/v2/alerts | grep -o '"alertname":"[^"]*"' | sort -u`
   - Confirm the expected alert name is present and `firing`.
5. **Branch:**
   - **Oracle fired** → reproduce once more (step 3) → capture evidence → done. Optionally run `clip-chrono.sh` for the recovery proof.
   - **Oracle silent** → escalate (ladder below) or switch to another vector → back to step 3.
6. **Restore.** Stop the attack (`pkill -f slowhttptest; pkill -f hping3; pkill -f hydra; pkill -f sqlmap`) and leave only after `smoke_test.py` is green again.

## Vectors and their oracle

Each vector's objective, command, and expected response live in its own README — the single source of truth. Here is only the mapping from vector to the alert it should fire.

| Vector | Script | Oracle (alert that must fire) |
|---|---|---|
| **L7 DoS** (main) | [`01-dos-applicatif/`](01-dos-applicatif/) | `HighLatencyP95`, `HighErrorRate`, `EndToEndProbeFailed`, `ServiceDown` |
| Login brute force | [`02-bruteforce-login/`](02-bruteforce-login/) | `AuthBruteForce`, `LoginFailureSpike` |
| SQL injection | [`03-sqli/`](03-sqli/) | `WafAttackBlocked` |

The L7 DoS is the headliner because its oracle maps to a response the remediation engine can actually heal. Brute force and SQLi are compromise-attempt scenarios: they prove detection and WAF/SIEM response, not availability recovery — keep the two outcomes distinct.

## CVE path — version-specific flaws

A separate branch from the behavioural vectors: find a **known vulnerability in a library version the SI actually runs**, then exploit it only when it is genuinely reachable here. Honest discipline, in order — do not skip a step to reach an exploit:

1. **Inventory.** Run [`00-recon/vuln-scan.sh`](00-recon/vuln-scan.sh). It reads versions as *built/running* (the Python manifests are ranges, so the real version lives in the image) and lists HIGH/CRITICAL CVEs with their fixed-in version.
2. **Triage.** Keep only a CVE that is (a) present in a version actually installed, (b) **reachable** given this app's config and exposure (most infra UIs are bound to `127.0.0.1`, so a CVE there is not attacker-reachable), and (c) backed by a **public PoC**. Drop the rest to the hardening report.
3. **Exploit — only on a confirmed, reachable CVE with a PoC.** Adapt that published PoC against the lab target under the scope guard; never author a generic weapon for an unverified flaw. Put it in a new `attacks/<nn>-cve-<id>/` with the usual README (objectif, prérequis, commande, effet, détection, remédiation).
4. **Oracle.** The expected signal depends on the CVE: an RCE/exfil shows up as a WAF block, a `DependencyFailures`/`ServiceDown` alert, or a `LedgerIntegrityBroken`/`integrity_violation` if data is touched. Note which alert (if any) catches it — a CVE that fires **no** oracle is itself a reportable detection gap.

Known lead on this stack: `ollama/ollama:latest` is unpinned (tag drift + supply-chain risk) and Ollama has a CVE history — but it is only reachable under the `--profile ai` and is not published. Scan it before assuming it is exploitable.

## Escalation ladder — when the oracle stays silent

Climb one rung at a time, re-checking the oracle after each, staying inside the scope and 60s caps:

1. Raise `DURATION` toward 60s.
2. Raise intensity: more slowhttptest connections (`-c`), a wider brute-force wordlist, a broader `ENDPOINT` than `/`.
3. Target a heavier route (an authenticated `/api/payments/*` path) so the work per request climbs.
4. Add the opt-in secondary L4 vector: `sudo SYN_FLOOD=1 ./01-dos-applicatif/dos.sh ...` (rate-capped) — for a *separate* scenario, never the recovery demo.

If the full ladder fires no oracle, the defense is holding under the authorized envelope — **that is itself a reportable result.** Record the ladder you climbed and the signals you did see; do not reach past the scope to force a hit.

## Attack infrastructure

The modern, reproducible kit this loop presents:

- **Attacker PC** (distinct from the Hôte) with `nmap`, `ffuf`, `slowhttptest`, `hydra`, `sqlmap`, `hping3`.
- **Scoped network**: the Windows mobile hotspot `RESILIENCE-G<n>`, Hôte at `172.16.147.10`, enforced by `_lib/guard.sh`.
- **Orchestration**: `attacks/clip-chrono.sh` runs the whole before → attack → auto-recovery → proof sequence in one continuous take.
- **Evidence**: every script writes a timestamped run to `attacks/logs/` (gitignored) for the dossier.

## Where the oracle lives

Management ports are published on `127.0.0.1` only (Hôte), per the subject — check them there, not from the attacker PC:

| Service | URL (Hôte) | Holds |
|---|---|---|
| Prometheus | http://127.0.0.1:9090 | metric alerts (`infra/prometheus/rules`) |
| Alertmanager | http://127.0.0.1:9093 | firing alerts routed to the remediation engine |
| Loki | http://127.0.0.1:3100 | SOC log alerts (`infra/loki/rules`) |
| Grafana | http://127.0.0.1:3000 | « Santé du service » and « SOC » dashboards |
