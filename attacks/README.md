# Scénarios d'attaque (pilier CYBER — Red Team)

Exécutés **depuis le PC Attaquant**, contre `http://192.168.137.1:8080` uniquement (SI fictif du groupe).
Réseaux du campus, autres groupes et services tiers : **hors périmètre**.

Un dossier par scénario : `attacks/<nn>-<nom>/` avec `README.md` (objectif, prérequis, commande, effet attendu,
détection attendue, remédiation attendue) et le script reproductible. Garde-fou commun dans `_lib/guard.sh` :
tout script refuse une cible hors `192.168.137.0/24` sauf `ALLOW_UNSAFE=1`, et journalise dans `logs/` (ignoré par git).

## Scénarios

| # | Dossier | Type | Détection (alerte existante) |
|---|---|---|---|
| 00 | [`00-recon/`](00-recon/) | Reconnaissance (préalable) | — |
| 01 | [`01-dos-applicatif/`](01-dos-applicatif/) | **DoS applicatif L7 — principal** | `HighLatencyP95`, `HighErrorRate`, `EndToEndProbeFailed` |
| 02 | [`02-bruteforce-login/`](02-bruteforce-login/) | Force brute `/api/auth/login` | `AuthBruteForce`, `LoginFailureSpike` |
| 03 | [`03-sqli/`](03-sqli/) | Injection SQL (sqlmap L1/R1) | `WafAttackBlocked` |

**Clip Chrono / démo de bout en bout** : [`clip-chrono.sh`](clip-chrono.sh) enchaîne, en une prise et sans
coupe, la transaction témoin (`tests/smoke_test.py`) → l'attaque L7 → l'attente de reprise automatique (sans
action humaine) → la preuve de reprise (nouvelle transaction témoin OK). Une intervention manuelle = 0/5 sur l'axe remédiation.

```bash
cd attacks
TARGET=192.168.137.1 ./clip-chrono.sh
```

### Outils (PC Attaquant)
`nmap hydra hping3 ffuf slowhttptest sqlmap`. Sur Fedora : `sudo dnf install -y nmap hydra hping3 ffuf`,
`slowhttptest` se compile depuis les sources, `sqlmap` via `git clone` / `pipx`.

## Signaux déjà en place pour la détection
| Attaque | Signal | Alerte existante |
|---|---|---|
| Force brute sur `/api/auth/login` | `event_type=auth_failure`, `auth_login_attempts_total{result="failure"}` | `AuthBruteForce` (Loki), `LoginFailureSpike` (Prometheus) |
| Injection SQL / XSS | blocage 403 du WAF, journal d'audit ModSecurity | `WafAttackBlocked` |
| Déni de service applicatif | latence p95, 5xx, `probe_success=0` | `HighLatencyP95`, `HighErrorRate`, `EndToEndProbeFailed` |
| Altération du registre | `payment_ledger_integrity_ok=0`, `event_type=integrity_violation` | `LedgerIntegrityBroken` |
| Rejeu / falsification de JWT | `event_type=auth_failure` côté payment-api | `InvalidTokenFlood` |

## À faire
- [x] Choisir l'attaque principale → DoS applicatif L7 (`01-dos-applicatif/`), compatible reprise automatique
- [x] Script principal + secondaires → DoS (principal), force brute et SQLi (secondaires ; disponibilité ≠ compromission)
- [ ] Mesurer sur l'infra réelle : délai de détection, délai de remédiation, transaction témoin OK (via `clip-chrono.sh`)
- [ ] Revue de durcissement (Trivy sur les images, comptes, ports exposés, en-têtes) et réglage du WAF (paranoïa, exclusions)
- [ ] Brancher le moteur de remédiation sur les alertes ci-dessus (actuellement à développer côté `remediation-engine`)
