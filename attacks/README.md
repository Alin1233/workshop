# Scénarios d'attaque (pilier CYBER — Red Team) — À DÉVELOPPER

Exécutés **depuis le PC Attaquant**, contre `http://192.168.137.1:8080` uniquement (SI fictif du groupe).
Réseaux du campus, autres groupes et services tiers : **hors périmètre**.

Un dossier par scénario : `attacks/<nn>-<nom>/` avec `README.md` (objectif, prérequis, commande, effet attendu,
détection attendue, remédiation attendue) et le script reproductible.

## Signaux déjà en place pour la détection
| Attaque | Signal | Alerte existante |
|---|---|---|
| Force brute sur `/api/auth/login` | `event_type=auth_failure`, `auth_login_attempts_total{result="failure"}` | `AuthBruteForce` (Loki), `LoginFailureSpike` (Prometheus) |
| Injection SQL / XSS | blocage 403 du WAF, journal d'audit ModSecurity | `WafAttackBlocked` |
| Déni de service applicatif | latence p95, 5xx, `probe_success=0` | `HighLatencyP95`, `HighErrorRate`, `EndToEndProbeFailed` |
| Altération du registre | `payment_ledger_integrity_ok=0`, `event_type=integrity_violation` | `LedgerIntegrityBroken` |
| Rejeu / falsification de JWT | `event_type=auth_failure` côté payment-api | `InvalidTokenFlood` |

## À faire
- [ ] Choisir l'attaque principale (crédible, reproductible, compatible avec une reprise automatique démontrable)
- [ ] Script principal + 1 ou 2 secondaires (attention : disponibilité ≠ compromission, les réponses diffèrent)
- [ ] Mesurer : délai de détection, délai de remédiation, transaction témoin OK
- [ ] Revue de durcissement (Trivy sur les images, comptes, ports exposés, en-têtes) et réglage du WAF (paranoïa, exclusions)
