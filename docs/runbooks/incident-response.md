# Runbook — réponse à incident (corpus de l'assistant RAG) — À COMPLÉTER

## Où regarder
- Grafana http://127.0.0.1:3000 — « Santé du service » (utilisabilité réelle) et « SOC » (événements de sécurité)
- Alertmanager http://127.0.0.1:9093 — alertes actives
- Loki (Grafana > Explore) : `{service="waf"} |= "transaction"`, `{event_type="auth_failure"}`

## Par alerte
| Alerte | Signification | Réponse automatique | Vérification |
|---|---|---|---|
| EndToEndProbeFailed | le parcours client échoue | à définir (remédiation) | `python tests/smoke_test.py` |
| LedgerIntegrityBroken | registre incohérent | restauration de la dernière sauvegarde saine, déclenchée par un opérateur ([restauration-base.md](restauration-base.md)) | `/api/payments/admin/integrity` |
| AuthBruteForce | force brute depuis une IP | à définir (blocage IP au WAF) | tableau SOC |
| WafAttackBlocked | attaques bloquées en série | à définir | journal d'audit du WAF |
