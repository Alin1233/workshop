# remediation-engine — moteur de remédiation (pilier DEV) — À DÉVELOPPER

Reçoit les alertes, décide d'une action, l'exécute, puis **vérifie** que le service métier est de nouveau utilisable.

## Contrat d'intégration (déjà câblé côté infra)

| Entrée / sortie | Détail |
|---|---|
| `POST /alerts` (port 8000) | webhook Alertmanager v4 (`infra/alertmanager/alertmanager.yml`), alertes `firing` **et** `resolved` |
| Labels reçus | `alertname`, `severity` (critical/warning), `domain` (availability/integrity/security/anomaly), `service`, parfois `client_ip` |
| Actions Docker | via `docker-socket-proxy` uniquement (restart/recreate limités), **jamais** le socket brut |
| Vérification | `GET http://payment-api:8000/internal/integrity`, sondes `probe_success` (Prometheus, avec l'identifiant `admin` / `/run/secrets/prometheus_password`), puis `python tests/smoke_test.py` (transaction témoin) |
| Sorties | `/metrics` (`remediation_actions_total{action,result}`, `remediation_duration_seconds`), journaux JSON `event_type=remediation_*` → Loki, API d'état pour le dashboard de supervision |

## À faire
- [ ] Choisir Node.js / FastAPI / Go et créer le service + Dockerfile (même durcissement que les autres : read_only, cap_drop ALL)
- [ ] Table de décision `alertname/domain` → action (redémarrer, recréer, restaurer la base, bloquer une IP au WAF, isoler un service)
- [ ] Distinguer **disponibilité** (redémarrage) et **compromission** (rotation des secrets, restauration, blocage) — exigence du sujet
- [ ] Anti-boucle : verrou par service, nombre max de tentatives, délai de refroidissement, escalade si échec
- [ ] Machine d'états de l'incident (détecté → décision → action → vérification → rétabli/échec) exposée au dashboard
- [ ] Authentifier les webhooks (token partagé ou réseau `obs` seul) — le moteur a des droits élevés
- [ ] Décommenter `remediation-engine` + `docker-socket-proxy` dans docker-compose.yml et le job Prometheus
