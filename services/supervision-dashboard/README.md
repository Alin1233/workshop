# supervision-dashboard — interface de supervision pour le jury (pilier DEV) — À DÉVELOPPER

React + Tailwind (imposé). Montre les composants, les événements, les alertes et l'avancement de la reprise ; c'est l'écran du Clip Chrono.

## Sources de données disponibles

| Source | Usage |
|---|---|
| Prometheus `/api/v1/query` | `probe_success`, `up`, `payment_ledger_integrity_ok`, taux de requêtes, `ALERTS` |
| Alertmanager `/api/v2/alerts` | alertes actives (Prometheus **et** règles SOC Loki) |
| Loki `/loki/api/v1/query_range` | flux d'événements (`event_type` : `remediation_*` du moteur avec `incident_id`, `waf_remediation_block`, `anomaly_detected`…) |
| remediation-engine `http://remediation-engine:8000` (livré, lecture seule) | `GET /api/state` (incidents ouverts, derniers incidents clos, IP bloquées, état du pont de restauration, dépendances), `GET /api/incidents?limit=&open=`, `GET /api/incidents/{id}` (chronologie horodatée : détection, décision, action, vérification, transaction témoin), `GET /api/decision-table` ; schéma : [`docs/api/remediation-engine.openapi.json`](../../docs/api/remediation-engine.openapi.json), détail : [README du moteur](../remediation-engine/README.md#sorties) |

Grafana (127.0.0.1:3000) fournit déjà les vues « Santé du service » et « SOC » : le dashboard React peut s'en inspirer ou les intégrer.

## À faire
- [ ] Projet Vite + React + Tailwind (même base que `services/frontend`), servi par nginx non privilégié, publié sur `MGMT_BIND`
- [ ] Back-for-front ou proxy nginx vers Prometheus/Alertmanager/Loki/remédiation (le navigateur ne doit pas joindre les réseaux internes).
  Prometheus et Alertmanager exigent une authentification basique, réseau interne compris : `admin` / `/run/secrets/<service>_password` (secret Compose). Loki interne (`loki:3100`) est sans identifiant ; depuis le PC Hôte, `127.0.0.1:3100` passe par `loki-proxy` (admin / `secrets/loki_password`). Les identifiants restent côté serveur, jamais dans le navigateur.
  L'API d'état du moteur n'a ni port publié ni authentification (joignable depuis `obs`, `app` et `dmz`) : le back-for-front la lit sur l'un de ces réseaux et porte lui-même le contrôle d'accès ; il ne relaie jamais `POST /alerts`.
- [ ] Vue chronologique : état avant / pendant / après l'incident, étapes de la remédiation, résultat de la transaction témoin
- [ ] Carte des composants (vert/rouge) et liste des alertes
