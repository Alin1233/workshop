# anomaly-detector — détection d'anomalies par ML (pilier IA/DATA) — À DÉVELOPPER

Le sujet exclut les seuls seuils codés en dur : un modèle doit distinguer comportement normal et suspect.

## Contrat d'intégration

| Entrée / sortie | Détail |
|---|---|
| Données | API Prometheus `http://prometheus:9090/api/v1/query_range` et Loki `http://loki:3100/loki/api/v1/query_range` (réseau `obs`) ; depuis le PC Hôte : `127.0.0.1:9090` / `127.0.0.1:3100` |
| Sortie | `GET /metrics` exposant `anomaly_score{service}` (0..1) et `anomaly_model_info{version}` |
| Alerte | règle `AnomalyDetected` déjà rédigée (commentée) dans `infra/prometheus/rules/availability.yml` → Alertmanager → remédiation |

## Pistes de variables
Débit et taux de 5xx par service, latence p95, échecs de connexion/min, blocages WAF/min, IP distinctes/min, `probe_success`.

## À faire
- [ ] Constituer le jeu de données : trafic normal (générateur de charge) + trafic d'attaque étiqueté (scripts de la branche `cyber`) → `ml/`
- [ ] Choisir et entraîner le modèle (Isolation Forest, autoencodeur, z-score multivarié…), mesurer précision/rappel/faux positifs
- [ ] Service d'inférence en boucle (toutes les 10 s) + Dockerfile + entrée compose (réseau `obs`)
- [ ] Décommenter la règle `AnomalyDetected` et le job Prometheus `anomaly-detector`
- [ ] Documenter données, préparation, modèle, résultats et limites (exigé dans le dossier)
