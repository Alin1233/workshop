# ml/ — données et entraînement du détecteur d'anomalies (pilier IA/DATA) — À DÉVELOPPER

Le service d'inférence vit dans `services/anomaly-detector/` ; ce dossier contient la partie expérimentale.

```
ml/
  data/        exports Prometheus/Loki (CSV/Parquet) — volumineux : non versionnés sauf échantillon
  notebooks/   exploration, choix des variables, évaluation
  train.py     entraînement reproductible → model/<version>.joblib
```

Export de métriques depuis le PC Hôte : `GET http://127.0.0.1:9090/api/v1/query_range?query=...&start=...&end=...&step=10s`.
