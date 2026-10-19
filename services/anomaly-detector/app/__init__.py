"""Détecteur d'anomalies ML : client Prometheus/Loki, variables, modèle robuste, service d'inférence.

Ce paquet est partagé entre le service d'inférence (conteneur) et les scripts d'expérimentation
de `ml/` : la logique de calcul des variables (`features`) et le modèle (`model`) ne sont donc
définis qu'une seule fois, puis importés des deux côtés (cf. `ml/README.md`).
"""
