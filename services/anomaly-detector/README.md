# anomaly-detector — détection d'anomalies par ML (pilier IA / DATA)

Service d'inférence qui distingue un comportement **normal** d'un comportement **suspect** à partir des
métriques Prometheus et des journaux Loki, sans se réduire à des seuils codés en dur : un modèle appris sur
le trafic normal attribue à chaque service un **score d'anomalie** 0..1, exposé à Prometheus et exploité par
l'alerte `AnomalyDetected` (→ Alertmanager → remédiation).

La partie expérimentale (jeu de données, entraînement, évaluation) vit dans [`ml/`](../../ml/README.md). Le
**code des variables et du modèle est partagé** entre `ml/` et ce service (paquet `app/`) : aucune logique
n'est dupliquée, l'entraînement et l'inférence calculent exactement les mêmes variables.

## Contrat d'intégration

| Entrée / sortie | Détail |
|---|---|
| Données | Prometheus `http://prometheus:9090` (`/api/v1/query`) et Loki `http://loki:3100` (requêtes métriques LogQL), réseau `obs`. Prometheus exige une authentification basique, réseau interne compris : le détecteur utilise `admin` / `/run/secrets/prometheus_password` (secret Compose, `PROMETHEUS_PASSWORD_FILE`). Loki interne est sans identifiant. Depuis le PC Hôte (`ml/export_features.py`) : `127.0.0.1:9090` (admin / `secrets/prometheus_password`) et `127.0.0.1:3100` via `loki-proxy` (admin / `secrets/loki_password`) |
| Sortie | `GET /metrics` (port 8000) : `anomaly_score{service}` (0..1), `anomaly_severity{service}`, `anomaly_model_info{version}`, `anomaly_detector_source_degraded` |
| Santé | `GET /health` → 200 (`status: ok` ou `degraded` si une source est momentanément injoignable) |
| Alerte | `AnomalyDetected` (`anomaly_score > 0.8 for 20s`, labels `severity=critical, domain=anomaly, service`) dans `infra/prometheus/rules/availability.yml` |

Le service est scrapé par le job `anomaly-detector` de `infra/prometheus/prometheus.yml` (avec `honor_labels: true`,
pour que le label `service` porté par `anomaly_score` — `auth-service` / `payment-api` / `frontend` — soit conservé).

## Variables (features) observées

Un vecteur par service, calculé toutes les 10 s (fenêtre glissante d'1 min). Toutes les variables sont orientées
« une hausse est suspecte » : une faible activité ou une période creuse n'est jamais une anomalie.

| Service | Variables |
|---|---|
| `auth-service` | débit de requêtes utilisateur, taux de 5xx, latence p95, **échecs de connexion/min**, taux de 4xx, sonde de bout en bout en échec |
| `payment-api` | débit de requêtes utilisateur, taux de 5xx, latence p95, **jetons invalides/min** (journal), taux de 4xx, sonde en échec |
| `frontend` | débit utilisateur (lignes nginx/min, sondes exclues), **blocages WAF (403)/min** (journal d'audit), sonde en échec |

Ces variables couvrent les scénarios d'attaque du laboratoire : force brute (échecs de connexion), rafale de
jetons invalides, abus de virements (débit + 4xx), injections SQLi/XSS bloquées par le WAF (403), et perte de
disponibilité (sonde en échec).

## Modèle

**Z-score robuste multivarié, calibré** (voir `ml/README.md` pour le détail et les résultats chiffrés). Pour
chaque service on apprend, sur le trafic normal, la médiane et une échelle robuste (MAD) de chaque variable.
En production : `z = (x − médiane) / échelle`, on ne garde que les écarts positifs, la sévérité est la norme
`‖max(0, z)‖₂`, puis `score = 1 − exp(−(sévérité/β)²)`. β est calibré pour que le **seuil 0,8 tombe juste
au-dessus du bruit normal**. Modèle minuscule, déterministe, interprétable (on connaît la variable dominante),
sérialisé en JSON et embarqué dans l'image (`model/rz-2026-10-19-v2.json`) : la démo ne dépend d'aucun ré-entraînement.

Résultats mesurés sur la stack réelle (détail : [`ml/README.md`](../../ml/README.md#4-résultats-chiffrés)) :
0 % de faux positifs sur le trafic normal et au repos dans les deux sessions évaluées, transaction témoin
sans alerte (score max 0,18 au repos, 0,51 sous charge), et les 5 scénarios d'attaque détectés sur le service
visé, avec une alerte reçue par Alertmanager **35 à 45 s** après le début de l'attaque.

## Pour la remédiation

- L'alerte `AnomalyDetected` porte `severity=critical`, `domain=anomaly` et `service` (`auth-service`,
  `payment-api` ou `frontend`). Elle retombe ~70 s après la fin de l'incident (fenêtre glissante d'1 min).
- Une attaque d'API traverse le frontal : `frontend` peut alerter en même temps que le service visé. Avant
  d'agir, s'appuyer sur la variable dominante (journal `anomaly_detected` dans Loki :
  `{service="anomaly-detector", event_type="anomaly_detected"}`) : `probe_failed` ⇒ indisponibilité (redémarrage
  pertinent) ; `login_failures_per_min`, `invalid_tokens_per_min`, `waf_blocks_per_min` ⇒ attaque (redémarrer ne
  sert à rien : blocage / notification).

## Robustesse

- Prometheus ou Loki momentanément injoignable : la boucle **conserve le dernier score**, lève
  `anomaly_detector_source_degraded=1` et journalise `event_type=anomaly_degraded` — elle ne plante jamais
  (pas de crash-loop).
- Résultat de requête vide (aucune donnée) : la variable devient neutre (0 ou médiane), pas une anomalie.
- Modèle absent ou illisible : le service reste debout, `/health` répond 503 `no_model` (pas de crash-loop).
- Franchissements de seuil journalisés en JSON (`event_type=anomaly_detected` / `anomaly_cleared`) avec le
  service concerné (`target_service`), le score, la sévérité et la **variable dominante**, pour l'investigation
  et la corrélation (le champ `service` reste celui de l'émetteur, `anomaly-detector`).

## Lancer

Le service démarre avec la stack (`docker compose up -d --build`). Variables d'environnement (valeurs par défaut) :

| Variable | Défaut | Rôle |
|---|---|---|
| `PROMETHEUS_URL` | `http://prometheus:9090` | source des métriques |
| `LOKI_URL` | `http://loki:3100` | source des journaux |
| `SCRAPE_INTERVAL` | `10` | période de la boucle (s) |
| `ANOMALY_THRESHOLD` | `0.8` | seuil de journalisation d'anomalie |
| `MODEL_PATH` / `MODEL_DIR` | `./model` | modèle à charger (dernier `*.json` par défaut) |

Vérifier en direct depuis le PC Hôte (le service n'est pas publié, on interroge Prometheus) :

```bash
curl -s 'http://127.0.0.1:9090/api/v1/query?query=anomaly_score' | python -m json.tool
curl -s 'http://127.0.0.1:9090/api/v1/query?query=anomaly_model_info'
```

## Développement / tests

Tests unitaires (sans la stack, faux clients Prometheus/Loki) : `tests/unit/test_anomaly_detector.py`
(variables, comblement des valeurs manquantes, apprentissage/scoring, inférence, résistance aux sources vides
ou injoignables). `python -m pytest tests/unit/test_anomaly_detector.py`.
