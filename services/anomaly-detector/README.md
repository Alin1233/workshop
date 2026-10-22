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
| Sortie | `GET /metrics` (port 8000) : `anomaly_score{service}` (0..1, **NaN = pas de donnée**), `anomaly_threshold` (seuil du modèle), `anomaly_data_available{service}`, `anomaly_severity{service}`, `anomaly_model_info{version}`, `anomaly_detector_source_up{source}`, `anomaly_detector_source_degraded`, `anomaly_detector_last_run_timestamp` |
| Santé | `GET /health` → 200 `ok` ; 200 `degraded` avec le détail `sources` / `services` s'il fonctionne partiellement ; 503 s'il ne peut rien scorer (`no_model` — modèle absent, pointeur invalide, `model_mismatch` — ou `degraded` / `auth_secret_unreadable`) |
| Alertes | `AnomalyDetected` (`anomaly_score >= anomaly_threshold`, `for: 20s`, labels `severity=critical, domain=anomaly, service`) ; santé du détecteur : `AnomalyDetectorBlind` (source injoignable 1 min) et `AnomalyDetectorDown` (arrêté ou plus aucun cycle), `severity=warning`, `service=anomaly-detector` — `infra/prometheus/rules/availability.yml`, testées par `infra/prometheus/tests/anomaly_rules_test.yml` (promtool) |

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
sérialisé en JSON et embarqué dans l'image (`model/rz-2026-10-19-v3.json`) : la démo ne dépend d'aucun ré-entraînement.

**Désignation et validation du modèle.** Le modèle actif est désigné par le pointeur `model/CURRENT` (nom du
fichier, écrit par `ml/train.py`), jamais par l'ordre des noms de fichiers ; sans pointeur, seul un répertoire à
modèle unique est accepté. Au chargement, le modèle est validé contre les variables du code (mêmes services,
mêmes noms, paramètres complets, version du JSON = nom du fichier) ; les variables sont associées **par nom**.
Un modèle refusé laisse le service debout, `/health` en 503 `no_model` avec la raison (`model_mismatch: …`).

**Seuil unique.** Le seuil (0,8) est celui pour lequel le modèle est calibré : il est enregistré dans le modèle,
exposé en `anomaly_threshold` et lu par la règle `AnomalyDetected` ; le service et la règle comparent avec `≥`.
Il n'est plus réglable par variable d'environnement (changer le seuil sans recalibrer n'aurait pas de sens).

Résultats mesurés sur la stack réelle (détail : [`ml/README.md`](../../ml/README.md#4-résultats-chiffrés)) :
0 % de faux positifs sur le trafic normal et au repos dans les deux sessions évaluées, transaction témoin
sans alerte (score max 0,18 au repos, 0,51 sous charge), et les 5 scénarios d'attaque détectés sur le service
visé, avec une alerte reçue par Alertmanager **35 à 45 s** après le début de l'attaque.

## Pour la remédiation

Ce contrat est appliqué par le moteur de remédiation (`services/remediation-engine/`, lignes `AnomalyDetected`,
`AnomalyDetectorDown` et `AnomalyDetectorBlind` de sa [table de décision](../remediation-engine/README.md#table-de-décision)).

- L'alerte `AnomalyDetected` porte `severity=critical`, `domain=anomaly` et `service` (`auth-service`,
  `payment-api` ou `frontend`). Elle retombe ~70 s après la fin de l'incident (fenêtre glissante d'1 min).
- Une attaque d'API traverse le frontal : `frontend` peut alerter en même temps que le service visé. Avant
  d'agir, le moteur lit la variable dominante (journal `anomaly_detected` dans Loki :
  `{service="anomaly-detector", event_type="anomaly_detected"}`) : `probe_failed`, `error_ratio_5xx`, `latency_p95`
  ⇒ indisponibilité (redémarrage du service visé) ; `login_failures_per_min`, `invalid_tokens_per_min`,
  `waf_blocks_per_min`, `client_errors_4xx_rate` ⇒ attaque (redémarrer ne sert à rien : blocage de l'IP la plus
  fautive au WAF, si elle compte au moins 10 événements en 2 min dans Loki, sinon escalade `no_offender`) ;
  `frontend` en même temps qu'un incident d'API : rattaché à cet incident, sans action ; autre variable : escalade
  (`triage_unknown`). Détail par alerte : [runbook § 6](../../docs/runbooks/incident-response.md).
- `AnomalyDetectorBlind` et `AnomalyDetectorDown` concernent **le détecteur lui-même** (`service=anomaly-detector`,
  `severity=warning`) : le SI métier n'est pas en cause et ce n'est pas une attaque. Ils ne déclenchent
  aucune action sur un service métier ; seule reprise sûre : redémarrer `anomaly-detector` (sans état) pour
  `AnomalyDetectorDown`, ce que le moteur fait une fois au plus par fenêtre anti-boucle, et vérifier la source
  (Loki/Prometheus) pour `AnomalyDetectorBlind`, que le moteur se contente d'observer.

## Robustesse

La boucle ne plante jamais (pas de crash-loop) et n'invente jamais un comportement « normal » :

- **Dégradation par service.** Une source injoignable (panne, authentification refusée) rend *manquantes* ses
  variables, et ses autres requêtes du cycle sont sautées. Loki en panne : `auth-service` (100 % Prometheus)
  reste scoré normalement ; `payment-api` et `frontend` deviennent incomplets. Prometheus en panne : tous les
  services sont incomplets. `anomaly_detector_source_up{source}` passe à 0, `event_type=anomaly_degraded`.
- **Score partiel.** Pour un service incomplet, la sévérité calculée sur les seules variables disponibles est un
  minorant de la sévérité complète (toutes les contributions sont positives) : si ce score partiel atteint déjà
  le seuil, l'anomalie est certaine et il est exposé (état `partial`, ex. sonde en échec pendant une panne de
  Loki) ; sinon on ne peut rien conclure.
- **Péremption bornée.** Sans score exploitable, le dernier score est conservé `STALE_AFTER_CYCLES - 1` cycles
  (micro-coupure, état `stale`), puis remplacé par **NaN** avec `anomaly_data_available=0` (état `no_data`,
  `event_type=anomaly_unknown`) : une alerte en cours retombe au lieu d'être maintenue toute la panne, sans
  faire croire que tout est normal ; `AnomalyDetectorBlind` signale alors la détection aveugle. Avant le premier
  cycle, le score vaut aussi NaN (pas 0).
- **Résultat vide** (requête réussie, aucune activité) : la variable devient neutre (0 ou médiane apprise), pas
  une anomalie — c'est la plateforme au repos, pas une panne de source.
- **Démarrage impossible** (modèle absent ou incohérent, fichier de mot de passe absent ou illisible) : le
  service reste debout, `/health` répond 503 avec la raison, `/metrics` reste servi et `AnomalyDetectorDown`
  se déclenche (aucun cycle n'aboutit).
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
| `STALE_AFTER_CYCLES` | `3` | nombre de cycles sans donnée au bout duquel le score devient NaN |
| `PROMETHEUS_USER` / `PROMETHEUS_PASSWORD_FILE` | `admin` / secret Compose | authentification auprès de Prometheus |
| `MODEL_PATH` / `MODEL_DIR` | `./model` | modèle explicite, ou répertoire dont `CURRENT` désigne le modèle actif |

Vérifier en direct depuis le PC Hôte (le service n'est pas publié, on interroge Prometheus) :

```bash
curl -s 'http://127.0.0.1:9090/api/v1/query?query=anomaly_score' | python -m json.tool
curl -s 'http://127.0.0.1:9090/api/v1/query?query=anomaly_model_info'
```

## Développement / tests

Tests unitaires (sans la stack, faux clients Prometheus/Loki) : `tests/unit/test_anomaly_detector.py`
(variables, comblement des valeurs manquantes, apprentissage/scoring par nom, validation et désignation du
modèle, péremption bornée, dégradation par service, seuil unique, secret illisible, scripts de `ml/`).
`python -m pytest tests/unit/test_anomaly_detector.py`. Règles d'alerte :
`docker run --rm -v "$PWD/infra/prometheus:/p:ro" --entrypoint promtool prom/prometheus:v3.15.0 test rules /p/tests/anomaly_rules_test.yml`.
