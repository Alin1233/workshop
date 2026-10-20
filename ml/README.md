# ml/ — données et entraînement du détecteur d'anomalies (pilier IA / DATA)

Partie expérimentale du détecteur. Le service d'inférence vit dans
[`services/anomaly-detector/`](../services/anomaly-detector/README.md) ; **le code des variables et du modèle
est partagé** (paquet `services/anomaly-detector/app/`, importé ici) pour que l'entraînement et l'inférence
calculent exactement les mêmes variables — aucune logique n'est dupliquée.

```
ml/
  generate_normal.py    générateur de trafic NORMAL (utilisateurs réalistes à travers le WAF)
  attack_scenarios.py   scénarios d'incident ÉTIQUETÉS, visant uniquement la stack locale
  export_features.py    export des séries de variables depuis Prometheus/Loki → CSV
  train.py              entraînement reproductible + évaluation chiffrée → model/<version>.json
  data/
    features_train.csv, labels.csv          session 1 (entraînement + évaluation) → evaluation.json
    features_test.csv, labels_test.csv      session 2 (test indépendant)         → evaluation_test.json
    features_sample.csv                     extrait lisible (fenêtre autour de la force brute)
    live_*.json                             mesures en direct (Prometheus ALERTS + Alertmanager)
  model/                trace des modèles : rz-2026-10-19.json (v1), rz-2026-10-19-v2.json (v2), rz-2026-10-19-v3.json
                        (déployé) et CURRENT, le pointeur vers le modèle actif (même contenu que dans le service)
```

Les autres exports `features*.csv` restent non versionnés (`data/.gitignore`). Le modèle déployé est celui de
`services/anomaly-detector/model/` (copié dans l'image Docker) ; `train.py` l'écrit aux deux endroits.

## Chaîne reproductible (depuis le PC Hôte, stack démarrée)

```bash
# 1. Trafic normal (débit variable + périodes creuses). Lancer en tâche de fond.
python ml/generate_normal.py --base http://127.0.0.1:8080 --duration 960 --seed 42

# 2. Scénarios d'attaque étiquetés (une ligne par service impacté dans ml/data/labels.csv), sous trafic normal.
#    --allow-docker ajoute l'arrêt bref de payment-api (scénario stop_payment).
python ml/attack_scenarios.py --base http://127.0.0.1:8080 --scenario all --duration 60 --gap 80
python ml/attack_scenarios.py --base http://127.0.0.1:8080 --scenario stop_payment --duration 30 --allow-docker

# 3. Export des variables sur toute la fenêtre (pas de 10 s, comme en production ; grille calée sur le pas).
python ml/export_features.py --start <epoch_debut> --end <epoch_fin> --step 10 --out ml/data/features_train.csv

# 4. Entraînement sur le normal antérieur à --train-until, évaluation sur le reste.
python ml/train.py --features ml/data/features_train.csv --labels ml/data/labels.csv \
    --train-until <epoch_fin_du_trafic_normal> --version rz-AAAA-MM-JJ

# 5. Session de test indépendante (étiquettes séparées), évaluée sans ré-entraîner.
python ml/attack_scenarios.py --base http://127.0.0.1:8080 --scenario all --gap 80 --labels ml/data/labels_test.csv
python ml/export_features.py --start <debut> --end <fin> --out ml/data/features_test.csv
python ml/train.py --model services/anomaly-detector/model/rz-2026-10-19-v3.json --train-until 0 \
    --features ml/data/features_test.csv --labels ml/data/labels_test.csv --report ml/data/evaluation_test.json
```

Garanties des scripts :
- `generate_normal.py` tire toutes ses décisions aléatoires dans le thread ordonnanceur (suite reproductible pour
  une graine donnée) et borne le travail en vol (`--max-in-flight`) : en cas de ralentissement, les actions en
  trop sont ignorées et comptées au lieu d'être empilées, les périodes creuses restent creuses, et l'arrêt est
  net à `--duration` ;
- `attack_scenarios.py` n'écrit une étiquette que si l'incident a réellement eu lieu (au moins la moitié des
  réponses attendues — 401, 403, 404/422 —, jeton obtenu pour `transfer_abuse`, `docker stop` réussi pour
  `stop_payment`) ; sinon erreur et code de sortie 1. Le conteneur arrêté est déduit des labels du projet
  Compose (`--project`, défaut `$COMPOSE_PROJECT_NAME`) ou fixé par `--payment-container` ;
- `train.py` évalue **chaque fenêtre** étiquetée séparément (`labels.csv` est en ajout seul : un scénario rejoué
  a plusieurs fenêtres), puis agrège par `scénario@service` (fenêtres alertées, délai médian et maximal, détail
  par fenêtre dans `per_window`) ; il met à jour le pointeur `CURRENT` du modèle actif.

Pour rejouer les chiffres du dossier à partir des données versionnées, seules les étapes 4 et 5 (dernière
commande) sont nécessaires : `--train-until 1792413876` pour la session 1.
Le port d'entrée est `8080` par défaut ; adapter si le WAF est publié ailleurs (ex. `8088`).

---

# Dossier technique : données, préparation, modèle, résultats, limites

## 1. Données

- **Source.** Métriques Prometheus (`http_requests_total`, `http_request_duration_seconds_bucket`,
  `auth_login_attempts_total`, `probe_success`) et journaux Loki (une ligne JSON par événement :
  `event_type`, `client_ip`, `status` ; journal d'audit WAF avec `transaction.response.http_code`).
- **Trafic normal.** `generate_normal.py` simule des utilisateurs réalistes à travers le WAF (inscription,
  connexion, consultation de compte, virements de faibles montants), avec un **débit variable** (profil
  sinusoïdal) et des **périodes creuses** récurrentes, pour que le modèle apprenne que l'inactivité est normale.
- **Incidents étiquetés.** `attack_scenarios.py` déclenche, **uniquement contre la stack locale**, des scénarios
  observables, chacun consignant ses bornes temporelles (étiquettes) :
  force brute d'identifiants (`auth-service`), rafale de jetons invalides (`payment-api`), abus de virements
  (`payment-api`), injections SQLi/XSS bloquées par le WAF (`frontend`), et, en option, arrêt bref du conteneur
  `payment-api` (disponibilité). Chaque scénario étiquette **tous les services qu'il impacte de façon observable** :
  une attaque d'API traverse le WAF et le frontal nginx et y crée un pic de trafic réel, le `frontend` est donc
  étiqueté avec le service visé (la rafale SQLi/XSS, bloquée par le WAF, n'impacte que le `frontend`).

## 2. Préparation

- **Variables.** Un vecteur par service, agrégé sur une fenêtre glissante d'1 min (cf. tableau du README du
  service). Les variables sont choisies pour être discriminantes **et** stables à vide ; toutes orientées
  « la hausse est suspecte ». Les débits ne comptent que le **trafic utilisateur** : les sondes blackbox, les
  `/health` et le healthcheck Docker sont exclus, si bien qu'une plateforme inactive vaut exactement 0.
- **Valeurs manquantes.** Une série absente dans Prometheus (ex. aucun 5xx) est ramenée à 0 (`or vector(0)`).
  Une requête réussie sans donnée est comblée par 0 (absence d'activité) ou par la médiane apprise (latence :
  valeur neutre) — l'absence de trafic ne crée jamais d'anomalie. **Même prétraitement à l'entraînement et en
  production** : à l'apprentissage, la médiane de comblement est calculée sur le seul normal d'apprentissage (le
  modèle la retrouve comme médiane apprise) ; à l'évaluation, chaque échantillon passe par `features.clean_values`
  avec les médianes du modèle, exactement comme le service. (Une source injoignable est un cas distinct, propre
  à l'inférence : ses variables sont « manquantes », jamais comblées — cf. README du service.)
- **Étiquetage.** Un échantillon `(timestamp, service)` est « attaque » s'il tombe dans une fenêtre étiquetée
  pour **ce service**, sinon « normal ». Les services non impactés pendant une attaque restent « normal » : ils
  mesurent les faux positifs en conditions d'attaque. Les **70 s qui suivent** chaque attaque (la fenêtre d'1 min
  y est encore « contaminée ») sont une zone de transition, exclue de l'apprentissage comme de l'évaluation.
- **Découpage temporel.** Le modèle n'apprend que sur le normal **antérieur** à `--train-until` (premier
  enregistrement de trafic normal). Les faux positifs sont mesurés sur le normal **tenu à l'écart** : second
  enregistrement, trafic normal pendant les attaques et période creuse finale.
- **Apprentissage sur le normal.** Médianes et échelles robustes estimées **uniquement** sur les échantillons
  normaux d'apprentissage (approche semi-supervisée : les étiquettes ne servent qu'à l'évaluation).

## 3. Modèle retenu et pourquoi

**Z-score robuste multivarié calibré**, un jeu de paramètres par service :

1. Par variable : médiane `m` et échelle robuste `s = max(1,4826 × MAD, q99(|x − m|) / 3)` — le 99e centile
   des écarts normaux vaut ~3 unités, si bien qu'une variable au bruit normal épisodique (sessions expirées →
   quelques jetons invalides) n'écrase pas le seuil de tout le service. Repli écart-type puis plancher par
   variable (`SCALE_FLOOR` de `train.py`) quand la variable est constante dans le normal (ex. une sonde en échec
   n'arrive jamais : plancher 0,1, donc une panne vaut 10 unités).
2. Écart d'une observation : `z = (x − m) / s`, dont on ne garde que la partie positive (hausse).
3. Sévérité multivariée : `S = ‖max(0, z)‖₂` (distance de Mahalanobis à covariance diagonale, bornée à 0).
4. Score : `score = 1 − exp(−(S/β)²)`, `β` calibré sur le normal pour que `score(T80) = 0,8`, où T80 est un
   quantile haut des sévérités normales (avec un plancher de sécurité).

**Pourquoi ce choix.** Les scénarios visés se traduisent par une **hausse marquée** d'une ou plusieurs
variables, ce qu'un écart robuste à la normale capte directement, y compris **au-delà des valeurs vues à
l'entraînement** (une force brute 50 fois plus intense donne un score plus élevé ; un Isolation Forest, lui,
ne sépare pas mieux un point « très loin » qu'un point « juste au-delà » du nuage normal). Le modèle est
**déterministe** (aucun aléa), **minuscule** et **interprétable** : chaque alerte désigne la variable dominante,
utile à la remédiation et à l'investigation. Il se sérialise en **JSON lisible et versionnable**, sans couplage
de version `scikit-learn`/`joblib` entre l'entraînement (Python 3.14) et le service (Python 3.12), et le scoring
n'exige aucune dépendance. Isolation Forest et autoencodeur n'ont **pas** été évalués expérimentalement sur ce
jeu de données : c'est une comparaison à mener si le modèle actuel montre ses limites (cf. §5).

## 4. Résultats chiffrés

<!-- RESULTS:DEBUT -->
Trois sessions sur la stack réelle (pas de 10 s, fenêtre glissante 1 min) :

| Session | Contenu | Rôle |
|---|---|---|
| 1 — entraînement (28 min) | 16 min de trafic normal (graine 42), puis 5 scénarios (pauses de 45 s) sous trafic normal (graine 7), puis 3 min sans trafic | apprentissage sur les 16 premières minutes, évaluation sur le reste |
| 2 — test indépendant (16 min) | trafic normal (graine 99), transaction témoin ×2 (sous charge et plateforme au repos), 5 scénarios (pauses de 80 s), 3 min sans trafic | évaluation hors échantillon (`evaluation_test.json`) + mesure **en direct** (Alertmanager) |
| 3 — validation en direct (9 min) | modèle final déployé : témoin au repos et sous charge, force brute, **Loki suspendu 30 s**, repos | vérification de bout en bout (`live_validation_model_v2.json`) |

**Modèle final `rz-2026-10-19-v3`, au niveau échantillon (score ≥ 0,8) :**

| Mesure | Session 1 (normal tenu à l'écart) | Session 2 (test indépendant) |
|---|---|---|
| Échantillons normaux / dont période creuse | 140 / 44 | 180 / 36 |
| Taux de faux positifs (normal) | **0 %** | **0 %** |
| Taux de faux positifs (période creuse) | **0 %** | **0 %** |
| Score maximal sur le normal | 0,738 | 0,764 |
| Précision | 1,00 | 1,00 |
| Rappel (échantillons d'attaque, tous services impactés) | 0,80 | 0,755 |
| Fausses alertes simulées (`for: 20s`) | 0 | 0 |
| Scénarios ayant déclenché l'alerte sur le service visé | 5/5 | 5/5 |

**Par scénario (session 2, service visé)** — délai mesuré depuis le début de l'attaque :

| Scénario | Service | Rappel | 1er score > 0,8 (hors ligne) | Alerte simulée `for: 20s` (hors ligne) | **Alerte reçue par Alertmanager (en direct)** |
|---|---|---|---|---|---|
| Force brute | auth-service | 0,83 | 11 s | 31 s | **44,6 s** |
| Rafale de jetons invalides | payment-api | 1,00 | 1 s | 21 s | **34,6 s** |
| Abus de virements | payment-api | 0,86 | 11 s | 31 s | **44,6 s** |
| Arrêt de payment-api (30 s) | payment-api | 0,75 | 10 s | 30 s | **43,7 s** |
| SQLi/XSS bloquées par le WAF | frontend | 1,00 | 0 s | 20 s | **43,6 s** |

Le délai en direct ajoute à la montée de la fenêtre d'1 min le scrape (10 s), la boucle d'inférence (10 s) et
la règle `for: 20s`. Il a été mesuré avec le modèle v1, dont la détection des attaques est identique (seul le
plancher de latence diffère, voir plus bas) ; la session 3 le confirme pour v2 (force brute : **43,3 s**).
L'alerte retombe ~70 s après la fin d'une attaque (le temps que la fenêtre d'1 min se vide). Côté frontal, les
attaques d'API sont également détectées (rafale de jetons, abus de virements), sauf la force brute, trop lente
(argon2) pour faire sortir le débit du frontal de sa plage normale (score max 0,81 en session 2, 0,74 en session 3).

**Transaction témoin et repos (sessions 2 et 3).** `tests/smoke_test.py` (40 virements concurrents, erreurs 4xx
volontaires) ne déclenche pas d'alerte : score max **0,18** plateforme au repos, **0,51** sous charge (modèle v2).
Au repos, le score reste à **0,0** sur les trois services (55 échantillons en direct).

**Comparaison avec les règles existantes (force brute, session 2, en direct).** Règle SOC Loki `AuthBruteForce`
(> 10 échecs/min par IP) : +16 s ; `AnomalyDetected` (ML) : +43 s ; règle statique `LoginFailureSpike` : +47 s.
Le modèle n'est pas plus rapide qu'une règle dédiée au seuil bas, mais **un seul modèle générique** couvre les
cinq scénarios, dont l'abus de virements et la hausse de trafic au frontal, pour lesquels aucune règle n'existe.

**Robustesse (session 3).** Loki suspendu 30 s : `anomaly_detector_source_degraded` passe à 1 en ~19 s (délai
d'attente des requêtes), `/health` répond `degraded` (200), dernier score conservé, journal
`event_type=anomaly_degraded` ; retour à 0 dès la reprise (`anomaly_recovered`), sans redémarrage du service.

**Ce que l'évaluation a corrigé (transparence).** La session 2, mesurée avec le modèle **v1**
(`ml/model/rz-2026-10-19.json`, plancher de latence 20 ms), a révélé un faux positif : la transaction témoin
lancée sur une plateforme au repos poussait payment-api à 1,0 (latence p95 de 136 ms sous 40 virements
concurrents, contre 41 ms habituellement, soit z = 4,7 avec un plancher de 20 ms). Le plancher a été porté à
**100 ms** (une variation de p95 inférieure à 100 ms est courante et ne caractérise pas une anomalie ; la règle
statique `HighLatencyP95` ne réagit qu'à 1 s) → modèle **v2**. Ce réglage ayant été décidé après avoir vu la
session 2, le modèle v2 a ensuite été validé sur une **troisième** session en direct. L'évaluation a aussi
révélé deux défauts de préparation, corrigés avant les chiffres ci-dessus : une zone de transition qui masquait
le début de l'attaque suivante, et une **fuite temporelle** à l'export (Loki omet les fenêtres sans événement ;
l'export empruntait alors le point suivant, 10 s dans le futur). Rapport v1 en direct : `live_test_session_model_v1.json`.

**v2 → v3 (revue de code).** L'évaluation comblait les latences manquantes avec une médiane calculée sur tout le
jeu de données (attaques et normal tenu à l'écart compris), alors que le service utilise la médiane du normal
d'apprentissage. Le prétraitement est désormais identique (voir §2) ; ré-entraîné sur les mêmes CSV, hors ligne,
le modèle change marginalement (médianes de latence d'auth-service et de payment-api, donc β/T80 de ces
services) → **v3**. Tous les chiffres ci-dessus sont identiques avec v3 (recalculés, `evaluation*.json`). Les
mesures en direct des sessions 2 et 3 ont été faites avec v1/v2 ; v3 a été redéployé et vérifié en direct sans
nouvelle collecte de données (authentification Prometheus, scores mis à jour, alertes de santé du détecteur).
<!-- RESULTS:FIN -->

**Seuil et fenêtre conservés : `anomaly_score >= anomaly_threshold` (0,8) `for 20s`.** Le seuil n'est écrit
qu'à un endroit (`THRESHOLD` dans `services/anomaly-detector/app/model.py`) : il est enregistré dans le modèle,
exposé par le service et lu par la règle, avec la même comparaison `≥` partout (évaluation comprise). Sur les deux sessions, le score normal
maximal reste à 0,74–0,76 (et 0,51 en direct sous charge), tandis que toutes les attaques atteignent 1,0 sur le
service visé : 0,8 laisse une marge des deux côtés. Les 20 s (3 évaluations consécutives) absorbent un pic isolé
(un seul échantillon normal à 0,80 en session 2, sans alerte) pour un coût de ~20 s sur le délai.

## 5. Limites

- **Portée des variables.** Le modèle voit des agrégats d'1 min : une attaque « basse et lente » (très diluée)
  ou qui n'élève aucune des variables suivies passerait inaperçue.
- **Dépendance aux journaux.** Les variables `jetons invalides/min` et `blocages WAF/min` viennent de Loki : si
  l'ingestion prend du retard ou tombe, ces signaux manquent (le service bascule en mode dégradé et conserve
  le dernier score, mais ne détecte pas de nouvelle anomalie pendant ce temps).
- **Calibration locale.** Les seuils robustes sont calibrés sur le trafic de ce laboratoire ; un changement de
  profil d'usage (nouvelles fonctionnalités, charge très différente) impose un ré-entraînement.
- **Covariance diagonale.** Le modèle traite les variables indépendamment (pas de corrélations croisées) : une
  anomalie qui ne se voit que dans la corrélation entre variables n'est pas captée. Un Isolation Forest ou un
  autoencodeur multivarié serait une piste si de tels cas apparaissaient.
- **Plage de charge apprise étroite.** Le normal provient d'un seul profil de générateur (≤ 6 req/s sur
  payment-api, ≤ 460 lignes/min au frontal). Une charge légitime nettement supérieure (test de charge, salle
  entière sur l'application) fera monter le score par le seul débit : ré-entraîner avec une plage de charge plus
  large avant un tel usage. En session 2, le débit du frontal a atteint 521 lignes/min (score 0,80, sans alerte).
- **Attribution.** Une attaque d'API traverse le frontal : l'alerte peut viser à la fois le service attaqué et
  `frontend`. Le moteur de remédiation s'appuie donc sur la variable dominante (journal `anomaly_detected`) et
  corrèle les alertes, plutôt que de redémarrer aveuglément le service désigné
  ([table de décision](../services/remediation-engine/README.md#table-de-décision)).
- **Jeu de données modeste.** ~45 min de données sur un SI fictif, depuis une seule machine (une seule IP : la
  variable « IP distinctes/min » n'a donc pas été retenue) : suffisant pour la démonstration, non représentatif
  d'une production réelle (saisonnalité journalière/hebdomadaire absente).
