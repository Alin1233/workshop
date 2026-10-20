# Recette du moteur de remédiation — reprise des compromissions par la chaîne d'alertes complète

Rejeu **de bout en bout, uniquement par les alertes** (Prometheus, Loki/SOC, détecteur ML → Alertmanager → webhook
authentifié → incident), des réponses à une compromission : blocage d'IP au WAF (force brute, injections, anomalie ML)
et restauration de la base (registre corrompu). On n'appelle **jamais** le moteur directement : l'API d'état est en
lecture seule et ne déclenche aucune action. Mesuré sur la pile locale le **20/10/2026** (`.env` `FRONT_PORT=8088`,
WAF sur http://127.0.0.1:8088), moteur reconstruit avec le correctif « conteneur en cours de démarrage » (ci-dessous).

Ces mesures alimentent le RTO/RPO du PCA/PRA et le dossier : elles sont données telles que relevées, et les limites
(poste attaquant simulé, NAT du labo, pont de développement) sont explicites.

## Méthode et outils

- **Outils d'attaque reproductibles** : [`scripts/scenarios/attack.py`](../../../scripts/scenarios/attack.py) — bibliothèque
  standard uniquement, lançable depuis n'importe quelle machine contre `--target http://<hôte>:<port>`, **sans Docker**.
  Les mots de passe des comptes fictifs sont **générés** à l'exécution (`secrets.token_urlsafe`), aucun secret en dur.
  Sous-commandes : `brute-force`, `injections`, `invalid-tokens`.
- **Orchestrateur côté hôte** : [`scripts/scenarios/run_recette.py`](../../../scripts/scenarios/run_recette.py) — démarre
  le poste attaquant et un témoin tiers sur `edge`, lance l'attaque, puis collecte les preuves : instant de déclenchement
  de l'alerte (Alertmanager `startsAt`, identifiants `admin` / `secrets/*_password`), chronologie de l'incident du moteur
  (`GET /api/incidents/{id}`), réponses du WAF, transaction témoin, et levée du blocage au TTL.
- **Horodatages** : en secondes **depuis le début de l'attaque** (ou de la corruption pour le scénario 3). Deux repères
  distincts : l'instant où l'alerte passe `firing` (vu de Prometheus/Loki via Alertmanager) et les jalons de l'incident
  (détection = réception du webhook, décision, action, vérification, rétablissement, retombée, clôture).
- **TTL de blocage court pour la démonstration** : `WAF_BLOCK_TTL_SECONDS=90` (via l'environnement du moteur,
  `waf_block.ttl_from_env`) pour montrer la **levée automatique** sans attendre 5 min ; **valeur par défaut 300 s
  rétablie** après la recette.

### Le « second poste » (limite importante)

**Aucune seconde machine réelle n'était disponible.** Le poste attaquant est un conteneur sur le réseau `edge` : le WAF
voit son **IP edge** (`172.25.0.3`) comme l'IP cliente réelle, exactement comme il verrait une autre machine du réseau
avant la traduction NAT (cf. [waf-blocking.md](waf-blocking.md), tableau « IP source vue par le WAF »). Un second
conteneur edge (`172.25.0.4`) sert de **témoin tiers** (autre client légitime), et l'hôte (`127.0.0.1:8088`, passerelle
edge, exclue) de troisième point de vue. En dev, chaque conteneur a donc **son** IP et le blocage est **ciblé** ; sur la
VM du labo, tous les postes arrivent avec la même IP NAT `172.16.255.252` (voir « Limites »).

## Correctif livré pendant la recette — « conteneur en cours de démarrage attendu, pas désigné comme cible »

**Cause.** Dans le diagnostic d'un redémarrage (`app/engine.py`, `_decide_restart`), dès qu'un maillon de la chaîne était
`starting`, la décision renvoyait un plan `act`/`restart` ciblant le service (`action=restart`). Aucun redémarrage
n'était finalement exécuté (le `settle` à l'exécution attendait la stabilisation), **mais la décision affichée et la
chronologie disaient « redémarrage de … »** — faux. Même défaut dans `_decide_integrity` : un PostgreSQL `starting`
était classé « base injoignable » et reclassé en panne de disponibilité, alors que le contrôle d'intégrité (409/503)
est trompeur pendant le démarrage.

**Incident réel qui l'a révélé** (pré-correctif, 20/10 09:35, dans l'historique local du moteur) :
`inc-20261020-073520-98c983`, `AnomalyDetected` (variable dominante `probe_failed`) sur payment-api →
décision **« waf est starting : redémarrage de waf (dépendance de payment-api) »**, **compteur d'actions à 0**.

**Changement.** Nouvelle disposition de décision `kind=wait` : un maillon `starting` est **attendu** (sous le verrou de la
chaîne), puis la chaîne est **re-diagnostiquée** sur l'état réel. Seul un conteneur **réellement en panne** (ou toujours
`starting` passé le délai `healthy_timeout_s` — il ne s'est pas stabilisé) devient la cible. Le libellé dit ce qui se
passe : *« … en cours de démarrage : attente de sa stabilisation puis nouveau diagnostic »*. Portée vérifiée :
- `_decide_restart` (stratégies `RESTART`, `OBSERVE_THEN_RESTART`, et le chemin ML de disponibilité qui l'appelle) ;
- `_decide_integrity` (PostgreSQL `starting` → attente puis nouveau contrôle d'intégrité, sans reclassement « base
  injoignable ») ;
- le redémarrage du détecteur (`RESTART_DETECTOR`) reste un **redémarrage forcé par conception** (service sans état) :
  il n'a jamais affiché de faux libellé, il est laissé tel quel ;
- les actions de blocage et de restauration ne diagnostiquent pas un `starting` comme cible de redémarrage.

**Tests** (`tests/unit/test_remediation_engine.py`) : le test existant
`test_container_already_starting_is_awaited_not_restarted` est **renforcé** (la décision est `wait`, jamais `acting`,
le libellé ne contient pas « redémarrage ») ; **deux tests ajoutés** :
`test_container_stuck_in_starting_is_eventually_restarted` (un `starting` qui ne se stabilise pas finit par être
redémarré) et `test_integrity_with_starting_postgres_waits_then_confirms_corruption` (PostgreSQL `starting` → attente,
puis restauration une fois sain, sans reclassement). Suite complète verte.

**Preuve en direct, après correctif** — on rejoue la **même course** (une alerte de disponibilité active alors que le
maillon est `starting`, redémarré par un tiers) : `docker stop frontend` → attendre que `EndToEndProbeFailed` soit
`firing` → `docker start frontend` (il passe `starting`) → le moteur reçoit le webhook ~5 s plus tard.
Incident `inc-20261020-092442-9e870e` :

| Jalon de la chronologie | Observé |
|---|---|
| décision | `kind=wait` — *« frontend en cours de démarrage : attente de sa stabilisation puis nouveau diagnostic »* |
| `wait:starting` → `wait:settled` | conteneurs re-lus : `frontend healthy, waf healthy` |
| nouvelle décision | `kind=verify` — *« conteneurs sains et symptôme disparu : vérification seule »* |
| vérification | conteneurs OK, sondes OK, transaction témoin OK → **recovered** |
| **actions du moteur** | **aucune** (0 redémarrage de frontend) |

Avant le correctif, cette course produisait « redémarrage de frontend » et passait par l'état `acting`.

## Résultats par scénario

Tous les scénarios sont **PASS**. Un conteneur attaquant edge simule le second poste (voir plus haut).

### 1. Force brute → `AuthBruteForce` → blocage d'IP → levée au TTL

`attack.py brute-force` (connexions répétées, mauvais mots de passe) à ~57/min pendant 35 s depuis `172.25.0.3`.
Incident `inc-20261020-090552-34f895`.

| Étape | Temps depuis le début de l'attaque |
|---|---|
| `AuthBruteForce` `firing` (Loki/SOC, > 10 échecs/min, 1 IP) | +21,5 s |
| détection (webhook reçu) | +28,5 s |
| décision (blocage de l'IP) | +28,5 s |
| **blocage effectué au WAF** | **+28,6 s** |
| blocage vérifié (config réellement chargée) + sondes | +28,8 s |
| transaction témoin OK (depuis la dmz) | +29,5 s |
| **rétabli et vérifié** | **+29,5 s** |
| retombée de l'alerte + clôture (fenêtre SOC 1 min après l'arrêt des échecs) | ≈ +88 s |
| expiration logique du blocage (TTL 90 s) | +121,5 s |
| **levée effective** (fichier réécrit + nginx rechargé par `expire()`) | **+131,6 s** |

Réponses du WAF pendant le blocage : attaquant `403 {"detail":"blocked_by_remediation"}` ; témoin tiers `200` ;
hôte (port publié) `200`. **Après la levée**, l'attaquant est de nouveau servi (`200`).

### 2. Injections SQLi/XSS → `WafAttackBlocked` → blocage → levée au TTL

`attack.py injections` (charges OWASP, toutes bloquées en 403 par ModSecurity) à ~30/min pendant 40 s depuis
`172.25.0.3`. Incident `inc-20261020-090822-43a204`.

| Étape | Temps depuis le début de l'attaque |
|---|---|
| `WafAttackBlocked` `firing` (Loki/SOC, > 5 refus 403/2 min, 1 IP) | +24,4 s |
| détection + décision + **blocage effectué** | +31,5 s |
| blocage vérifié + sondes | +31,8 s |
| transaction témoin OK | +32,5 s |
| **rétabli et vérifié** | **+32,5 s** |
| expiration logique (TTL 90 s) / **levée effective** | +122,9 s / **+133,4 s** |

Attaquant `403 blocked_by_remediation` (plus **aucune** ligne d'audit ModSecurity, l'alerte retombe d'elle-même) ;
témoin tiers `200` ; hôte `200` ; après la levée, attaquant `200`.

### 3. Registre corrompu → `LedgerIntegrityBroken` → restauration par le pont

Pont de développement initialisé, **sauvegarde saine prise juste avant** (`remediation_bridge_dev.py backup`,
`integrity: ok`), runner lancé en tâche de fond (`… run`). Corruption par `psql` sur l'hôte (le solde d'un compte ne
correspond plus à ses écritures ; `accounts.id` étant un UUID, sélection par `account_number`, `-v ON_ERROR_STOP=1`) :

```sql
UPDATE accounts SET balance_cents = balance_cents + 100000 WHERE account_number='RA0010314121';
```

Incident `inc-20261020-091218-591df5`. **Quelle alerte arrive en premier ?** `LedgerIntegrityBroken` (Prometheus,
`payment_ledger_integrity_ok == 0`) passe `firing` à **+11,2 s** et **ouvre l'incident** ; `LedgerIntegrityViolationLogged`
(Loki, journal `integrity_violation`) passe `firing` à **+17,3 s** et est **corrélée au même incident** (clé
`integrity:payment-api`) — **une seule restauration**, pas de double.

| Étape | Temps depuis la corruption |
|---|---|
| `LedgerIntegrityBroken` `firing` (Prometheus) | +11,2 s |
| détection (webhook, ouvre l'incident) | +19,9 s |
| décision : corruption confirmée (PostgreSQL sain **et** `/internal/integrity` = 409) | +20,0 s |
| demande de restauration déposée au pont | +20,0 s |
| `LedgerIntegrityViolationLogged` (Loki) corrélée au même incident | +24,4 s |
| **restauration faite** (runner dev, `resilience-pg-restore latest-healthy`) | **+31,5 s** |
| intégrité vérifiée `200` | +31,6 s |
| transaction témoin OK | +31,9 s |
| **rétabli et vérifié** | **+31,9 s** |
| retombée `LedgerIntegrityBroken` (métrique revenue à 1) | +49,9 s |
| retombée `LedgerIntegrityViolationLogged` (fenêtre Loki 2 min) + **clôture** | +174,4 s |

**1 seule action `restore_db` (succès)**, aucun redémarrage de PostgreSQL ni des API (la restauration les arrête et les
relance elle-même ; le moteur maintient les actions de disponibilité). Après : `/internal/integrity` = **200**, solde du
compte revenu à sa valeur saine. Runner arrêté en fin de scénario.

### 4. Anomalie ML de sécurité → blocage

**4A — Les règles SOC bloquent d'abord, l'incident ML reconnaît « déjà bloqué ».** Pendant les scénarios 1 et 2,
`AnomalyDetected` (seuil `anomaly_score ≥ 0,8`, `for: 20s`) s'est déclenchée **après** le blocage SOC. Le moteur a trié
par variable dominante puis constaté que l'IP était déjà bloquée — **aucun second blocage** :

| Incident | Service | Variable dominante | Score | Décision |
|---|---|---|---|---|
| `inc-20261020-090210-248f72` | auth-service | `login_failures_per_min` | 1,00 | *« 172.25.0.3 déjà bloquée au WAF : vérification seule »*, 0 action |
| `inc-20261020-090620-aa8294` | auth-service | `login_failures_per_min` | 1,00 | idem |
| `inc-20261020-090840-b43833` | frontend | `waf_blocks_per_min` | 0,96 | idem |

**4B — Un cas où c'est le chemin ML qui bloque** (attaque que le ML capte mais pas les seuils SOC). Jetons invalides sur
`/api/payments/accounts/me` à **15/min** pendant 135 s depuis `172.25.0.3`. Incident `inc-20261020-092040-087d04`.

| Étape | Temps depuis le début de l'attaque |
|---|---|
| `AnomalyDetected` `firing` (payment-api, `anomaly_score` 0,845 ≥ 0,8) | +77,8 s |
| détection + triage (`dominant_feature=invalid_tokens_per_min`) + décision | +86,6 s |
| **blocage effectué** (Loki : 22 événements en 2 min depuis l'IP ≥ seuil 10) | +86,6 s |
| blocage vérifié | +87,1 s |
| transaction témoin OK → **rétabli et vérifié** | +87,5 s |

**`InvalidTokenFlood` (SOC) ne s'est jamais déclenchée** : son seuil est **> 20 événements/min pour une IP**, or
l'attaque est à **15/min**. Le détecteur ML, lui, voit `invalid_tokens_per_min = 15` (médiane normale 0, échelle ≈ 2,05,
z ≈ 7,3) → `anomaly_score ≈ 0,94 ≥ 0,8`. C'est donc le **chemin ML** (lecture du journal `anomaly_detected`, attribution
de l'IP dans Loki, blocage) qui réagit, exactement le cas demandé. Pour une attaque plus intense (force brute, > 20/min),
les règles SOC (`for: 0s`) sont plus rapides que l'anomalie (`for: 20s`) et bloquent les premières (cas 4A).

**4C — Force brute sous les seuils SOC : le chemin ML bloque sur `login_failures_per_min`.** Même démonstration que 4B,
mais par **force brute** (`attack.py brute-force`), pour que la variable dominante soit `login_failures_per_min` et que
l'attribution se fasse sur les `auth_failure` d'`auth-service` dans Loki. Scénario d'orchestration `ml-brute-force`
(`run_recette.py`) : l'incident est suivi par sa clé `anomaly:auth-service` (il n'est pas indexé sur l'IP), l'attaque est
lancée en tâche de fond et l'incident suivi en parallèle (le blocage survient pendant l'attaque).

*Choix du débit, à partir des seuils réels.* Il faut rester **sous** `AuthBruteForce` (> 10 échecs/min pour une IP,
`soc.yml`) et `LoginFailureSpike` (> 20/min au total, `availability.yml`), mais donner **≥ 10 échecs en 2 min** pour
l'attribution Loki (`SECURITY_MIN_EVENTS = 10`) et un **`anomaly_score` ≥ 0,8**. Le modèle v3 (auth-service : médiane
`login_failures_per_min` 0, échelle 1,0, β 3,27, `t80` 4,15) donne un score ≥ 0,8 dès `login_failures_per_min ≈ 4,1`.
Deux débits retenus : **9/min** (cas positif : ≤ 10/min donc pas de SOC, et 2 min × 9 ≈ 18 ≥ 10) et **5/min** (cas
négatif : l'anomalie se déclenche mais le total d'échecs reste < 10 sur la fenêtre Loki).

**Score prédit vs mesuré.** Le score **prédit en régime établi** est ~1,0 à 9/min et ~0,91 à 5/min. Le score **mesuré**
(celui que le moteur lit dans le journal `anomaly_detected`, écrit à la **transition** — donc pendant la montée du taux,
où `login_failures_per_min ≈ 4,8`) est **0,890 à 9/min** et **0,886 à 5/min**, tous deux ≥ 0,8. Ce qui **distingue
blocage et escalade n'est donc pas le score mais le compte d'attribution Loki sur 2 min** (10 ≥ seuil → blocage ;
8 < seuil → escalade).

*Cas positif (9/min, blocage par le chemin ML)* — incident `inc-20261020-095200-2dcd9b` :

| Étape | Temps depuis le début de l'attaque |
|---|---|
| `AnomalyDetected` `firing` (auth-service, score 0,890 ≥ 0,8) | +55,9 s |
| détection + triage (`dominant_feature=login_failures_per_min`) + décision | +64,7 s |
| **blocage effectué** (Loki : **10 événements en 2 min** depuis l'IP ≥ seuil 10) | +64,8 s |
| blocage vérifié | +65,3 s |
| transaction témoin OK → **rétabli et vérifié** | +65,8 s |
| expiration logique (TTL 90 s) / **levée effective** | +154,9 s / +161,7 s |

Aucun incident SOC (`AuthBruteForce`/`LoginFailureSpike`) n'a été créé ; attaquant `403 blocked_by_remediation`, témoin
tiers `200`, hôte `200` ; après la levée, attaquant `200`.

*Cas négatif (5/min, attribution trop faible → pas de blocage)* — incident `inc-20261020-095530-07efed` :

| Étape | Temps depuis le début de l'attaque |
|---|---|
| `AnomalyDetected` `firing` (auth-service, score 0,886 ≥ 0,8) | +80,1 s |
| détection + triage + **escalade** (`reason=no_offender`) | +88,9 s |

Décision du moteur : *« attaque (login_failures_per_min) sans IP dominante (meilleure : ('172.25.0.3', 8.0)) : attaque
distribuée, escalade »*. L'IP n'a que **8 échecs en 2 min** (< 10) : le moteur **n'exécute aucun blocage** et **escalade**
— l'attaquant reste servi (`200`). On a donc bien la garantie demandée : **pas de blocage sur une attribution faible**.
Effet attendu de cette escalade : elle incrémente `remediation_escalations_total{reason="no_offender"}`, ce qui fait
`firing` l'alerte `RemediationFailed` ; le moteur la traite comme une alerte **sur lui-même** (`nature=self`,
observation seule, **jamais de self-remédiation**) et l'incident se clôt de lui-même quand l'alerte retombe (fenêtre
`increase[10m]`).

## Bogues trouvés et corrigés

- **Conteneur en cours de démarrage désigné comme cible** (décrit ci-dessus) : corrigé, testé, et **vérifié en direct**
  (incident `inc-20261020-092442-9e870e`). C'est le seul bogue trouvé ; tous les scénarios passent (1, 2, 3, 4A, 4B, 4C
  positif et négatif). Le rejeu « force brute → anomalie de sécurité » (4C) n'a révélé aucun nouveau bogue.

**Nuance mesurée (comportement attendu, pas un bogue).** La **levée effective** d'un blocage se produit à
**TTL + au plus une période de fond** (`background_period_s`, 15 s) : c'est `expire()` qui réécrit le fichier et recharge
nginx. L'API `GET /api/state` reflète, elle, l'**expiration logique** au TTL (`WafBlocklist.active()` filtre les entrées
expirées en mémoire). D'où l'écart mesuré (ex. S1 : logique +121,5 s, effective +131,6 s). Cohérent avec
[waf-blocking.md](waf-blocking.md) (« le blocage dure au plus TTL + une période »).

## Limites restantes

- **NAT du labo** : sur la VM, tous les postes (attaquant, jury, opérateurs) arrivent avec la même IP
  `172.16.255.252` ; bloquer l'attaquant **bloque tout le monde** pendant le TTL (raison du TTL court : 60–120 s pour la
  démo). En dev local, chaque conteneur edge a sa propre IP, donc le blocage est **ciblé** : les chiffres ci-dessus ne
  reflètent pas l'effet collatéral du NAT. La transaction témoin du moteur part de la dmz (exclue) et reste donc valable
  pendant un blocage.
- **Pont de restauration** : éprouvé ici avec le **runner de développement** (`remediation_bridge_dev.py`), pas avec
  l'unité systemd durcie de la VM (`resilience-remediation-bridge.service`, root sans capacités). Les temps de
  restauration sur la VM peuvent différer légèrement (cf. [restauration-base.md](../../../docs/runbooks/restauration-base.md)).
- **Non rejoué sur la VM** : recette menée sur la pile locale ; à reproduire sur la VM du labo avant le jury (TODO infra).
- **Attaque répartie** : une attaque sur plusieurs IP n'est pas bloquée (escalade) — risque accepté dans l'EBIOS RM.
