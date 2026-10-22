# remediation-engine — moteur de remédiation automatique (pilier DEV / SÉCURITÉ)

Reçoit les alertes d'Alertmanager, **décide** d'une réponse dans une table explicite, **agit**, puis **prouve** que le
service métier est de nouveau utilisable : santé des conteneurs, sondes de bout en bout, puis transaction témoin
(inscription, connexion, virement, soldes) à travers le WAF. Un conteneur redémarré n'est jamais une preuve suffisante.

Deux familles de réponses, séparées dans le code, les journaux, les métriques et l'API (`nature`) :

| Nature | Situation | Réponse |
|---|---|---|
| `availability` | le service est en panne | **redémarrer** le maillon en panne (PostgreSQL d'abord s'il est en cause) |
| `compromise` | le service est attaqué ou ses données sont fausses | **bloquer** l'IP attaquante au WAF, **restaurer** la dernière sauvegarde saine |

Redémarrer un service attaqué ne corrige rien ; restaurer une base simplement arrêtée détruirait des données : le moteur
ne confond jamais les deux.

## Architecture

```
Prometheus ─┐                                 ┌─ docker-socket-proxy (réseau docker-api) ──▶ démon Docker
Loki ruler ─┴▶ Alertmanager ──POST /alerts──▶ │      restart / start / kill, lecture d'état — rien d'autre
               (jeton porteur)   202 immédiat │
                                 remediation-engine ──▶ volume waf-blocklist ──▶ WAF (map nginx, SIGHUP)
   tâche asynchrone par incident :            │
   décision → action → vérification           ├─ /bridge (pont hôte) ──▶ resilience-pg-restore (systemd sur la VM)
                                              ├─ Prometheus (probe_success), Loki (IP fautive, variable dominante ML)
                                              ├─ payment-api /internal/integrity (réseau app)
                                              └─ transaction témoin via http://waf:8080 (réseau dmz)
```

| Fichier | Rôle |
|---|---|
| `app/main.py` | webhook authentifié, API d'état en lecture seule, `/health`, `/metrics` |
| `app/decisions.py` | **table de décision** (une ligne par alerte), chaînes de dépendances, requêtes LogQL d'attribution |
| `app/engine.py` | incidents, décisions, actions sous verrou, anti-boucle, vérification, escalade, boucle de fond |
| `app/incidents.py` | machine d'états horodatée, garde anti-boucle, fichier d'état JSON (écriture atomique) |
| `app/actions/docker_proxy.py` | client minimal du proxy Docker (conteneurs retrouvés par labels Compose) |
| `app/actions/waf_block.py` | blocage d'IP au WAF ([docs/waf-blocking.md](docs/waf-blocking.md)) |
| `app/actions/db_restore.py` | client du pont de restauration ([runbook](../../docs/runbooks/restauration-base.md#restauration-automatique-moteur-de-remédiation)) |
| `app/clients.py`, `app/witness.py` | Prometheus (authentifié), Loki, intégrité ; transaction témoin |
| `app/config.py`, `app/metrics.py` | configuration (variables d'environnement, garde-fous anti-boucle) ; métriques `remediation_*` |
| `proxy/haproxy.cfg.template` | modèle haproxy durci du proxy Docker (voir « Modèle de sécurité ») |

## Table de décision

Elle couvre **toutes** les règles de `infra/prometheus/rules/*.yml` et `infra/loki/rules/fake/soc.yml` (un test
échoue si une alerte manque) ; elle est aussi servie par `GET /api/decision-table`. Les scénarios EBIOS RM
(`docs/governance/ebios-rm.md`) y sont rattachés.

| Alerte | Nature | Réponse | EBIOS |
|---|---|---|---|
| `ServiceDown` | availability | redémarrer le service (PostgreSQL d'abord s'il est arrêté ou en échec) ; chaîne saine et `up` revenu à 1 : vérification seule | S3 |
| `EndToEndProbeFailed` | availability | label `auth`/`payments`/`frontend` → `auth-service`/`payment-api`/`frontend` ; on répare le maillon en panne du parcours PostgreSQL → API → frontal → WAF | S3 |
| `HighErrorRate` | availability | redémarrer le service qui renvoie des 5xx (PostgreSQL d'abord s'il est en cause) | S3 |
| `DependencyFailures` | availability | base injoignable : redémarrer PostgreSQL s'il est arrêté/en échec, puis l'API **seulement si** elle ne revient pas seule dans le délai de grâce (30 s) | S4 |
| `HighLatencyP95` | availability | observer 3 min ; redémarrer seulement si l'alerte persiste | S3 |
| `LedgerIntegrityBroken`, `LedgerIntegrityViolationLogged` | compromise | confirmer la corruption : PostgreSQL sain **et** `/internal/integrity` = 409. Base injoignable (503, connexion refusée) = panne de disponibilité, reclassée et traitée comme `DependencyFailures`, **aucune restauration**. Corruption confirmée : `RestoreBridge.request_restore` ; pont absent : escalade (jamais de restauration improvisée) | S5 |
| `AuthBruteForce`, `InvalidTokenFlood`, `WafAttackBlocked` | compromise | bloquer au WAF l'IP du label `client_ip` (300 s) ; IP exclue (réseaux internes, passerelles) : escalade | S1, S2 |
| `LoginFailureSpike` | compromise | IP la plus fautive dans Loki (échecs `auth_failure`, 2 min) ; ≥ 10 échecs : blocage, sinon observation (attaque distribuée) | S1 |
| `AnomalyDetected` | triage | dernier journal `anomaly_detected` du détecteur : variable d'attaque (`login_failures_per_min`, `invalid_tokens_per_min`, `waf_blocks_per_min`, `client_errors_4xx_rate`) → IP fautive dans Loki et blocage ; variable de panne (`error_ratio_5xx`, `latency_p95`, `probe_failed`) → redémarrage du service ; co-alerte du frontal pendant un incident d'API → rattachée, sans action ; sinon observation et escalade | S1, S3 |
| `AnomalyDetectorDown` | availability | **un seul** redémarrage d'`anomaly-detector` par 30 min (sans état), aucune action métier | — |
| `AnomalyDetectorBlind` | observe | observer (source du détecteur injoignable : ni panne métier ni attaque) | — |
| `LedgerIntegrityCheckStale`, `HostDiskSpaceLow`, `HostMemoryLow`, `BackupMissing`, `BackupFailed` | operator | journaliser et escalader (`reason=policy`), aucune action | — |
| `RemediationFailed`, `RemediationEngineDown`, toute alerte `service=remediation-engine` ou `docker-socket-proxy` | self | journaliser uniquement : le moteur ne se remédie jamais lui-même (anti-boucle) | S6 |
| alerte inconnue | operator | escalade, aucune action | — |

Les alertes qui appellent la même réponse sur la même cible forment **un seul incident** (clé de corrélation) :
`ServiceDown` + `EndToEndProbeFailed` + `HighErrorRate` sur payment-api, ou `AuthBruteForce` + `WafAttackBlocked`
depuis la même IP. Seuls les services `postgres`, `auth-service`, `payment-api`, `frontend`, `waf` et
`anomaly-detector` peuvent être redémarrés ; un conteneur absent n'est jamais recréé (escalade).

## Machine d'états et anti-boucle

```
detected → decided ─┬─▶ acting → verifying ─┬─▶ recovered ──(alertes retombées)──▶ clos
                    │                       └─▶ failed ─┬─▶ decided (nouvelle tentative)
                    ├─▶ verifying (rien à faire)        └─▶ escalated ──(alertes retombées)──▶ clos
                    ├─▶ observing ──(persiste)──▶ decided
                    └─▶ escalated
```

- Chaque transition, décision, action et contrôle est daté dans la **chronologie** de l'incident (`timeline`), avec
  les preuves (états des conteneurs, sondes, étapes de la transaction témoin, variable dominante…).
- **Clôture** : quand toutes les alertes de l'incident sont retombées (`resolved`) **et** qu'il est rétabli et vérifié,
  escaladé ou observé. Pour un blocage d'IP, la retombée de `AuthBruteForce`/`WafAttackBlocked` (les requêtes bloquées
  n'atteignent plus ModSecurity ni les API) fait partie de la preuve.
- **Idempotence** : les notifications répétées d'Alertmanager (toutes les 5 min) sont comptées, sans nouvelle action.
  Une alerte encore active longtemps (90 s) après un rétablissement vérifié provoque une nouvelle évaluation.
- **Verrou par cible** (service, IP) : deux incidents n'agissent jamais en même temps sur le même conteneur. Le second
  refait son diagnostic sous verrou et constate le travail du premier (action réussie récente, chaîne saine) au lieu
  d'agir à son tour. Un conteneur déjà en cours de démarrage (`starting`) est attendu, pas redémarré.
- **Budget** par cible et par fenêtre glissante : 3 redémarrages / 10 min (20 s minimum entre deux), 3 blocages de la
  même IP / 10 min, 1 restauration / 15 min, 1 redémarrage du détecteur / 30 min ; au-delà, **escalade**.
- **Restauration en cours** (demande du moteur, ou runner de l'hôte occupé) : `resilience-pg-restore` arrête exprès les
  API ; aucun redémarrage de PostgreSQL ni des API n'est tenté avant la fin, puis le diagnostic est refait.
  Une restauration en échec (précondition refusée, quota du runner, script en échec) n'est jamais rejouée : escalade.
- **Escalade** : état `escalated`, journal `remediation_escalated`, métrique `remediation_escalations_total{reason}`,
  qui alimente l'alerte `RemediationFailed` (sauf `reason=policy`, escalade prévue par conception).
- **Persistance** : incidents, chronologies et anti-boucle sont écrits de façon atomique dans
  `/state/remediation-state.json` (volume nommé `remediation-state`, conteneur en lecture seule). Après un redémarrage
  du moteur, l'historique est conservé, les notifications répétées retrouvent leur incident et un incident interrompu
  en pleine action passe en `failed` puis est repris (sous anti-boucle).

## Vérification après chaque action

| Action | Contrôles, dans l'ordre |
|---|---|
| redémarrage d'un service métier | conteneurs de la chaîne `healthy` (via le proxy) → toutes les sondes `probe_success` à 1 (Prometheus) → transaction témoin |
| restauration | PostgreSQL et API `healthy` → `/internal/integrity` = 200 → sondes → transaction témoin |
| blocage d'IP | `WafBlocklist.verify` (configuration réellement chargée par le WAF) → sondes → transaction témoin |
| redémarrage du détecteur | conteneur `healthy` |

La **transaction témoin** (`app/witness.py`, même parcours que `tests/smoke_test.py`) passe par `http://waf:8080` :
deux utilisateurs neufs `temoin-…@remediation.local` (mots de passe générés à chaque fois), connexion, virement de
1,00 € avec `Idempotency-Key`, puis contrôle des deux soldes. Prometheus injoignable : contrôle des sondes marqué
« indisponible », la transaction témoin reste seule juge. Un contrôle en échec = tentative en échec (nouvelle tentative
sous anti-boucle, puis escalade).

## Sorties

| Sortie | Détail |
|---|---|
| `/metrics` | `remediation_actions_total{action,target,result}` (restart, start, block_ip, restore_db × success, failure, refused ; `target` borné : service Compose redémarrable, `waf` pour un blocage, `paydb` pour une restauration — jamais l'IP bloquée ni une valeur reçue dans une alerte), `remediation_duration_seconds{nature}` (détection = webhook reçu → rétablissement vérifié) et `remediation_alert_to_recovery_seconds{nature}` (déclenchement de l'alerte, `startsAt` → rétablissement vérifié : la durée du Clip Chrono, hors délai `for:` des règles), observées **seulement si le moteur a agi** (une vérification seule, « déjà redémarré par… » ou « IP déjà bloquée », compterait deux fois la même panne), seaux de 0,5 s à 20 min ; `remediation_incidents_open`, `remediation_verification_total{result}`, `remediation_escalations_total{reason}`, `remediation_alerts_received_total{status}`, `remediation_webhook_rejected_total{reason}`, `remediation_blocked_ips` (mise à jour au blocage puis à chaque passage de la boucle de fond, 15 s), `remediation_dependency_up{dependency}` ; affichées, avec le journal ci-dessous, dans la rangée « Remédiation » du tableau Grafana « Santé du service » (`infra/grafana/generate_dashboards.py`) |
| Journaux JSON (Loki) | une ligne par événement, `event_type=remediation_*` : `detected`, `correlated`, `duplicate`, `decided`, `observing`, `action`, `action_failed`, `verification`, `recovered`, `escalated`, `closed`, `alert_resolved`, `webhook`, `webhook_rejected`… toujours avec `incident_id`, `alertname`, `nature`, `state`, `target_service` |
| `GET /api/state` | incidents ouverts, 20 derniers incidents clos, IP bloquées (expiration, motif, incident), état du pont de restauration (runner, heartbeat, restauration en cours), dépendances |
| `GET /api/incidents?limit=50&open=false` | incidents résumés, du plus récent au plus ancien |
| `GET /api/incidents/{id}` | incident complet : alertes, décision, actions, chronologie horodatée |
| `GET /api/decision-table` | la table de décision |
| `GET /health` | 200 tant que le service sert ; `status=degraded` et la liste `degraded` si le proxy, Prometheus, Loki, le WAF, le pont, le fichier d'état ou le jeton manquent (le déploiement `--wait` n'échoue pas pour autant) |

L'API est **en lecture seule** : aucune route ne déclenche ni n'annule une action (un test le vérifie). Le futur
dashboard de supervision la lira par son back-for-front ; aucun port n'est publié.

Le schéma OpenAPI du webhook et de l'API d'état est versionné dans
[`docs/api/remediation-engine.openapi.json`](../../docs/api/remediation-engine.openapi.json) (pas de `/docs` en direct) :
`python scripts/export_openapi.py` le régénère sans secret ni stack, `--check` (CI et `tests/unit/test_openapi_docs.py`)
échoue s'il ne correspond plus au code. Le webhook vérifiant lui-même son jeton, son authentification porteur, son
corps et ses refus (400, 401, 413, 503) sont ajoutés par le script d'export, sauf si l'application les déclare.

## Modèle de sécurité

Le moteur a les droits les plus élevés de la plateforme : le détourner permettrait de couper les services (EBIOS :
« moteur de remédiation détourné », G4 ; S6 « fausses alertes »).

- **Webhook authentifié** : Alertmanager envoie `Authorization: Bearer <jeton>` (`http_config.authorization.
  credentials_file`, secret `remediation_webhook_token` généré par `scripts/init_secrets.py`, monté dans les deux
  conteneurs). Comparaison à temps constant (`hmac.compare_digest`), jeton relu à chaque appel (rotation sans
  redémarrage), refus 401 journalisé (`remediation_webhook_rejected`, IP source) et compté ; jeton absent : 503, le
  moteur ne traite rien (fermé par défaut). Corps limité à 1 Mio.
- **Aucune interface d'administration** : pas de route d'action, pas de port publié. Le moteur n'agit que sur alerte, et
  seulement selon la table (alerte inconnue : escalade ; alerte sur le moteur lui-même : rien).
- **Pas de socket Docker** : le moteur parle à `tecnativa/docker-socket-proxy:v0.5.0`, seul conteneur qui monte
  `/var/run/docker.sock` (en `:ro`), sur le réseau `docker-api` **interne** partagé avec le seul moteur.
  Variables : `CONTAINERS=1`, `POST=1`, `ALLOW_RESTARTS=1`, `ALLOW_START=1`, tout le reste à 0 (`EVENTS`, `PING`,
  `VERSION` compris). Or, dans le modèle haproxy d'origine, `CONTAINERS=1` + `POST=1` ouvre **toute** la section
  `/containers` (création d'un conteneur privilégié = root sur l'hôte, suppression, archive…). Le modèle durci
  `proxy/haproxy.cfg.template` (monté en lecture seule) n'autorise en plus que `GET /containers/json`,
  `GET /containers/{id}/json` et `POST /containers/{id}/(restart|start|kill)` ; vérifié en direct : `POST
  /containers/create`, `DELETE /containers/…`, `…/exec`, `…/update`, `…/stop`, `…/logs`, `/images`, `/info`,
  `/events`, `/version` → 403.
- **Cibles restreintes par le moteur** : conteneurs retrouvés par labels Compose (projet `COMPOSE_PROJECT` + service),
  jamais par un nom ou un identifiant reçu dans une alerte ; liste blanche de services redémarrables ; IP validées,
  réseaux internes jamais bloqués (liste d'exclusion de `WafBlocklist`).
- **Restauration sans exécution** : le moteur dépose une demande dans `/bridge` ; le runner de l'hôte la valide
  (409 exigé, une à la fois, 3 par heure) et exécute `resilience-pg-restore` ([runbook](../../docs/runbooks/restauration-base.md)).
- **Conteneur durci** : utilisateur 10001, `read_only`, `cap_drop: ALL`, `no-new-privileges`, `/tmp` en tmpfs ; seuls
  `/state`, `/waf-blocklist` et `/bridge` sont inscriptibles. Secrets en fichiers (`prometheus_password`, jeton).

**Risques résiduels**
- Un moteur compromis peut redémarrer, démarrer ou signaler (`kill`) **n'importe quel conteneur de l'hôte** (le proxy
  ne filtre pas par conteneur), lire leur `inspect` (variables d'environnement comprises : nos services n'y mettent
  aucun secret, mais d'autres conteneurs de l'hôte le pourraient), bloquer des IP au WAF pendant 300 s et demander une
  restauration (que le runner refuse sans corruption réelle). Il ne peut ni créer de conteneur, ni exécuter de commande,
  ni lire de volume. Piste : un proxy à liste blanche par conteneur (ex. `wollomatic/socket-proxy`).
- Le proxy tourne en root (nécessaire pour ouvrir le socket) ; il n'a aucune capability et un système de fichiers en
  lecture seule. Son modèle haproxy est une copie de celle de l'image v0.5.0 : à revoir à chaque changement de version.
- Le jeton du webhook est partagé (pas de mTLS) ; quiconque lit `secrets/` sur l'hôte peut forger des alertes, qui ne
  déclenchent toutefois que les réponses de la table, bornées par l'anti-boucle.
- L'API d'état est joignable sans authentification depuis les réseaux `obs`, `app` et `dmz` (lecture seule : incidents,
  IP bloquées). Le back-for-front du dashboard devra y ajouter son propre contrôle d'accès.
- Au labo, tous les clients arrivent par la même IP NAT (172.16.255.252) : la bloquer coupe tout le monde pendant 300 s
  (raison de la durée courte, voir [docs/waf-blocking.md](docs/waf-blocking.md)). Une attaque répartie sur plusieurs IP
  n'est pas bloquée (escalade), risque accepté dans l'EBIOS RM.

## Blocage d'IP au WAF (résumé de [docs/waf-blocking.md](docs/waf-blocking.md))

Le moteur écrit la liste `blocked-ips.conf` (lignes `"<ip>" 1;` uniquement, IP validées) dans le volume
`waf-blocklist`, monté en lecture seule dans le WAF où elle alimente un `map` nginx ; il recharge nginx à chaud par
`SIGHUP` (`DockerProxy.signal`). L'IP bloquée reçoit `403 {"detail":"blocked_by_remediation"}` **avant ModSecurity**
(journal `event_type=waf_remediation_block`), si bien que les alertes de sécurité retombent. La vérification interroge le
port interne 8081 du WAF, qui répond selon la configuration réellement chargée. Expiration automatique (300 s par
défaut, `WAF_BLOCK_TTL_SECONDS`) ; motifs et incidents dans `blocked-ips.json` (survit au redémarrage du moteur) ; jamais
bloqués : boucle locale, dmz, réseaux du moteur, passerelles des réseaux du WAF (complétés par `WAF_BLOCK_ALLOWLIST`).

## Lancer

```bash
python scripts/init_secrets.py                    # crée secrets/remediation_webhook_token (conserve les autres)
python3 scripts/remediation_bridge_dev.py init    # pont de restauration local (avant le premier up), puis `run` pour le runner
docker compose up -d --build                      # moteur + docker-socket-proxy ; healthy même sans pont ni Loki
docker compose exec remediation-engine python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/api/state').read().decode())"
```

Variables principales (valeurs par défaut dans `docker-compose.yml`) : `COMPOSE_PROJECT`, `DOCKER_PROXY_URL`,
`PROMETHEUS_URL` / `PROMETHEUS_USER` / `PROMETHEUS_PASSWORD_FILE`, `LOKI_URL`, `PAYMENT_API_URL`, `WITNESS_BASE_URL`,
`WEBHOOK_TOKEN_FILE`, `STATE_FILE`, `WAF_BLOCKLIST_PATH`, `WAF_BLOCK_TTL_SECONDS`, `WAF_BLOCK_ALLOWLIST`,
`REMEDIATION_BRIDGE_PATH`, `RESTORE_TIMEOUT_SECONDS`, `RESTART_MAX_ATTEMPTS` / `RESTART_WINDOW_SECONDS` /
`RESTART_COOLDOWN_SECONDS`, `SECURITY_MIN_EVENTS`, `LATENCY_PERSIST_SECONDS`.

## Tester

- Unitaires (sans la stack, faux proxy Docker / WAF / pont / Prometheus / Loki / témoin) :
  `.venv/bin/python -m pytest tests/unit/test_remediation_engine.py` — table de décision pour chaque alerte, webhook
  authentifié, machine d'états, anti-boucle et verrou, idempotence, corruption vs panne de base, routage des anomalies,
  vérification en échec puis escalade, persistance après redémarrage, absence de route de modification, client du proxy
  Docker et transaction témoin contre de faux serveurs HTTP. Les actions ont leurs propres fichiers :
  `tests/unit/test_waf_block.py` (blocage WAF) et `tests/unit/test_db_restore.py` (client du pont et runner de l'hôte) ;
  `tests/unit/test_openapi_docs.py` vérifie que `docs/api/remediation-engine.openapi.json` est à jour.
- En direct (disponibilité) : `docker compose stop payment-api`, puis suivre `GET /api/incidents` : `ServiceDown` et
  `EndToEndProbeFailed` forment un incident, payment-api est redémarré, vérifié (sondes + témoin) puis clos à la retombée
  des alertes. Mesuré sur la pile locale : **rétabli et vérifié 46 s après l'arrêt** (alerte à +31 s, reçue à +39 s,
  conteneur sain à +45 s, témoin réussi à +46 s), incident clos à +69 s.
- En direct (sécurité et compromission) : rejeu complet **par la chaîne d'alertes** (force brute, injections, registre
  corrompu, anomalie ML) avec des outils reproductibles — [`scripts/scenarios/attack.py`](../../scripts/scenarios/attack.py)
  (attaques, bibliothèque standard, `--target`, mots de passe générés) et
  [`scripts/scenarios/run_recette.py`](../../scripts/scenarios/run_recette.py) (orchestrateur hôte qui collecte les
  preuves). Méthode, tables de mesures par scénario, bogues corrigés et limites (poste attaquant simulé, NAT du labo) :
  **[docs/recette.md](docs/recette.md)**. Relevés du 20/10 sur la pile locale (poste attaquant = conteneur `edge`) :
  force brute → `AuthBruteForce` → **IP bloquée au WAF ~29 s** après le début de l'attaque (alerte à +21 s), blocage
  vérifié, sondes et témoin OK, attaquant `403 blocked_by_remediation`, **levée automatique au TTL** ; injections →
  `WafAttackBlocked` → blocage en ~32 s ; registre corrompu → `LedgerIntegrityBroken` (Prometheus) et
  `LedgerIntegrityViolationLogged` (Loki) corrélées en **un seul** incident → **une** restauration par le pont, intégrité
  revenue à `200` en ~32 s ; anomalie ML de sécurité → blocage par le chemin ML, ou constat « déjà bloquée » quand le SOC
  a bloqué avant.
