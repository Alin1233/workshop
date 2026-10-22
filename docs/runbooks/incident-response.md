# Runbook — réponse à incident

Ce runbook dit à l'opérateur, alerte par alerte, ce que signifie l'alerte, ce que le moteur de remédiation fait seul,
comment vérifier que le service est rétabli et quoi faire à la main quand le moteur escalade ou ne tourne plus. Il
couvre les **21 alertes** des fichiers de règles : 16 règles Prometheus (`infra/prometheus/rules/availability.yml` et
`infra/prometheus/rules/host.yml`) et 5 règles SOC évaluées par Loki (`infra/loki/rules/fake/soc.yml`). Les réponses
automatiques décrites ici sont celles du code du moteur (`services/remediation-engine/app/decisions.py` pour la table de
décision, `app/engine.py` pour son exécution), table que le moteur sert aussi par `GET /api/decision-table`. La
restauration de la base est détaillée dans le runbook [restauration-base.md](restauration-base.md), que ce document ne
recopie pas. Les durées cibles de reprise (RTO, RPO) sont dans le [PCA/PRA](../governance/pca-pra.md).

Les commandes sont écrites pour le poste de développement, à la racine du dépôt, avec les secrets dans `secrets/`. Sur
la VM PC Hôte (`172.16.147.10`), l'opérateur se connecte par `ssh resilience@172.16.147.10`, se place dans la version
active avec `cd "$(readlink -f /opt/resilience-alpha/current)"`, préfixe les commandes Docker par `sudo` (l'utilisateur
`resilience` n'est pas dans le groupe `docker`) et trouve les secrets dans `/opt/resilience-alpha/shared/secrets/<nom>`,
lisibles par root seulement (`sudo cat …`). L'application est servie par le WAF sur le port 8080 (8088 sur un poste dont
le fichier `.env` fixe `FRONT_PORT=8088`).

## 1. Vue d'ensemble

### La chaîne de réponse : alerte, Alertmanager, moteur, action, vérification

Une alerte naît dans Prometheus, qui évalue ses règles toutes les 10 s sur les métriques et les sondes de bout en bout,
ou dans le ruler Loki, qui évalue les règles SOC toutes les 15 s sur les journaux. Elle passe à l'état `firing` quand sa
condition est vraie depuis la durée `for:` de la règle. Alertmanager la regroupe alors par `alertname` et `service`,
attend 5 s (`group_wait`) et l'envoie au webhook du moteur de remédiation (`POST /alerts`, authentifié par le jeton du
fichier `secrets/remediation_webhook_token`). Alertmanager renvoie une alerte toujours active toutes les 5 min
(`repeat_interval`) et prévient aussi le moteur quand elle retombe (`resolved`).

Le moteur ouvre un **incident** et le fait avancer dans une machine d'états horodatée : `detected` (alerte reçue),
`decided` (réponse choisie dans la table de décision), `acting` (action en cours), `verifying` (preuves de reprise),
puis `recovered` (rétabli et vérifié) ou `failed` (tentative en échec, nouvelle tentative sous anti-boucle), et enfin
`escalated` quand il rend la main à l'opérateur. Un incident reste en `observing` quand la table prévoit de surveiller
sans agir. Un incident est clos quand toutes ses alertes sont retombées et qu'il est rétabli, escaladé ou observé.

Un conteneur redémarré n'est jamais une preuve suffisante. Après chaque action, le moteur vérifie dans l'ordre que les
conteneurs concernés sont `healthy` (par le proxy Docker, 90 s au plus), que toutes les sondes de bout en bout
`probe_success` sont revenues à 1 dans Prometheus (60 s au plus), puis il joue une **transaction témoin** à travers le
WAF : deux utilisateurs neufs `temoin-…@remediation.local`, connexion, virement de 1,00 €, contrôle des deux soldes,
soit le même parcours que `tests/smoke_test.py`. Après une restauration, il contrôle en plus que le registre répond 200
sur `/internal/integrity` ; après un blocage d'IP, que le WAF a réellement chargé la nouvelle liste. Mesure de référence
sur la pile locale (arrêt de payment-api) : alerte à +31 s, webhook reçu à +39 s, conteneur sain à +45 s, transaction
témoin réussie et incident rétabli à +46 s, incident clos à +69 s.

### Deux familles de réponses : disponibilité et compromission

Le moteur sépare deux natures de réponse, visibles dans le champ `nature` des incidents, des journaux et des métriques.
Une réponse de **disponibilité** (`availability`) traite un service en panne : le moteur **redémarre** le maillon en
panne, PostgreSQL d'abord s'il est en cause, puis l'API, puis le frontal et le WAF quand l'alerte vient d'une sonde de
bout en bout. Une réponse de **compromission** (`compromise`) traite un service attaqué ou des données fausses : le
moteur **bloque** l'IP attaquante au WAF, ou **restaure** la dernière sauvegarde saine de la base. Redémarrer un service
attaqué ne corrige rien, et restaurer une base simplement arrêtée détruirait les écritures légitimes faites depuis la
sauvegarde : c'est pourquoi le moteur confirme toujours qu'une alerte d'intégrité est une vraie corruption (PostgreSQL
sain et `/internal/integrity` en 409) avant de restaurer.

Les autres alertes n'entraînent aucune action sur le service métier. Les alertes du PC Hôte, des sauvegardes et
`LedgerIntegrityCheckStale` sont **escaladées par conception** (motif `policy`) : le moteur les journalise et laisse
l'opérateur agir. `AnomalyDetectorBlind` est seulement **observée**. `AnomalyDetected` est **triée** selon la variable
dominante du modèle ML, puis traitée comme une panne ou comme une attaque. Les alertes qui visent le moteur lui-même
(`RemediationFailed`, `RemediationEngineDown`, et toute alerte qui porte `service=remediation-engine` ou
`service=docker-socket-proxy`) ne sont **jamais remédiées** par lui (anti-boucle) : elles s'adressent à l'opérateur.
Une alerte absente de la table de décision est escaladée sans action (motif `unknown_alert`).

### Les garde-fous du moteur : corrélation, verrous, anti-boucle

Les alertes qui appellent la même réponse sur la même cible forment un seul incident. `ServiceDown`,
`EndToEndProbeFailed`, `HighErrorRate` et `DependencyFailures` visant payment-api partagent la clé `service:payment-api` ;
`AuthBruteForce`, `InvalidTokenFlood` et `WafAttackBlocked` venant de la même IP partagent la clé `ip:<IP>` ;
`LedgerIntegrityBroken` et `LedgerIntegrityViolationLogged` partagent la clé `integrity:payment-api`. Deux incidents
n'agissent jamais en même temps sur le même conteneur (verrou par cible), et une action réussie d'un autre incident sur
la même cible depuis moins de 120 s transforme la décision en « vérification seule ». Un conteneur en cours de
démarrage (`starting`) est attendu puis re-diagnostiqué, jamais redémarré d'office.

Le budget anti-boucle est le suivant : 3 redémarrages d'un même service sur 10 min glissantes, avec 20 s au moins entre
deux redémarrages, et 3 tentatives au plus par incident, espacées de 10 s ; 3 blocages de la même IP sur 10 min ; un seul
redémarrage du détecteur d'anomalies sur 30 min ; une seule restauration sur 15 min côté moteur, et 3 restaurations par
heure côté runner de l'hôte. Une restauration en échec n'est jamais rejouée automatiquement. Au-delà de ces limites,
l'incident est escaladé. Seuls `postgres`, `auth-service`, `payment-api`, `frontend`, `waf` et `anomaly-detector`
peuvent être redémarrés par le moteur, et un conteneur absent n'est jamais recréé par lui (escalade `container_missing`).

### Ce que l'opérateur fait et ne fait pas pendant que le moteur agit

Tant qu'un incident est en `decided`, `acting` ou `verifying`, l'opérateur **observe** et ne lance aucune action
concurrente sur la même cible : pas de `docker compose restart`, pas de `restart_service.yml`, pas de blocage manuel.
Une action manuelle en parallèle fausse le diagnostic du moteur (il voit un conteneur `starting` ou une chaîne saine
qu'il n'a pas réparée) et brouille la chronologie qui servira de preuve. En particulier, l'opérateur ne **redémarre
jamais les API pendant une restauration de la base** : `resilience-pg-restore` arrête volontairement `auth-service` et
`payment-api` pendant qu'il recrée `authdb` et `paydb`, et les relancer au milieu de l'opération les connecterait à une
base en cours de recréation. Le moteur ne sait qu'une restauration est en cours que lorsqu'il l'a demandée lui-même :
avant de lancer une restauration à la main, il faut poser un silence ciblé (voir la section « Restauration lancée par
l'opérateur »).

Sur le dashboard de supervision (http://127.0.0.1:8091), le moteur traite l'incident quand le bandeau est ambre
**« Remédiation en cours »** avec une étape « Action : … » ou « Vérification : … », que la tuile « Moteur de remédiation » est bleue
(en action) et que la chronologie de la reprise montre la décision et l'action en cours. Pendant une restauration
demandée par le moteur, les tuiles des API et de PostgreSQL passent en bleu « arrêtée volontairement pendant la
restauration » et la tuile du pont affiche « restauration en cours ». Un bandeau rouge **« Incident en cours »** avec
une étape « Décision : … » ou « Observation : … » signifie que l'incident est pris en compte sans action en cours
(observation, attente de la retombée de l'alerte, maillon qui démarre).

### Ce que voit le client pendant un incident

Le front interroge toutes les 5 s les deux `/health` (authentification et paiements) et affiche l'état du service :
« Service dégradé » quand une seule des deux API est en panne, « Service indisponible » quand les deux échouent
(PostgreSQL arrêté, restauration de la base en cours), puis il revient seul à la normale. Quand PostgreSQL est arrêté,
les API ne plantent pas : elles répondent 503 `database_unavailable` (jamais une erreur 500), leur `/health` passe en
503, et elles reviennent seules dès que la base répond de nouveau, car leurs connexions sont testées avant usage. Une IP
bloquée par le moteur reçoit `403 {"detail":"blocked_by_remediation"}` sur toutes les pages.

Un client peut renvoyer un virement après un incident sans risque d'être débité deux fois : un virement est une seule
transaction (entier ou absent), l'en-tête `Idempotency-Key` est obligatoire et le formulaire renvoie la **même** clé
après un incident, si bien que le second envoi est reconnu et jamais débité une seconde fois. C'est le message à donner
aux clients pendant une panne ; le détail des messages affichés est dans le [PCA/PRA](../governance/pca-pra.md).

### Reconnaître une reprise automatique d'une escalade

Une **reprise automatique** se lit à trois endroits concordants. Le bandeau du dashboard de supervision passe au vert
**« Service rétabli »** (« Rétabli et vérifié — en attente de la retombée des alertes »), puis l'incident est clos et le
bandeau revient à « Opérationnel » 3 min plus tard. L'incident a l'issue `recovered` dans « Derniers incidents » et dans
l'API d'état du moteur. Grafana pose une annotation verte « Rétabli et vérifié » sur les graphiques du tableau « Santé
du service ». L'opérateur n'a rien à faire, sinon consigner l'incident (voir « Après l'incident »).

Une **escalade** demande un humain. Le bandeau affiche « Incident en cours » avec l'étape **« Escaladé à l'opérateur :
<motif> »**, l'incident a l'issue `escalated`, les panneaux « Actions en échec » ou « Escalades à traiter » de la rangée
« Remédiation automatique » de Grafana passent au rouge et l'alerte `RemediationFailed` se déclenche. Les escalades
prévues par conception (motif `policy` : PC Hôte, sauvegardes, contrôle d'intégrité figé) ne déclenchent pas
`RemediationFailed` ; elles apparaissent sur le dashboard en remarque « incident d'exploitation ouvert ». **Aucune
notification humaine n'est envoyée** : Alertmanager n'a qu'un destinataire, le moteur. Une escalade n'est donc vue que si
quelqu'un regarde le dashboard de supervision ou Grafana ; pendant la démonstration, un opérateur garde l'écran de
supervision sous les yeux.

### À qui escalader

Le premier niveau est l'**opérateur d'astreinte** (dans le démonstrateur, l'équipe présente), qui suit le dashboard et
applique ce runbook ; les responsabilités détaillées sont dans le RACI du [PCA/PRA](../governance/pca-pra.md). Il escalade selon la
nature du problème : au **responsable infrastructure** (pilier Infrastructure) pour la VM, Docker, le disque, la
mémoire, les sauvegardes, le pont de restauration et les playbooks Ansible ; au **responsable sécurité** (pilier
Sécurité, fonction SOC) pour toute compromission, tout blocage d'IP douteux, toute attaque non bloquée et toute suspicion
sur le moteur ou sur les secrets ; au **responsable développement** pour un défaut applicatif, un registre incohérent
sans cause externe ou un comportement anormal du moteur de remédiation ; au **référent IA/Data** pour le détecteur
d'anomalies et son modèle. Un incident qui touche les données ou les fonds, ou qui dure au-delà de quelques minutes, est
remonté à la **cellule de crise** : le pilier Transformation prépare la classification et la notification DORA, la
Direction les valide (voir « Après l'incident »).

## 2. Où regarder

### Accès aux interfaces de gestion par tunnel SSH

Les interfaces de gestion ne sont publiées que sur `127.0.0.1` de la VM et demandent toutes le compte `admin`, avec un
mot de passe propre à chaque interface. Depuis le poste de l'opérateur, un seul tunnel SSH les rend joignables sur les
mêmes ports locaux ; le mot de passe se lit sur la VM, par exemple pour le dashboard de supervision :

```bash
ssh -N -L 8091:127.0.0.1:8091 -L 3000:127.0.0.1:3000 -L 9093:127.0.0.1:9093 -L 9090:127.0.0.1:9090 \
    -L 3100:127.0.0.1:3100 -L 8090:127.0.0.1:8090 resilience@172.16.147.10
ssh resilience@172.16.147.10 sudo cat /opt/resilience-alpha/shared/secrets/supervision_password
```

Le dashboard de supervision est sur le port 8091 (`secrets/supervision_password`), Grafana sur le port 3000
(`secrets/grafana_admin_password`), Alertmanager sur le port 9093 (`secrets/alertmanager_password`), Prometheus sur le
port 9090 (`secrets/prometheus_password`), Loki sur le port 3100 derrière loki-proxy (`secrets/loki_password`) et
l'assistant RAG sur le port 8090 (`secrets/ops_assistant_password`). Le moteur de remédiation n'a aucun port publié :
son API d'état se lit depuis son conteneur (voir plus bas).

### Dashboard de supervision (port 8091)

Le dashboard de supervision est l'écran à regarder en premier pendant un incident : http://127.0.0.1:8091, compte
`admin`, mot de passe dans `secrets/supervision_password`, sur la VM par le tunnel `ssh -N -L 8091:127.0.0.1:8091
resilience@172.16.147.10`. Il se rafraîchit toutes les 2 s et ne fait que lire. Le bandeau donne l'état global
(« Opérationnel », « Incident en cours », « Remédiation en cours », « Service rétabli ») avec l'étape en cours et la
décision du moteur ; la carte des composants montre le parcours client (WAF, frontal, auth-service, payment-api,
PostgreSQL) et la chaîne de résilience (observation, détecteur ML, moteur, pont de restauration) ; la chronologie de la
reprise est horodatée par le moteur ; les panneaux listent les alertes actives (Prometheus et SOC Loki, y compris celles
en confirmation, silences signalés), les IP bloquées au WAF avec le compte à rebours de leur levée, les événements Loki
en direct et les derniers incidents avec leur issue.

### Grafana : tableaux « Santé du service » et « SOC » (port 3000)

Grafana est sur http://127.0.0.1:3000 (compte `admin`, mot de passe dans `secrets/grafana_admin_password`, tunnel
`-L 3000:127.0.0.1:3000`). Pendant un incident, on consulte deux tableaux de bord. Le tableau **« Resilience-Alpha —
Santé du service »** répond à la question « le service est-il utilisable ? » : rangée des sondes de bout en bout à
travers le WAF (parcours client, intégrité du registre, processus API, alertes actives, disponibilité avant, pendant et
après l'incident), puis rangée **« Remédiation automatique »**, puis « Trafic et performances » (requêtes par service et
code, latence p95), « Métier », « PC Hôte et sauvegardes » et « Alertes et journaux ». Le tableau **« Resilience-Alpha —
SOC »** montre les événements de sécurité : compteurs sur 15 min (échecs d'authentification, requêtes bloquées par le
WAF, violations d'intégrité, pannes de dépendance), échecs d'authentification et blocages WAF par IP source, codes HTTP
du frontal, top 10 des IP sources, événements de sécurité applicatifs et journal d'audit du WAF (ModSecurity).

La rangée « Remédiation automatique (moteur : alerte → décision → action → vérification → rétabli ou escalade) » du
tableau « Santé du service » suit le moteur : incidents ouverts, IP bloquées, actions en échec et escalades à traiter
(rouges dès la première), état du moteur et de ses six dépendances (proxy Docker, Prometheus, Loki, liste de blocage du
WAF, pont de restauration, fichier d'état), actions par type, cible et résultat, escalades par motif, vérifications
réussies ou en échec, durées « détection → rétablissement vérifié » et « alerte → rétablissement vérifié », alertes
reçues et refus du webhook, requêtes refusées par le blocage d'IP, et journal du moteur mis en forme. Des annotations
marquent sur tous les graphiques l'ouverture d'un incident (orange), un échec ou une escalade (rouge) et un
rétablissement vérifié (vert).

### Alertmanager (port 9093)

Alertmanager est sur http://127.0.0.1:9093 (compte `admin`, mot de passe dans `secrets/alertmanager_password`, tunnel
`-L 9093:127.0.0.1:9093`). Il montre les alertes actives reçues de Prometheus et du ruler Loki, et les silences. C'est
là que les alertes restent visibles quand le moteur est arrêté. Le compte `admin` permet aussi de poser des silences, et
un silence empêche le moteur de recevoir les alertes qu'il couvre : on ne pose qu'un silence ciblé et court, selon la
procédure de la section « Restauration lancée par l'opérateur ».

### Prometheus (port 9090)

Prometheus est sur http://127.0.0.1:9090 (compte `admin`, mot de passe dans `secrets/prometheus_password`, tunnel
`-L 9090:127.0.0.1:9090`). La page « Alerts » donne l'état de chaque règle (inactive, `pending` pendant la durée `for:`,
`firing`). Les requêtes PromQL utiles pendant un incident sont `ALERTS{alertstate="firing"}` (alertes actives),
`probe_success{job="blackbox-http"}` (parcours client par sonde : `auth`, `payments`, `frontend`),
`up{job=~"auth-service|payment-api"}` (processus des API), `payment_ledger_integrity_ok` (registre cohérent à 1),
`anomaly_score` et `anomaly_threshold` (score ML par service et seuil 0,8), `remediation_incidents_open` et
`remediation_dependency_up` (moteur).

### Loki : requête des échecs d'authentification

Les journaux se consultent dans Grafana, menu « Explore », source de données Loki, ou par l'API de Loki derrière
loki-proxy sur http://127.0.0.1:3100 (compte `admin`, mot de passe dans `secrets/loki_password`). La requête Loki qui
retrouve les **échecs d'authentification** (mauvais mots de passe sur auth-service) est
`{service="auth-service", event_type="auth_failure"}`. Pour compter les échecs d'authentification par IP source sur une
minute, exactement comme la règle `AuthBruteForce`, la requête est
`sum by (client_ip) (count_over_time({service="auth-service", event_type="auth_failure"} | json client_ip="client_ip" [1m]))`.
Les jetons invalides refusés par payment-api portent le même type d'événement : `{service="payment-api",
event_type="auth_failure"}` ; la requête `{event_type="auth_failure"}` montre les échecs des deux services ensemble.

```bash
curl -s -G -u "admin:$(cat secrets/loki_password)" http://127.0.0.1:3100/loki/api/v1/query \
  --data-urlencode 'query=sum by (client_ip) (count_over_time({service="auth-service", event_type="auth_failure"} | json client_ip="client_ip" [1m]))'
```

### Loki : requêtes des blocages du WAF

Les requêtes bloquées par le WAF lui-même (ModSecurity, HTTP 403, requête interrompue) se comptent par IP source avec la
même requête que la règle `WafAttackBlocked` :
`sum by (client_ip) (count_over_time({service="waf"} |= "\"transaction\"" | json client_ip="transaction.client_ip", code="transaction.response.http_code", interrupted="transaction.is_interrupted" | __error__="" | code="403" | interrupted="true" [2m]))`.
Le journal d'audit complet du WAF se lit avec `{service="waf"} |= "\"transaction\""`. Les requêtes d'une IP bloquée par
le moteur, refusées avant ModSecurity avec `403 blocked_by_remediation`, ont leur propre événement :
`{service="waf", event_type="waf_remediation_block"}`, et se comptent par IP avec
`sum by (client_ip) (count_over_time({service="waf", event_type="waf_remediation_block"} | json [5m]))`.

### Loki : journaux du moteur de remédiation et du détecteur

Chaque étape du moteur de remédiation est une ligne JSON `event_type=remediation_*` qui rappelle l'incident, l'alerte,
la nature et la cible. Tous les événements du moteur se lisent avec
`{service="remediation-engine", event_type=~"remediation_.+"} | json`, les escalades avec
`{service="remediation-engine", event_type="remediation_escalated"} | json` (champs `reason` et `explanation`), et
toute l'histoire d'un incident avec `{service="remediation-engine"} | json | incident_id="inc-20261020-123035-fc6254"`.
Les franchissements de seuil du détecteur d'anomalies, avec la variable dominante, se lisent avec
`{service="anomaly-detector", event_type="anomaly_detected"} | json | target_service="payment-api"`. Les violations
d'intégrité du registre se lisent avec `{service="payment-api", event_type="integrity_violation"} | json`, et les pannes
de base de données vues par les API avec `{event_type="dependency_failure"}`.

### État du moteur de remédiation (API interne)

Le moteur de remédiation n'a pas de port publié : son API d'état, en lecture seule, se lit depuis son propre conteneur
avec `docker compose exec` (sur la VM : `sudo docker compose exec` depuis la version active). La première commande
résume l'état : incidents ouverts avec leur décision, IP bloquées, état du pont de restauration (disponible, occupé).
La deuxième affiche la chronologie horodatée d'un incident. La troisième donne la santé du moteur et la liste de ses
dépendances en défaut (`status=degraded`).

```bash
docker compose exec -T remediation-engine python -c "import json,urllib.request as u; s=json.load(u.urlopen('http://127.0.0.1:8000/api/state')); [print(i['id'], i['alertname'], i['service'], i['state'], (i['decision'] or {}).get('reason')) for i in s['open_incidents']]; print('ouverts:', len(s['open_incidents']), '| IP bloquées:', s['blocked_ips'], '| pont:', s['bridge'].get('available'), s['bridge'].get('busy'))"
docker compose exec -T remediation-engine python -c "import json,sys,urllib.request as u; d=json.load(u.urlopen('http://127.0.0.1:8000/api/incidents/'+sys.argv[1])); [print(e['at'][11:23], e['state'], e['event'], json.dumps(e.get('detail',{}), ensure_ascii=False)[:160]) for e in d['timeline']]" inc-20261020-123035-fc6254
docker compose exec -T remediation-engine python -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8000/health').read().decode())"
```

### Assistant RAG des opérateurs (port 8090)

L'assistant RAG est sur http://127.0.0.1:8090 (compte `admin`, mot de passe dans `secrets/ops_assistant_password`,
tunnel `-L 8090:127.0.0.1:8090`). Il répond aux questions sur les procédures à partir de ce runbook et du reste de la
documentation, cite le fichier et la section de chaque information, et n'exécute aucune action. Il ne voit ni les
alertes en cours ni les métriques : il faut vérifier la source citée avant d'appliquer une commande. Sur la VM, sans
GPU, une réponse prend environ une minute. Son index n'est reconstruit qu'au démarrage : après une modification de la
documentation, `docker compose restart ops-assistant`.

## 3. Alertes de disponibilité : redémarrer le maillon en panne

### Redémarrer un service à la main avec Ansible (restart_service.yml) puis vérifier sa reprise

Quand le moteur a escaladé ou ne tourne pas, l'opérateur redémarre un service avec le playbook Ansible
`restart_service.yml`, lancé depuis son poste à la racine du dépôt :
`ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e service=payment-api`. Le playbook refuse tout
service hors de sa liste (`auth-service`, `payment-api`, `frontend`, `waf`), recrée le conteneur de la version active
(`docker compose up -d --force-recreate --wait --wait-timeout 90`, donc jusqu'à 90 s d'attente de son healthcheck),
puis vérifie la reprise réelle en rejouant la transaction témoin `tests/smoke_test.py` sur l'hôte, jusqu'à 5 fois à 5 s
d'intervalle : le playbook échoue si le service ne redevient pas utilisable. Le playbook ne gère ni PostgreSQL ni le
détecteur d'anomalies : sur la VM, depuis la version active, on utilise `sudo docker compose up -d --wait postgres` et
`sudo docker compose restart anomaly-detector`.

Après un redémarrage manuel, la reprise se vérifie comme après une action du moteur : transaction témoin depuis le
poste de l'opérateur (`python tests/smoke_test.py http://172.16.147.10:8080`, 28 vérifications, code de sortie 0 = service
rétabli), panneau « Parcours client » de Grafana à OK, et contrôle d'intégrité du registre à 200. Sur le poste de
développement, l'équivalent du playbook est `docker compose up -d --wait <service>` suivi de
`python tests/smoke_test.py http://127.0.0.1:8080`.

### ServiceDown : une API ne répond plus au scrape Prometheus

**Signification et déclenchement.** `ServiceDown` se déclenche quand Prometheus n'arrive plus à lire `/metrics`
d'auth-service ou de payment-api : `up{job=~"auth-service|payment-api"} == 0` pendant 15 s (`for: 15s`, scrape toutes les
10 s). Elle porte `severity=critical`, `domain=availability` et `service=auth-service` ou `service=payment-api`. Le
processus de l'API est arrêté, planté ou injoignable sur le réseau `app`. Ce n'est pas le cas d'une base arrêtée : l'API
répond alors 503 mais `up` reste à 1, et ce sont `EndToEndProbeFailed` et `DependencyFailures` qui se déclenchent.

**Causes probables.** Conteneur arrêté (`docker compose stop`), processus planté, conteneur tué par manque de mémoire
(au-delà de son `mem_limit`), ou restauration de la base en cours : `resilience-pg-restore` arrête volontairement les
deux API.

**Ce que fait le moteur.** `ServiceDown` suit la stratégie de redémarrage (nature `availability`). Le moteur
diagnostique la chaîne PostgreSQL puis API : il attend d'abord un maillon `starting`, redémarre PostgreSQL en premier
s'il est arrêté ou en échec (`start` pour un conteneur arrêté, `restart` sinon), laisse alors 30 s à l'API pour revenir
seule, et ne redémarre l'API que si elle reste en panne. Si tous les conteneurs sont sains, il relit
`max(up{job="<service>"})` pendant 15 s : revenu à 1, il se contente de vérifier ; sinon il redémarre l'API. Si une
restauration demandée par le moteur est en cours (pont occupé), il suspend toute action sur PostgreSQL et sur les API
jusqu'à la fin de la restauration (6 min au plus), puis refait le diagnostic. La vérification enchaîne conteneurs
`healthy`, sondes à 1 et transaction témoin. En cas d'échec, il retente 10 s plus tard, dans la limite de 3 tentatives
par incident et de 3 redémarrages par service sur 10 min, puis escalade (`attempts_exhausted`, `verification_failed` ou `action_failed`) ; un
conteneur absent est escaladé (`container_missing`). Les alertes `EndToEndProbeFailed`, `HighErrorRate` et
`DependencyFailures` du même service rejoignent le même incident.

**Vérifier le rétablissement.** Le dashboard de supervision affiche « Service rétabli » et la tuile de l'API est verte ;
dans Grafana, « Processus API » et « Parcours client » sont OK ; `docker compose ps auth-service payment-api` montre les
deux conteneurs `healthy` ; la transaction témoin `python tests/smoke_test.py http://127.0.0.1:8080` (28 vérifications)
se termine avec le code 0. Sur la VM, depuis la version active : `python3 tests/smoke_test.py`.

**Reprise manuelle.** Si le moteur a escaladé ou ne tourne pas, lire d'abord la cause avec
`docker compose logs --tail 200 payment-api` et `docker inspect -f '{{.State.OOMKilled}} {{.State.ExitCode}}'
resilience-alpha-payment-api-1`, puis relancer l'API par Ansible depuis le poste de l'opérateur :
`ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e service=payment-api` (voir « Redémarrer un
service à la main avec Ansible »). Si une restauration manuelle de la base est en cours, ne rien relancer : attendre la
fin du playbook de restauration.

**Escalade.** Si l'API retombe après chaque redémarrage (anti-boucle épuisé), escalader au responsable développement
(défaut applicatif, régression de la dernière version) et envisager le retour à la version précédente
(`ansible-playbook -i ansible/inventory.ini ansible/deploy.yml -e deploy_ref=<commit précédent>`) ; si le conteneur est
tué par manque de mémoire, escalader au responsable infrastructure.

### EndToEndProbeFailed : le parcours client échoue à travers le WAF

**Signification et déclenchement.** `EndToEndProbeFailed` se déclenche quand une sonde de bout en bout échoue :
`probe_success{job="blackbox-http"} == 0` pendant 15 s. Le service blackbox interroge toutes les 5 s, à travers le WAF
comme un vrai client, la page d'accueil `http://waf:8080/` (label `service=frontend`), `http://waf:8080/api/auth/health`
(label `service=auth`) et `http://waf:8080/api/payments/health` (label `service=payments`). Un `/health` d'API ne répond
200 que si le processus **et** la base répondent. L'alerte porte `severity=critical` et `domain=availability`.

**Causes probables.** WAF arrêté ou en erreur, frontal nginx arrêté, API arrêtée, PostgreSQL arrêté (les `/health` des
deux API répondent alors 503). Le blocage d'IP n'est pas en cause : les sondes partent de la dmz, jamais bloquée.

**Ce que fait le moteur.** Le moteur traduit le label de la sonde en service Compose (`auth` → auth-service, `payments`
→ payment-api, `frontend` → frontend) et diagnostique tout le parcours dans l'ordre où il faut réparer : PostgreSQL,
l'API, le frontal, le WAF (pour la sonde `frontend` : le frontal puis le WAF). Il redémarre le premier maillon en panne,
avec les mêmes attentes que pour `ServiceDown` (maillon `starting` attendu, 30 s laissées aux services qui dépendent
d'une base réparée, suspension pendant une restauration demandée par le moteur). Si tous les conteneurs sont sains, il
relit la sonde pendant 15 s : revenue à 1, il vérifie seulement ; sinon il redémarre le service visé. Quand le WAF
tombe, les trois sondes échouent ensemble et ouvrent trois incidents : le premier redémarre le WAF, les deux autres
constatent cette action récente et se contentent de vérifier. Mêmes vérifications et même anti-boucle que pour
`ServiceDown`.

**Vérifier le rétablissement.** Le panneau « Parcours client » de Grafana affiche les trois sondes OK et la frise
« Disponibilité avant / pendant / après l'incident » repasse au vert ; `probe_success{job="blackbox-http"}` vaut 1 pour
`auth`, `payments` et `frontend` ; la transaction témoin `python tests/smoke_test.py http://127.0.0.1:8080` réussit.

**Reprise manuelle.** Trouver le maillon en panne avec `docker compose ps` et
`curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/api/payments/health` (502 : l'API ne répond pas
derrière le frontal ; 503 : l'API répond mais pas sa base). Relancer le maillon avec
`ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e service=<waf|frontend|auth-service|payment-api>`,
ou PostgreSQL avec `docker compose up -d --wait postgres` (le playbook ne gère pas PostgreSQL).

**Escalade.** Un WAF qui ne redémarre pas (configuration ou certificat invalides) relève du responsable infrastructure
et du responsable sécurité ; une API qui ne se rétablit pas, du responsable développement.

### HighErrorRate : plus de 20 % de réponses 5xx

**Signification et déclenchement.** `HighErrorRate` se déclenche quand plus de 20 % des réponses d'un service sont des
erreurs 5xx sur une minute glissante, pendant 30 s :
`sum by (service) (rate(http_requests_total{status=~"5.."}[1m])) / sum by (service) (rate(http_requests_total[1m])) > 0.2`.
Elle porte `severity=warning`, `domain=availability` et le `service` qui renvoie les erreurs.

**Causes probables.** Base injoignable (les API répondent alors 503 `database_unavailable`), défaut applicatif, service
saturé.

**Ce que fait le moteur.** `HighErrorRate` suit la stratégie de redémarrage, sans contrôle du symptôme : le moteur répare
d'abord PostgreSQL s'il est en panne, puis, même si tous les conteneurs sont sains, redémarre le service qui renvoie les
5xx, sauf si un autre incident vient de le redémarrer (moins de 120 s), auquel cas il vérifie seulement. Mêmes
vérifications et même anti-boucle que pour `ServiceDown`. Une alerte `HighErrorRate` qui vise le moteur de remédiation
lui-même n'est jamais remédiée.

**Vérifier le rétablissement.** Dans Grafana, le panneau « Requêtes / s par service et code » ne montre plus de 5xx ; la
transaction témoin réussit.

**Reprise manuelle.** Lire les erreurs avec `docker compose logs --tail 200 <service>` ou la requête Loki
`{service="payment-api", level="error"}`, vérifier PostgreSQL (`docker compose ps postgres`), puis relancer le service
avec `restart_service.yml` si les erreurs persistent.

**Escalade.** Des 5xx qui reviennent après redémarrage signalent un défaut applicatif : responsable développement ; une
base en cause : responsable infrastructure.

### HighLatencyP95 : latence p95 supérieure à 1 s

**Signification et déclenchement.** `HighLatencyP95` se déclenche quand le 95e centile de la latence d'un service, hors
`/health`, dépasse 1 s pendant 1 min :
`histogram_quantile(0.95, sum by (service, le) (rate(http_request_duration_seconds_bucket{route!="/health"}[1m]))) > 1`.
Elle porte `severity=warning` et `domain=availability`.

**Causes probables.** Charge élevée (les connexions sont coûteuses : argon2 prend jusqu'à 2,5 Gio pour 60 connexions
simultanées sur auth-service), PC Hôte saturé, base lente, attaque par saturation.

**Ce que fait le moteur.** `HighLatencyP95` suit la stratégie « observer puis redémarrer » : le moteur observe d'abord
pendant 180 s (`LATENCY_PERSIST_SECONDS`) sans rien faire. Si l'alerte retombe pendant ce délai, l'incident est clos
sans action (`resolved_without_action`). Si elle est toujours active, il passe au diagnostic de redémarrage (PostgreSQL
puis le service) et redémarre le service, sous le même anti-boucle que les autres redémarrages. Attention : une alerte
`AnomalyDetected` dont la variable dominante est `latency_p95` redémarre le service tout de suite, sans ces 180 s
d'observation.

**Vérifier le rétablissement.** Le panneau « Latence p95 » de Grafana repasse sous 1 s.

**Reprise manuelle.** Chercher d'abord la source de la charge (`uptime`, `docker stats --no-stream`, top 10 des IP du
tableau SOC) : redémarrer ne sert à rien si la charge continue. Ne redémarrer que si la latence reste haute sans charge.

**Escalade.** Ressources du PC Hôte : responsable infrastructure ; charge venant d'une seule IP (déni de service) :
responsable sécurité.

### DependencyFailures : une API n'arrive plus à joindre sa base

**Signification et déclenchement.** `DependencyFailures` est une règle SOC évaluée par Loki toutes les 15 s : elle se
déclenche dès qu'un service journalise plus de 3 événements `dependency_failure` en une minute,
`sum by (service) (count_over_time({event_type="dependency_failure"}[1m])) > 3`, sans délai (`for: 0s`). Elle porte
`severity=critical`, `domain=availability` et le `service` émetteur (auth-service ou payment-api). Pendant une panne de
base, les API restent debout : elles répondent 503 `database_unavailable` (jamais 500), leur `/health` passe en 503
(les sondes de bout en bout échouent donc aussi) et elles se reconnectent seules dès que PostgreSQL répond de nouveau.

**Causes probables.** PostgreSQL arrêté, planté, `unhealthy` ou saturé ; volume `pgdata` inaccessible ; disque plein.

**Ce que fait le moteur.** `DependencyFailures` suit la stratégie de redémarrage, mais ne redémarre jamais une chaîne
saine. Le moteur diagnostique PostgreSQL puis l'API : si PostgreSQL est arrêté ou en échec, il le démarre ou le
redémarre, attend qu'il soit `healthy` (90 s au plus), laisse 30 s à l'API pour se reconnecter seule (les connexions sont
testées avant usage) et ne redémarre l'API que si elle reste en échec. Si tous les conteneurs sont sains, il vérifie
seulement, sans action (la base est revenue d'elle-même). L'alerte rejoint l'incident `ServiceDown` ou
`EndToEndProbeFailed` du même service. Pendant une panne de base, `LedgerIntegrityBroken` se déclenche souvent aussi :
le moteur la traite alors comme une panne de disponibilité, sans restauration (voir `LedgerIntegrityBroken`).

**Vérifier le rétablissement.** `docker compose ps postgres` montre PostgreSQL `healthy` ; la requête Loki
`{event_type="dependency_failure"}` ne produit plus de lignes ; les `/health` des API répondent 200 et la transaction
témoin réussit.

**Reprise manuelle.** Relancer PostgreSQL avec `docker compose up -d --wait postgres` et lire ses journaux
(`docker compose logs --tail 200 postgres`). Si le volume de données est perdu ou illisible, suivre le runbook
[restauration-base.md](restauration-base.md).

**Escalade.** Responsable infrastructure (disque, volume, Docker) ; si des données sont perdues, cellule de crise.

## 4. Intégrité du registre de paiement : confirmer puis restaurer

### Ce que vérifie le contrôle d'intégrité du registre

Le contrôle d'intégrité du registre de paiement (`ledger.check_integrity` dans payment-api) vérifie quatre règles de la
comptabilité en partie double : la somme de toutes les écritures est nulle, le solde de chaque compte est égal à la
somme de ses écritures, chaque virement est équilibré (une écriture de −montant et une de +montant) et aucun solde n'est
négatif. payment-api le lance toutes les 15 s et publie le résultat dans `payment_ledger_integrity_ok` (1 cohérent, 0
incohérent ou base injoignable) et l'heure du dernier contrôle dans `payment_ledger_integrity_last_check_timestamp`. Le
même contrôle se lance à la demande par `GET /internal/integrity` (réseau interne) ou `GET /api/payments/admin/integrity`
(compte admin) : 200 si le registre est cohérent, 409 s'il est incohérent, avec un rapport JSON qui détaille chaque règle
en échec, et 503 si la base est injoignable. C'est la preuve que les **données** sont saines après une reprise, au-delà
du simple redémarrage d'un conteneur. Sa limite : il voit une incohérence, pas une fraude équilibrée (un faux virement
correctement passé en partie double reste cohérent).

### LedgerIntegrityBroken : registre de paiement incohérent

**Signification et déclenchement.** `LedgerIntegrityBroken` se déclenche dès que payment-api expose
`payment_ledger_integrity_ok == 0`, sans délai (`for: 0s`). payment-api contrôle son registre toutes les 15 s
(`INTEGRITY_INTERVAL_SECONDS`) : somme des écritures nulle, soldes égaux aux écritures, virements équilibrés, aucun solde
négatif. L'alerte porte `severity=critical`, `domain=integrity`, `service=payment-api`. La jauge tombe aussi à 0 quand la
base est injoignable : une alerte d'intégrité n'est donc pas, à elle seule, la preuve d'une corruption.

**Causes probables.** Modification directe des données en base (compromission, scénario EBIOS S5), défaut applicatif,
ou simple panne de PostgreSQL (fausse alerte d'intégrité).

**Ce que fait le moteur.** Le moteur distingue la corruption de la panne de base avant toute restauration (nature
`compromise`). Il lit l'état de PostgreSQL par le proxy Docker ; si PostgreSQL démarre, il attend sa stabilisation puis
refait le contrôle. Il appelle ensuite `/internal/integrity` de payment-api. Si PostgreSQL est arrêté ou en échec, ou si
le contrôle répond 503 ou ne répond pas, il n'y a **pas de restauration** : l'incident est reclassé en disponibilité et
traité comme `DependencyFailures` (redémarrer PostgreSQL, puis l'API si besoin), avec une vérification qui inclut le
contrôle d'intégrité à 200 ; si, une fois la base revenue, le registre reste en 409, la tentative suivante décide la
restauration. Si le contrôle répond 200, le moteur vérifie seulement. Un autre code de réponse est escaladé
(`action_failed`).

**Restauration automatique.** Une corruption est confirmée quand PostgreSQL est sain et que `/internal/integrity`
répond **409**. Si le pont de restauration est indisponible (heartbeat du runner de l'hôte plus vieux que 120 s), le
moteur escalade (`bridge_unavailable`) : la restauration est alors manuelle. Sinon, il revérifie sous verrou que le
registre est toujours incohérent (redevenu cohérent, il ne restaure pas) et dépose une demande au pont ; le runner de l'hôte revérifie lui-même le 409 et lance `resilience-pg-restore
latest-healthy`, qui choisit la dernière sauvegarde saine, sauvegarde l'état courant (`pre-restore`), arrête les API,
recrée `authdb` et `paydb`, relance les API et contrôle le registre à 200. Pendant ce temps, le moteur suspend tout
redémarrage de PostgreSQL et des API. Il vérifie ensuite PostgreSQL et les deux API `healthy`, le registre à 200, les
sondes et la transaction témoin. Une seule restauration est permise par 15 min côté moteur (3 par heure côté runner) et
une restauration en échec n'est jamais rejouée : précondition refusée, quota atteint, runner occupé, délai dépassé ou
script en échec mènent à l'escalade. Mesuré en recette : alerte à +11 s après la corruption, restauration faite à
+31,5 s, rétabli et vérifié à +31,9 s. Le protocole du pont est décrit dans [restauration-base.md](restauration-base.md).

**Vérifier le rétablissement.** Le contrôle interne du registre doit répondre 200 ; le panneau « Intégrité du registre »
de Grafana est OK ; le contrôle d'administration `GET /api/payments/admin/integrity` (compte `admin@resilience.local`,
mot de passe dans `secrets/admin_password`) répond 200 ; la transaction témoin réussit. Le contrôle interne se lance
depuis le conteneur de payment-api :

```bash
docker compose exec -T payment-api python -c 'import urllib.error, urllib.request
try: print(urllib.request.urlopen("http://127.0.0.1:8000/internal/integrity", timeout=10).status)
except urllib.error.HTTPError as err: print(err.code, err.read().decode()[:500])'
```

**Reprise manuelle.** Un redémarrage ne corrige pas des données corrompues : il faut restaurer. Si le moteur a escaladé,
poser d'abord le silence ciblé de la section « Restauration lancée par l'opérateur », puis suivre
[restauration-base.md](restauration-base.md) : `ansible-playbook -i ansible/inventory.ini ansible/restore_database.yml
-e confirm_restore=true`.

**Escalade.** Responsable sécurité (qui a modifié la base ? une compromission impose aussi de faire tourner les
secrets), responsable développement (défaut applicatif), cellule de crise : une corruption du registre est probablement
un incident majeur au sens de DORA, même restaurée en quelques secondes.

### LedgerIntegrityViolationLogged : violation d'intégrité journalisée par payment-api

**Signification et déclenchement.** `LedgerIntegrityViolationLogged` est une règle SOC évaluée par Loki : elle se
déclenche dès que payment-api a journalisé au moins un événement `integrity_violation` dans les 2 dernières minutes,
`count_over_time({service="payment-api", event_type="integrity_violation"}[2m]) > 0`, sans délai. Elle porte
`severity=critical`, `domain=integrity`, `service=payment-api`.

**Causes probables.** Les mêmes que `LedgerIntegrityBroken` : c'est le même contrôle, vu par les journaux.

**Ce que fait le moteur.** Exactement la même réponse que `LedgerIntegrityBroken`, dans le **même incident** (clé
`integrity:payment-api`) : une seule restauration, jamais deux. En recette, `LedgerIntegrityBroken` arrive la première
(+11 s) et ouvre l'incident ; `LedgerIntegrityViolationLogged` (+17 s) y est rattachée. Comme la fenêtre Loki est de
2 min, cette alerte retombe environ 2 min après la dernière violation journalisée, et l'incident se clôt alors.

**Vérifier, reprendre, escalader.** Comme pour `LedgerIntegrityBroken`. Le détail des contrôles en échec se lit dans
`{service="payment-api", event_type="integrity_violation"} | json`.

### LedgerIntegrityCheckStale : le contrôle d'intégrité ne s'exécute plus

**Signification et déclenchement.** `LedgerIntegrityCheckStale` se déclenche quand le dernier contrôle d'intégrité date
de plus de 60 s alors que payment-api expose encore ses métriques :
`time() - payment_ledger_integrity_last_check_timestamp > 60` pendant 30 s. Elle porte `severity=warning`,
`domain=integrity`, `service=payment-api`. Le registre n'est plus surveillé.

**Causes probables.** Tâche de contrôle bloquée (verrou en base, requête lente), boucle de payment-api saturée.

**Ce que fait le moteur.** Rien sur le service : il journalise l'alerte et l'escalade par conception (motif `policy`),
sans restauration à l'aveugle. Cette escalade ne déclenche pas `RemediationFailed`.

**Vérifier le rétablissement.** Dans Prometheus, `time() - payment_ledger_integrity_last_check_timestamp` repasse sous
60 s.

**Reprise manuelle.** Lancer le contrôle interne à la main (commande de `LedgerIntegrityBroken`). S'il répond 200, le
registre est sain : relancer payment-api (`restart_service.yml -e service=payment-api`) pour redémarrer la tâche de
contrôle. S'il répond 409, suivre `LedgerIntegrityBroken` ; s'il répond 503, suivre `DependencyFailures`.

**Escalade.** Responsable développement.

## 5. Alertes de sécurité : bloquer l'IP attaquante au WAF

### Fonctionnement du blocage d'IP au WAF

Le blocage est la réponse de compromission à une attaque attribuée à une IP. Le moteur écrit l'IP dans la liste
`blocked-ips.conf` du volume partagé `waf-blocklist`, recharge le WAF à chaud (SIGHUP par le proxy Docker), puis vérifie
par le port interne 8081 du WAF que la configuration réellement chargée bloque l'IP. L'IP bloquée reçoit
`403 {"detail":"blocked_by_remediation"}` avant ModSecurity, ses requêtes n'atteignent plus les API et les alertes de
sécurité retombent d'elles-mêmes. Le blocage dure 300 s par défaut (`WAF_BLOCK_TTL_SECONDS`) et se lève seul : la levée
effective a lieu au plus une période de la boucle de fond (15 s) après l'expiration. Ne sont jamais bloquées la boucle
locale, la dmz (`172.31.248.0/21` : sondes, frontal, transaction témoin), les réseaux du moteur et les passerelles des
réseaux du WAF, par lesquelles arrivent les clients de l'hôte et les tunnels SSH des opérateurs.

**NAT du labo.** Au labo, tous les postes arrivent sur la VM avec la même IP `172.16.255.252`. Bloquer l'attaquant bloque
donc tous les clients du labo, jury compris, pendant toute la durée du blocage. La transaction témoin du moteur part de
la dmz et reste valable. Pour utiliser l'application pendant un blocage, passer par un tunnel SSH
(`ssh -N -L 8080:127.0.0.1:8080 resilience@172.16.147.10`, puis http://127.0.0.1:8080), qui arrive par la passerelle
exclue du blocage.

### AuthBruteForce : force brute depuis une IP

**Signification et déclenchement.** `AuthBruteForce` est une règle SOC évaluée par Loki toutes les 15 s : elle se
déclenche quand une même IP cliente cumule plus de 10 échecs d'authentification sur auth-service en une minute,
`sum by (client_ip) (count_over_time({service="auth-service", event_type="auth_failure"} | json client_ip="client_ip" [1m])) > 10`,
sans délai (`for: 0s`). Elle porte `severity=warning`, `domain=security`, `service=auth-service` et le label `client_ip`
de l'IP fautive.

**Causes probables.** Force brute ou bourrage d'identifiants depuis une machine ; plus rarement, un utilisateur ou un
script qui réessaie en boucle avec un mauvais mot de passe.

**Ce que fait le moteur.** `AuthBruteForce` suit la stratégie « bloquer l'IP de l'alerte » (nature `compromise`). Le
moteur valide l'IP du label `client_ip` : absente ou invalide, il escalade (`no_offender`) ; dans un réseau exclu du
blocage, il escalade sans jamais la bloquer (`not_allowed`) ; si la liste de blocage du WAF est indisponible, il escalade
(`waf_unavailable`) ; si l'IP est déjà bloquée, il vérifie seulement. Sinon il la bloque 300 s au WAF, puis vérifie le
blocage chargé par le WAF, les sondes et la transaction témoin. Une même IP peut être bloquée 3 fois au plus sur 10 min ;
un blocage en échec est retenté 10 s plus tard, 3 tentatives au plus, puis escaladé. `InvalidTokenFlood` et
`WafAttackBlocked` venant de la même IP rejoignent le même incident. Mesuré en recette : alerte à +21,5 s après le début
de l'attaque, IP bloquée à +28,6 s, rétabli et vérifié à +29,5 s.

**Vérifier le rétablissement.** Le panneau « IP bloquées au WAF » du dashboard de supervision affiche l'IP et le compte à
rebours de sa levée ; dans Grafana, « IP bloquées (WAF) » vaut 1 et « Refus du blocage WAF, par IP » montre les requêtes
refusées de l'attaquant ; la requête Loki `{service="waf", event_type="waf_remediation_block"}` liste ces refus ; le
panneau SOC « Échecs d'authentification par IP source » retombe ; l'alerte retombe environ une minute après le blocage.

**Reprise manuelle.** Si l'escalade est `not_allowed`, l'IP est celle d'une passerelle (hôte, tunnel SSH d'un opérateur)
ou de la dmz : l'attaque vient de la VM elle-même ou d'un poste d'opérateur, ce qui est un incident de sécurité sur
l'hôte, à ne pas traiter par un blocage. Pour les autres escalades, bloquer l'IP à la main (voir « Poser ou lever un
blocage d'IP à la main ») après avoir vérifié dans le tableau SOC qu'il s'agit bien d'une attaque.

**Escalade.** Responsable sécurité ; au labo, prévenir le jury que tous les postes sont bloqués pendant la durée du
blocage.

### InvalidTokenFlood : rafale de jetons invalides sur payment-api

**Signification et déclenchement.** `InvalidTokenFlood` est une règle SOC évaluée par Loki : elle se déclenche quand une
même IP présente plus de 20 jetons invalides à payment-api en une minute,
`sum by (client_ip) (count_over_time({service="payment-api", event_type="auth_failure"} | json client_ip="client_ip" [1m])) > 20`,
sans délai. Elle porte `severity=warning`, `domain=security`, `service=payment-api` et le label `client_ip`.

**Causes probables.** Rejeu de jetons volés, expirés ou forgés ; un client resté en boucle avec un jeton expiré (les JWT
durent 15 min).

**Ce que fait le moteur.** La même réponse que pour `AuthBruteForce` : blocage au WAF de l'IP du label `client_ip`, avec
les mêmes refus, vérifications et limites. Une attaque plus lente que le seuil (15 jetons par minute en recette) ne
déclenche pas cette règle, mais le détecteur d'anomalies la voit (`AnomalyDetected`, variable `invalid_tokens_per_min`) et
le moteur bloque alors l'IP par le chemin ML.

**Vérifier, reprendre, escalader.** Comme pour `AuthBruteForce`, avec la requête Loki
`{service="payment-api", event_type="auth_failure"}`. Responsable sécurité ; un jeton forgé valide signerait une fuite de
la clé privée JWT (`secrets/jwt_private.pem`) : faire tourner les secrets.

### WafAttackBlocked : injections bloquées en série par le WAF

**Signification et déclenchement.** `WafAttackBlocked` est une règle SOC évaluée par Loki : elle se déclenche quand le
WAF a lui-même interrompu plus de 5 requêtes d'une même IP en 2 min (ModSecurity, HTTP 403,
`transaction.is_interrupted=true`), sans délai. Depuis la revue de durcissement, les 403 renvoyés par les API (par
exemple un compte non admin sur `/admin/integrity`) ne comptent plus : seules les requêtes que le WAF a bloquées
déclenchent l'alerte. La requête complète est celle de la section « Loki : requêtes des blocages du WAF ». L'alerte porte
`severity=warning`, `domain=security`, `service=waf` et le label `client_ip`.

**Causes probables.** Injections SQL ou XSS, scanner de vulnérabilités ; plus rarement un faux positif du CRS (aucun
mesuré au niveau de paranoïa 1 sur 1 735 requêtes légitimes).

**Ce que fait le moteur.** La même réponse que pour `AuthBruteForce` : blocage au WAF de l'IP du label `client_ip`. Une
fois l'IP bloquée, ses requêtes sont refusées avant ModSecurity et ne figurent plus dans le journal d'audit : l'alerte
retombe dans les 2 min, même si l'attaquant insiste. Mesuré en recette : alerte à +24,4 s, IP bloquée à +31,5 s,
rétabli et vérifié à +32,5 s.

**Vérifier le rétablissement.** Le tableau SOC montre « Requêtes bloquées par le WAF (15 min) » qui cesse de croître,
« Blocages WAF par IP source » qui retombe et le « Journal d'audit du WAF (ModSecurity) » ; l'IP figure parmi les IP
bloquées du dashboard de supervision.

**Reprise manuelle.** Lire dans le journal d'audit (`{service="waf"} |= "\"transaction\""`) les règles déclenchées pour
écarter un faux positif ; un client légitime bloqué à tort se débloque à la main (voir plus bas).

**Escalade.** Responsable sécurité.

### LoginFailureSpike : pic d'échecs de connexion, toutes IP confondues

**Signification et déclenchement.** `LoginFailureSpike` est une règle Prometheus : elle se déclenche quand auth-service
compte plus de 20 échecs de connexion par minute, toutes IP confondues, pendant 30 s,
`sum(rate(auth_login_attempts_total{result="failure"}[1m])) * 60 > 20`. Elle porte `severity=warning`,
`domain=security`, `service=auth-service`, mais aucune IP.

**Causes probables.** Force brute répartie sur plusieurs IP, pulvérisation de mots de passe, ou force brute d'une seule
IP (`AuthBruteForce` se déclenche alors aussi).

**Ce que fait le moteur.** Le moteur cherche dans Loki l'IP la plus fautive sur les 2 dernières minutes, avec la requête
`sum by (client_ip) (count_over_time({service="auth-service", event_type="auth_failure"} | json client_ip="client_ip" | client_ip!="" [2m]))`.
Si Loki est injoignable, il escalade (`no_offender`). Si la meilleure IP a au moins 10 échecs en 2 min
(`SECURITY_MIN_EVENTS`), il la bloque au WAF comme pour `AuthBruteForce`. Sinon, il **observe sans escalader** :
l'attaque est répartie ou terminée, l'incident reste en observation jusqu'à la retombée de l'alerte et
`RemediationFailed` ne se déclenche pas.

**Vérifier le rétablissement.** Le panneau « Connexions / min par résultat » de Grafana montre les échecs qui
retombent ; l'alerte retombe.

**Reprise manuelle.** Si le moteur observe, analyser les IP dans le tableau SOC (« Échecs d'authentification par IP
source ») et bloquer à la main les IP clairement fautives. Au labo, tous les postes partagent l'IP du NAT : l'attribution
par IP n'y distingue personne.

**Escalade.** Responsable sécurité : une attaque répartie n'est pas bloquée automatiquement (risque accepté dans
l'analyse EBIOS RM).

### Poser ou lever un blocage d'IP à la main

Le fichier `blocked-ips.conf` ne se modifie jamais à la main : le moteur le réécrit à partir de son état
`blocked-ips.json` et rétablirait un blocage effacé. On passe par le code du moteur, depuis son conteneur. La première
commande lève le blocage d'une IP (elle répond `False` si l'IP n'était pas bloquée), la seconde bloque une IP pendant
300 s ; une IP exclue du blocage est refusée. Le blocage manuel apparaît dans le dashboard avec l'incident `operateur`
et se lève seul à l'expiration, comme un blocage du moteur. Quand le moteur est arrêté, remplacer
`docker compose exec -T remediation-engine` par `docker compose run --rm --no-deps -T remediation-engine` : les
blocages ne se lèvent plus seuls tant que le moteur est arrêté.

```bash
docker compose exec -T remediation-engine python -c "import os,sys; from app.actions.docker_proxy import DockerProxy; from app.actions.waf_block import WafBlocklist; b=WafBlocklist.from_env(DockerProxy(os.environ['DOCKER_PROXY_URL'], os.environ['COMPOSE_PROJECT'])); print(b.unblock(sys.argv[1]), [e.ip for e in b.active()])" 203.0.113.7
docker compose exec -T remediation-engine python -c "import os,sys; from app.actions.docker_proxy import DockerProxy; from app.actions.waf_block import WafBlocklist; b=WafBlocklist.from_env(DockerProxy(os.environ['DOCKER_PROXY_URL'], os.environ['COMPOSE_PROJECT'])); print(b.block(sys.argv[1], 300, 'blocage manuel', 'operateur'))" 203.0.113.7
```

## 6. Anomalie détectée par le modèle ML

### AnomalyDetected : comportement anormal, score supérieur ou égal à 0,8

**Comment le détecteur alimente la chaîne d'alertes.** Le détecteur d'anomalies (`services/anomaly-detector`) expose à
Prometheus un score `anomaly_score{service}` par service et le seuil `anomaly_threshold` ; Prometheus évalue la règle
`AnomalyDetected`, qui compare les deux, et Alertmanager transmet l'alerte au moteur de remédiation comme toute autre
alerte. Le détecteur n'appelle jamais le moteur directement.

**Signification et déclenchement.** `AnomalyDetected` se déclenche quand le score d'anomalie d'un service atteint le
seuil du modèle pendant 20 s : `anomaly_score >= on(job, instance) group_left() anomaly_threshold`. Le seuil vaut
**0,8** : il est enregistré dans le modèle, exposé par le détecteur en `anomaly_threshold` et comparé avec « supérieur ou
égal », comme dans le code. Le détecteur calcule toutes les 10 s, sur une fenêtre glissante d'une minute, un score entre
0 et 1 pour auth-service, payment-api et frontend ; un score NaN (pas de donnée) ne déclenche jamais l'alerte. L'alerte
porte `severity=critical`, `domain=anomaly` et le `service` visé ; elle retombe environ 70 s après la fin de l'incident.
À chaque franchissement du seuil, le détecteur journalise un événement `anomaly_detected` avec le service visé
(`target_service`), le score et la **variable dominante** (`dominant_feature`).

**Causes probables.** Attaque sous les seuils des règles SOC (9 échecs de connexion par minute, 15 jetons invalides par
minute en recette), panne (sonde en échec, erreurs 5xx), latence anormale.

**Ce que fait le moteur : tri par variable dominante.** Le moteur lit le dernier événement `anomaly_detected` du service
dans Loki (15 dernières minutes). Si Loki est injoignable ou s'il n'y a pas d'événement récent, il escalade
(`triage_unknown`). Sinon, la variable dominante décide de la réponse, et l'incident est reclassé en compromission ou en
disponibilité.

**Variable d'attaque : blocage de l'IP fautive.** Pour `login_failures_per_min`, `invalid_tokens_per_min`,
`waf_blocks_per_min` et `client_errors_4xx_rate`, le moteur attribue l'attaque à une IP dans Loki sur 2 min : échecs
d'authentification d'auth-service, jetons invalides de payment-api, requêtes interrompues par le WAF, ou réponses 4xx de
l'API visée (pour `client_errors_4xx_rate`, seulement sur auth-service et payment-api : sur le frontal, il n'y a pas de
source d'IP et le moteur escalade). Si la meilleure IP compte au moins 10 événements en 2 min, il la bloque au WAF
exactement comme pour `AuthBruteForce`, et se contente de vérifier si une règle SOC l'a déjà bloquée. En dessous de
10 événements, il **escalade** (`no_offender`, « attaque distribuée ») sans rien bloquer, contrairement à
`LoginFailureSpike`, qui observe. Mesuré en recette : à 9 échecs par minute, IP bloquée à +64,8 s ; à 5 échecs par
minute (8 échecs en 2 min), escalade sans blocage.

**Variable de panne : redémarrage.** Pour `probe_failed`, le moteur applique la réponse d'`EndToEndProbeFailed` :
diagnostic de tout le parcours (PostgreSQL, API, frontal, WAF) et contrôle de la sonde avant d'agir. Pour
`error_ratio_5xx` et `latency_p95`, il applique la réponse de `HighErrorRate` : réparation de PostgreSQL s'il est en
cause, puis redémarrage du service même si les conteneurs sont sains, sans période d'observation. L'incident d'anomalie
(clé `anomaly:<service>`) est distinct de celui de `ServiceDown` : il constate le plus souvent « déjà redémarré par… »
et vérifie seulement.

**Autre variable.** Pour une autre variable dominante (débit de requêtes), une anomalie du frontal pendant qu'un
incident d'API est ouvert, ou ouvert depuis moins de 5 min, est rattachée à cet incident et observée sans action (le
trafic d'attaque traverse le frontal). Dans tous les autres cas, le moteur escalade (`triage_unknown`).

**Vérifier le rétablissement.** Selon la branche suivie, mêmes contrôles que l'alerte correspondante (IP bloquée,
service rétabli) ; `anomaly_score` du service repasse sous 0,8 dans Prometheus ; la tuile « Détecteur ML » du dashboard
affiche des scores sous le seuil.

**Reprise manuelle.** Lire la variable dominante avec
`{service="anomaly-detector", event_type="anomaly_detected"} | json | target_service="payment-api"`, puis appliquer la
section de l'alerte correspondante : blocage manuel pour une variable d'attaque, `restart_service.yml` pour une panne.

**Escalade.** Responsable sécurité pour une attaque sans IP dominante ; référent IA/Data pour un faux positif présumé
(aucun mesuré au repos ni pendant la transaction témoin).

## 7. Santé du détecteur d'anomalies

### AnomalyDetectorDown : le détecteur ne produit plus de score

**Signification et déclenchement.** `AnomalyDetectorDown` se déclenche quand le détecteur n'est plus scrapé ou qu'il
n'a plus terminé de cycle depuis 60 s, pendant 1 min :
`up{job="anomaly-detector"} == 0 or (time() - anomaly_detector_last_run_timestamp > 60)`. Elle porte
`severity=warning`, `domain=availability`, `service=anomaly-detector`. Il n'y a plus aucune détection ML, mais le service
métier n'est pas touché et les règles SOC continuent de protéger.

**Causes probables.** Conteneur arrêté, boucle bloquée, modèle absent ou incohérent (`no_model`, `model_mismatch`),
secret Prometheus illisible (`auth_secret_unreadable`) : la cause est donnée par `GET /health` du détecteur (503 avec la
raison).

**Ce que fait le moteur.** Un seul redémarrage d'`anomaly-detector`, service sans état, sans diagnostic préalable et
sans aucune action sur le service métier. La vérification se limite au conteneur `healthy`. Le budget est d'un
redémarrage par 30 min : un deuxième besoin dans ce délai, ou une vérification en échec, mène à l'escalade
(`attempts_exhausted` ou `verification_failed`), donc à `RemediationFailed`.

**Vérifier le rétablissement.** `up{job="anomaly-detector"}` vaut 1 et `anomaly_detector_last_run_timestamp` avance ;
la tuile « Détecteur ML » du dashboard de supervision redevient verte.

**Reprise manuelle.** Lire la santé et les journaux du détecteur, puis le redémarrer (le playbook `restart_service.yml`
ne l'accepte pas) ; un modèle refusé (`model_mismatch`) demande un redéploiement de la version.

```bash
docker compose exec -T anomaly-detector python -c "import urllib.request as u, urllib.error as e
try: print(u.urlopen('http://127.0.0.1:8000/health', timeout=5).read().decode())
except e.HTTPError as x: print(x.code, x.read().decode())"
docker compose logs --tail 100 anomaly-detector
docker compose restart anomaly-detector
```

**Escalade.** Référent IA/Data.

### AnomalyDetectorBlind : une source du détecteur est injoignable

**Signification et déclenchement.** `AnomalyDetectorBlind` se déclenche quand une source du détecteur (Prometheus ou
Loki, label `source`) est injoignable depuis 1 min : `anomaly_detector_source_up == 0` pendant 1 min. Elle porte
`severity=warning`, `domain=anomaly`, `service=anomaly-detector`. Les services qui dépendent de cette source n'ont plus
de score (`anomaly_score` à NaN, `anomaly_data_available` à 0) : Loki en panne prive payment-api et frontend de score,
Prometheus en panne prive les trois services. Ce n'est ni une panne du service métier ni une attaque.

**Ce que fait le moteur.** Il observe seulement : aucune action, aucune escalade ; l'incident se clôt à la retombée de
l'alerte.

**Vérifier le rétablissement.** `anomaly_detector_source_up` revient à 1 pour la source.

**Reprise manuelle.** Vérifier la source : conteneur (`docker compose ps loki prometheus`), disponibilité de Loki
(`curl -s -u "admin:$(cat secrets/loki_password)" http://127.0.0.1:3100/ready`), identifiant Prometheus du détecteur.
Ne redémarrer, n'isoler ni ne bloquer aucun service métier.

**Escalade.** Responsable infrastructure (chaîne d'observation).

## 8. PC Hôte et sauvegardes : escalade par conception

Ces quatre alertes viennent de node-exporter et de son collecteur de fichiers (`service=pc-hote`, qui ne désigne aucun
service Compose). Le moteur les journalise et les escalade par conception (motif `policy`) sans aucune action : elles ne
déclenchent pas `RemediationFailed` et apparaissent sur le dashboard en remarque « incident d'exploitation ouvert ». On
les suit dans la rangée « PC Hôte et sauvegardes (node-exporter, timer resilience-pg-backup) » du tableau Grafana
« Santé du service ». Toutes s'escaladent au responsable infrastructure.

### HostDiskSpaceLow : moins de 15 % d'espace libre sur le PC Hôte

**Signification et déclenchement.** `HostDiskSpaceLow` se déclenche quand le système de fichiers `/` du PC Hôte a
moins de 15 % d'espace libre pendant 5 min. Elle porte `severity=warning`, `domain=availability`.

**Causes probables.** Images Docker accumulées par les constructions, journaux, sauvegardes PostgreSQL (96 conservées,
soit 24 h), anciennes versions déployées (3 conservées), modèles Ollama (environ 2,3 Go).

**Ce que fait le moteur.** Il escalade sans action (`policy`).

**Vérifier le rétablissement.** Le panneau « Disque / utilisé » repasse sous 85 %.

**Reprise manuelle.** Mesurer avec `df -h /`, `sudo docker system df` et
`sudo du -sh /var/backups/resilience-alpha /opt/resilience-alpha/releases`, puis libérer de la place avec
`sudo docker image prune -f` (images sans étiquette seulement) et `sudo journalctl --vacuum-size=200M`. Ne jamais
supprimer de sauvegarde à la main ni lancer `docker volume prune` (les données PostgreSQL sont dans un volume) ; avant
tout ménage, copier les sauvegardes hors de l'hôte avec `ansible-playbook -i ansible/inventory.ini
ansible/backup_database.yml`.

### HostMemoryLow : moins de 10 % de mémoire disponible

**Signification et déclenchement.** `HostMemoryLow` se déclenche quand le PC Hôte a moins de 10 % de mémoire disponible
pendant 2 min. Elle porte `severity=warning`, `domain=availability`.

**Causes probables.** LLM de l'assistant (3,8 Go pour `llama3.2:3b`), connexions en rafale sur auth-service (argon2,
jusqu'à 2,5 Gio), fuite mémoire d'un service.

**Ce que fait le moteur.** Il escalade sans action (`policy`). Si un conteneur métier est tué par manque de mémoire,
`ServiceDown` ou `EndToEndProbeFailed` prennent le relais et le moteur le redémarre.

**Vérifier le rétablissement.** Le panneau « Mémoire utilisée » repasse sous 90 %.

**Reprise manuelle.** Identifier le consommateur avec `free -h` et `sudo docker stats --no-stream`. Le moyen le plus sûr
de libérer de la mémoire sans toucher au service métier est d'arrêter le LLM : `sudo docker compose stop ollama`
(l'assistant RAG reste debout, en mode dégradé).

### BackupMissing : aucune sauvegarde réussie depuis 30 min

**Signification et déclenchement.** `BackupMissing` se déclenche quand la dernière sauvegarde PostgreSQL réussie date de
plus de 30 min, pendant 1 min : `time() - resilience_backup_last_success_timestamp_seconds > 1800`. Le timer sauvegarde
toutes les 15 min : deux sauvegardes manquées signifient que le RPO de 15 min est dépassé. Elle porte
`severity=warning`, `domain=availability`.

**Causes probables.** Timer arrêté ou absent, sauvegardes en échec (voir `BackupFailed`).

**Ce que fait le moteur.** Il escalade sans action (`policy`). Tant que les sauvegardes manquent, une restauration
automatique reviendrait à une sauvegarde plus ancienne et perdrait davantage d'écritures.

**Vérifier le rétablissement.** Le panneau « Âge de la dernière sauvegarde » repasse sous 1 800 s et « Registre dans la
dernière sauvegarde » est OK.

**Reprise manuelle.** Sur la VM : `systemctl list-timers resilience-pg-backup.timer`,
`journalctl -u resilience-pg-backup -n 50`, puis lancer une sauvegarde avec `sudo systemctl start resilience-pg-backup`.
Depuis le poste de l'opérateur, `ansible-playbook -i ansible/inventory.ini ansible/backup_database.yml` réinstalle le
timer, fait une sauvegarde et la copie hors de l'hôte.

### BackupFailed : la dernière sauvegarde PostgreSQL a échoué

**Signification et déclenchement.** `BackupFailed` se déclenche dès que le dernier échec de sauvegarde est plus récent
que la dernière réussite : `resilience_backup_last_failure_timestamp_seconds >
resilience_backup_last_success_timestamp_seconds`, sans délai. Elle porte `severity=warning`, `domain=availability`.

**Causes probables.** PostgreSQL arrêté, disque plein, Docker indisponible pour `pg_dump`.

**Ce que fait le moteur.** Il escalade sans action (`policy`).

**Vérifier le rétablissement.** L'alerte retombe à la sauvegarde réussie suivante (au plus 15 min, ou tout de suite après
une sauvegarde manuelle).

**Reprise manuelle.** Lire l'erreur avec `journalctl -u resilience-pg-backup -n 100`, corriger la cause, puis relancer
avec `sudo systemctl start resilience-pg-backup`.

## 9. Restauration lancée par l'opérateur : poser un silence ciblé

**Depuis le 22/10, `ansible/restore_database.yml` pose ce silence et le lève tout seul** (et `deploy.yml` en pose un de 15 min, qui expire seul, pour couvrir la recréation des conteneurs et ses transactions témoins). La procédure manuelle ci-dessous reste valable pour une restauration lancée directement sur l'hôte avec `resilience-pg-restore`, sans le playbook.

### Pourquoi le moteur doit être tenu à l'écart

Le moteur ne sait qu'une restauration est en cours que lorsqu'il l'a demandée lui-même (demande en vol dans le pont, ou
runner de l'hôte occupé). Une restauration lancée par l'opérateur avec `restore_database.yml` exécute
`resilience-pg-restore` directement : ni le moteur ni le dashboard de supervision ne la voient (les tuiles des API
passent en rouge, pas en bleu). Or le script arrête volontairement auth-service et payment-api pendant qu'il recrée les
bases : `ServiceDown` et `EndToEndProbeFailed` se déclenchent après 15 s, `AnomalyDetected` (variable `probe_failed`)
après 20 s, et le moteur redémarrerait les API au milieu de la restauration. Avant de lancer la restauration,
l'opérateur pose donc un **silence Alertmanager ciblé** : Alertmanager ne transmet plus au moteur les alertes de
disponibilité des deux API et de leurs sondes pendant la fenêtre de restauration.

### Préparer la restauration

Vérifier d'abord, avec la commande d'état du moteur (section « État du moteur de remédiation »), qu'aucun incident
n'est ouvert sur PostgreSQL, auth-service ou payment-api et que le pont n'est pas occupé. Si le moteur restaure déjà la
base, attendre la fin : le verrou de `resilience-pg-restore` refuserait de toute façon une seconde restauration (code
75). Un silence ne retire pas un incident déjà ouvert : si un incident est en cours sur ces services, le laisser finir ou
se clore avant de poser le silence. Sur la VM, ouvrir le tunnel `ssh -N -L 9093:127.0.0.1:9093 resilience@172.16.147.10`.

### Créer le silence ciblé

Le silence couvre seulement les alertes de disponibilité (`ServiceDown`, `EndToEndProbeFailed`, `HighErrorRate`,
`DependencyFailures`, `AnomalyDetected`) **et** seulement les deux API et leurs sondes (`service` égal à `auth-service`,
`payment-api`, `auth` ou `payments`) : les deux matchers s'appliquent ensemble. Les sondes de bout en bout portent
`service=auth` et `service=payments`, pas le nom du service Compose : un silence limité à
`service=~"auth-service|payment-api"` laisserait passer `EndToEndProbeFailed`, et le moteur relancerait les API. Il dure 10 min au plus. Il ne couvre ni
les alertes d'intégrité (elles prouvent le résultat de la restauration et ne peuvent pas se déclencher pendant qu'elle
tourne, payment-api étant arrêtée), ni la sonde du frontal, ni PostgreSQL, ni les alertes de sécurité.

```bash
AM=http://127.0.0.1:9093
AM_AUTH="admin:$(cat secrets/alertmanager_password)"   # VM : "admin:$(ssh resilience@172.16.147.10 sudo cat /opt/resilience-alpha/shared/secrets/alertmanager_password)"
DEBUT=$(date -u +%Y-%m-%dT%H:%M:%SZ); FIN=$(date -u -d '+10 min' +%Y-%m-%dT%H:%M:%SZ)
SILENCE=$(cat <<EOF
{"matchers": [
   {"name": "alertname", "value": "ServiceDown|EndToEndProbeFailed|HighErrorRate|DependencyFailures|AnomalyDetected", "isRegex": true, "isEqual": true},
   {"name": "service", "value": "auth-service|payment-api|auth|payments", "isRegex": true, "isEqual": true}],
 "startsAt": "$DEBUT", "endsAt": "$FIN", "createdBy": "operateur",
 "comment": "restauration manuelle restore_database.yml : API arrêtées volontairement"}
EOF
)
ID=$(curl -sS --fail -u "$AM_AUTH" -X POST "$AM/api/v2/silences" -H 'Content-Type: application/json' -d "$SILENCE" \
     | python3 -c 'import json,sys; print(json.load(sys.stdin)["silenceID"])'); echo "silence $ID"
```

Le même silence peut se poser dans l'interface d'Alertmanager (« New Silence »), avec exactement ces deux matchers en
expression régulière, une fin dans 10 min et un commentaire.

### Restaurer, vérifier, lever le silence

Lancer la restauration selon [restauration-base.md](restauration-base.md)
(`ansible-playbook -i ansible/inventory.ini ansible/restore_database.yml -e confirm_restore=true`), puis vérifier que le
contrôle interne du registre répond 200 et que les sondes sont revenues à 1. Lever alors le silence aussitôt, sans
attendre son expiration, et contrôler qu'aucun silence ne reste actif :

```bash
curl -sS --fail -u "$AM_AUTH" -X DELETE "$AM/api/v2/silence/$ID" && echo "silence $ID levé"
curl -sS -u "$AM_AUTH" "$AM/api/v2/silences" | python3 -c 'import json,sys; [print(s["id"], s["comment"]) for s in json.load(sys.stdin) if s["status"]["state"] == "active"]'
```

Si une alerte de ces services est encore active quand le silence est levé, Alertmanager la transmet au moteur, qui la
traite normalement : c'est le comportement voulu, le silence ne doit couvrir que la restauration.

### Ne jamais poser un silence global

Un silence `alertname=~".+"` (ou tout silence sans matcher de service) coupe la remédiation automatique de toute la
plateforme : le moteur est le seul destinataire d'Alertmanager, il ne reçoit plus aucune alerte, et aucune panne,
attaque ou corruption n'est plus traitée pendant toute la durée du silence. Comme aucune notification humaine n'existe,
personne n'est prévenu non plus. Les retombées des alertes silencieuses sont aussi retenues, si bien que des incidents
déjà ouverts restent ouverts. La revue de durcissement l'a constaté : pendant des silences globaux, un arrêt de
payment-api survenu à 11:37:43 n'a été remédié qu'à 11:38:52, et l'incident est resté ouvert jusqu'à 11:48:27. Un silence
est donc toujours ciblé sur les services concernés, court, commenté, et levé dès la fin de l'opération.

## 10. Moteur de remédiation en échec, arrêté ou compromis

### RemediationFailed : remédiation en échec ou incident escaladé

**Signification et déclenchement.** `RemediationFailed` se déclenche, sans délai, dès qu'une action du moteur a échoué
ou a été refusée, ou qu'un incident a été escaladé pour un autre motif que `policy`, dans les 10 dernières minutes :
`sum(increase(remediation_actions_total{result=~"failure|refused"}[10m])) > 0 or sum(increase(remediation_escalations_total{reason!="policy"}[10m])) > 0`.
Elle porte `severity=critical`, `domain=availability`, `service=remediation-engine`. Elle reste active environ 10 min
après le dernier échec (fenêtre de `increase`), puis retombe seule. Elle signifie qu'une **intervention humaine est
requise**.

**Ce que fait le moteur.** Rien : il journalise et observe l'alerte, sans jamais agir sur lui-même (anti-boucle).

**Retrouver l'incident escaladé.** L'incident à traiter se trouve dans « Derniers incidents » du dashboard de
supervision (issue « escaladé ») avec son motif dans le bandeau, dans le panneau « Escalades par motif (période) » de
Grafana, par la commande d'état du moteur, ou dans Loki avec
`{service="remediation-engine", event_type="remediation_escalated"} | json`. La chronologie de l'incident
(`/api/incidents/<id>`) dit quelle étape a échoué.

**Que faire selon le motif.** Pour `attempts_exhausted`, le service retombe malgré 3 redémarrages en 10 min : chercher
la cause dans ses journaux au lieu de redémarrer encore, et envisager le retour à la version précédente. Pour
`verification_failed`, l'action a été faite mais la reprise n'est pas prouvée : la chronologie indique le contrôle en
échec (conteneurs, sondes, intégrité, transaction témoin), à reprendre à la main. Pour `action_failed`, l'action n'a pas
pu être exécutée (proxy Docker, WAF ou pont injoignable, restauration en échec, erreur interne) : lire `/health` du
moteur et ses journaux. Pour `bridge_unavailable`, une corruption est confirmée mais le runner de l'hôte est absent :
restaurer à la main ([restauration-base.md](restauration-base.md)) et vérifier les unités systemd du pont sur la VM
(`systemctl status resilience-remediation-bridge.path resilience-remediation-bridge-heartbeat.timer`).

Pour `waf_unavailable`, la liste de blocage du WAF est inaccessible : vérifier le volume `waf-blocklist` et redémarrer le
moteur. Pour `no_offender`, l'attaque n'a pas d'IP attribuable (attaque répartie, moins de 10 événements en 2 min, Loki
injoignable) : analyse par le responsable sécurité et blocage manuel éventuel. Pour `not_allowed`, l'IP appartient à un
réseau exclu (hôte, tunnel d'opérateur, dmz) ou le service n'est pas redémarrable : incident de sécurité sur l'hôte ou
reprise manuelle. Pour `triage_unknown`, l'anomalie ML n'a pas de variable dominante exploitable : lire l'événement
`anomaly_detected`. Pour `container_missing`, le conteneur a disparu : le recréer avec `docker compose up -d --wait
<service>` (sur la VM, depuis la version active) ou redéployer. Pour `unknown_alert`, une règle d'alerte a été ajoutée
sans sa ligne dans la table de décision : responsable développement.

**Vérifier le rétablissement.** Le service de l'incident escaladé est rétabli à la main (transaction témoin réussie),
puis `RemediationFailed` retombe une dizaine de minutes après le dernier échec.

### RemediationEngineDown : le moteur ne répond plus

**Signification et déclenchement.** `RemediationEngineDown` se déclenche quand Prometheus n'arrive plus à scraper le
moteur pendant 30 s : `up{job="remediation-engine"} == 0`. Elle porte `severity=critical`, `domain=availability`,
`service=remediation-engine`. Il n'y a plus aucune reprise automatique. Alertmanager reçoit l'alerte mais ne peut pas la
livrer, puisque le moteur est son seul destinataire : elle se voit dans l'interface d'Alertmanager, dans le panneau
« Moteur et dépendances » de Grafana (moteur KO) et sur le dashboard de supervision (tuile « Moteur de remédiation » rouge, remarque
« moteur de remédiation injoignable : la reprise n'est pas suivie »).

**Causes probables.** Conteneur arrêté par un opérateur, plantage, manque de mémoire (512 Mo), volume d'état
inaccessible.

**Ce que fait le moteur.** Rien, puisqu'il est arrêté.

**Reprise manuelle.** Lire la cause avec `docker compose logs --tail 100 remediation-engine`, puis relancer le moteur
avec `docker compose up -d --wait remediation-engine` (sur la VM, `sudo` depuis la version active). Vérifier ensuite
`/health` du moteur (`status=ok`, ou la liste des dépendances en défaut) et la commande d'état. Pendant que le moteur est
arrêté, appliquer à la main la reprise de chaque alerte active, section par section.

**Escalade.** Responsable développement, et responsable sécurité si l'arrêt n'est pas expliqué.

### Ce qui fonctionne encore sans le moteur

Sans le moteur, la détection continue : Prometheus, le ruler Loki et Alertmanager évaluent et affichent les alertes, et
le dashboard de supervision et Grafana restent consultables. Le WAF continue de bloquer les injections (CRS), les
conteneurs qui plantent sont relancés par Docker (`restart: unless-stopped`, mais pas ceux arrêtés par
`docker compose stop`), les API se reconnectent seules à une base revenue et les sauvegardes planifiées continuent. En
revanche, plus aucun redémarrage, blocage, restauration ni vérification n'est fait, plus aucune chronologie d'incident
n'est tenue, et **les IP déjà bloquées ne se débloquent plus** : la levée à l'expiration est faite par la boucle de fond
du moteur. Au redémarrage du moteur, les blocages échus sont levés en 15 s ; avant, on les lève à la main (section
« Poser ou lever un blocage d'IP à la main », avec `docker compose run`).

Quand le moteur revient, il recharge son état, reprend les incidents interrompus (un incident coupé en pleine action
passe en `failed` puis est retenté sous anti-boucle) et reçoit de nouveau les alertes encore actives, au plus tard au
renvoi d'Alertmanager (5 min). Il faut donc terminer les interventions manuelles avant de relancer le moteur, ou garder
un silence ciblé sur la cible de l'intervention.

### Arrêter le moteur sans risque

Si le moteur se comporte mal (redémarrages en boucle, blocages injustifiés, restauration inattendue), on l'arrête avec
`docker compose stop remediation-engine`. Son état (incidents, chronologies, anti-boucle) est écrit de façon atomique à
chaque étape : l'arrêt ne perd rien, et l'alerte `RemediationEngineDown` qui suit est attendue. On n'utilise pas un
silence global pour « couper » le moteur : il continuerait de tourner et traiterait d'un coup toutes les alertes à
l'expiration du silence.

Si le moteur est soupçonné d'être compromis (actions sans alerte correspondante, refus du webhook
`remediation_webhook_rejected` en série, blocages ou restaurations inexpliqués), on coupe aussi ses moyens d'agir :
`docker compose stop remediation-engine docker-socket-proxy` arrête le proxy, seule porte vers Docker, et sur la VM
`sudo systemctl stop resilience-remediation-bridge.path` arrête le runner de restauration (son heartbeat se périme, toute
demande de restauration serait refusée). On conserve ensuite les preuves : fichier d'état
(`docker compose cp remediation-engine:/state/remediation-state.json ./preuves/`), journaux Loki du moteur et du proxy.
Enfin on fait tourner le jeton du webhook : supprimer `secrets/remediation_webhook_token`, le régénérer avec
`python scripts/init_secrets.py` (qui ne recrée que les secrets absents), puis recréer les deux conteneurs qui le
montent (`docker compose up -d --force-recreate alertmanager remediation-engine`) ; l'escalade va au responsable
sécurité.

## 11. Après l'incident

### Ce qu'il faut consigner

Chaque incident, rétabli seul ou à la main, est consigné : identifiant d'incident du moteur, alertes, horodatages (première
anomalie observée, déclenchement de l'alerte, détection par le moteur, décision, action, rétablissement vérifié,
clôture), nature de la réponse, action et résultat, motif d'escalade éventuel, interventions manuelles (qui, quand,
quelle commande), silences posés et levés, données perdues (pour une restauration, l'âge de la sauvegarde restaurée,
`backup_age_seconds`, et les écritures faites depuis), clients touchés (au labo, un blocage d'IP touche tous les postes
du NAT), cause et actions correctives. Les durées mesurées alimentent le [PCA/PRA](../governance/pca-pra.md).

### Où sont les preuves

La chronologie horodatée de chaque incident est dans l'API d'état du moteur (`/api/incidents/<id>`) et dans son fichier
d'état `/state/remediation-state.json` (volume `remediation-state`, 200 incidents clos conservés). Les journaux sont dans
Loki et les métriques dans Prometheus, conservés 7 jours chacun : il faut exporter les preuves avant. Pour une
restauration, la sauvegarde `pre-restore` de `/var/backups/resilience-alpha/` conserve l'état corrompu pour
l'investigation, et `journalctl -u resilience-remediation-bridge` garde les événements du pont. Les commandes suivantes
exportent un incident et ses journaux :

```bash
mkdir -p preuves
docker compose exec -T remediation-engine python -c "import sys,urllib.request as u; print(u.urlopen('http://127.0.0.1:8000/api/incidents/'+sys.argv[1]).read().decode())" inc-20261020-123035-fc6254 > preuves/inc-20261020-123035-fc6254.json
curl -s -G -u "admin:$(cat secrets/loki_password)" http://127.0.0.1:3100/loki/api/v1/query_range \
  --data-urlencode 'query={service="remediation-engine"} | json | incident_id="inc-20261020-123035-fc6254"' \
  --data-urlencode 'since=24h' --data-urlencode 'limit=5000' > preuves/loki-inc-20261020-123035-fc6254.json
```

### Obligation de notification (DORA)

La plateforme relève de DORA (établissement de paiement) : chaque incident est classé majeur ou mineur selon les
critères DORA (clients touchés, durée, pertes de données, criticité du service, impact économique et réputationnel). Un
incident majeur est notifié à l'ACPR : notification initiale sous 4 h après la classification et au plus tard 24 h
après la détection, rapport intermédiaire sous 72 h, rapport final sous un mois. Une panne d'API corrigée en moins d'une
minute reste un incident mineur, enregistré mais pas notifié ; une corruption du registre (scénario S5) est
probablement majeure, même restaurée en quelques secondes. La chaîne de remédiation ne prévient personne : c'est à
l'opérateur d'informer la cellule de crise ; le pilier Transformation prépare la classification et le premier rapport à
partir de la chronologie du moteur, la Direction les valide. L'analyse complète est dans
[nis2-dora.md](../governance/nis2-dora.md), les seuils internes qui ouvrent l'examen de classification dans le
[PCA/PRA](../governance/pca-pra.md).
