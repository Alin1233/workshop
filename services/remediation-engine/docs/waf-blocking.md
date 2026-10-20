# Blocage d'IP au WAF (réponse à une compromission)

Réponse du moteur à une **tentative de compromission** (force brute `AuthBruteForce`, rafale de jetons invalides
`InvalidTokenFlood`, injections en série `WafAttackBlocked`, anomalie dont la variable dominante est de sécurité) :
couper l'accès de l'attaquant au point d'entrée, sans toucher au service. C'est l'opposé d'un redémarrage, qui ne
rétablit que la **disponibilité** et laisserait l'attaquant continuer.

Code : `app/actions/waf_block.py` (`WafBlocklist`, `BlockEntry`). Configuration du WAF : `infra/waf/`.
Tests : `tests/unit/test_waf_block.py`.

## Mécanisme retenu

```
moteur (uid 10001)                         volume waf-blocklist                 WAF (nginx + ModSecurity, uid 101)
WafBlocklist.block(ip, ttl, …)  ──écrit──▶  blocked-ips.json (état, 0600)
                                 ──écrit──▶  blocked-ips.conf (0644)  ──lu (ro)──▶  map $remote_addr $remediation_blocked
DockerProxy.signal("waf","HUP") ──▶ docker-socket-proxy ──▶ POST /containers/{id}/kill?signal=HUP ──▶ nginx (PID 1) recharge
WafBlocklist.verify(ip)         ──▶ GET http://waf:8081/remediation/blocklist?ip=…  ──▶ {"blocked":1}
```

- **Liste** : `blocked-ips.conf` ne contient que des lignes `"<ip>" 1;` (IP validées par `ipaddress`, triées) et des
  commentaires. Elle est incluse dans deux blocs `map` nginx (`infra/waf/00-remediation-blocklist.conf.template`) :
  le moteur ne peut ni ajouter de directive ni sortir du bloc. Motif, incident et expiration restent dans
  `blocked-ips.json`, jamais dans la configuration nginx (pas d'injection possible par un texte libre).
- **Include en glob** (`include /waf-blocklist/blocked-ips.con[f];`) : un glob sans correspondance n'est pas une erreur
  pour nginx. Le WAF démarre donc sur un volume neuf, avant le moteur, et le premier rechargement après la création du
  fichier le prend en compte. Aucun service d'initialisation, aucune dépendance de démarrage WAF → moteur.
- **Refus** : `infra/waf/location_common.conf.template` (inclus au niveau `server` des ports 8080 et 8443) teste
  `$remediation_blocked` en phase « server rewrite », avant toute location et **avant ModSecurity**, puis passe par une
  location nommée (inaccessible par URI) qui répond `403 {"detail":"blocked_by_remediation"}` avec `modsecurity off`.
  Le refus ne dépend donc pas du mode de ModSecurity (`WAF_MODE=DetectionOnly` compris).
- **Rechargement** : SIGHUP au PID 1 du conteneur `waf`, qui est le maître nginx (`nginx -g 'daemon off;'`, uid 101).
  nginx relit toute la configuration (règles CRS comprises), démarre de nouveaux workers, puis arrête les anciens en
  douceur. Si la nouvelle configuration est invalide, il journalise `[emerg]` et **garde l'ancienne** : le WAF continue
  de servir.

### Pourquoi pas `@ipMatchFromFile` (ModSecurity)

Essayé sur l'image `owasp/modsecurity-crs:4.25-nginx-alpine-lts` : un fichier absent **ou** une ligne invalide fait
échouer le chargement des règles (`"modsecurity_rules_file" directive Rules error`), donc le démarrage de nginx. Il
faudrait garantir l'existence du fichier avant le WAF (service d'init, dépendance au moteur) et ces refus passeraient
par l'audit ModSecurity, donc par la règle SOC `WafAttackBlocked`. Le `map` nginx en glob n'a aucun de ces défauts.

### Preuves (pile locale, `FRONT_PORT=8088`)

| Essai | Résultat |
|---|---|
| WAF recréé avec un volume `waf-blocklist` vide (fichier absent) | démarre, `healthy`, application 200 |
| `block(<IP attaquant sur edge>, 300)` via le vrai `DockerProxy` et un `docker-socket-proxy` (`CONTAINERS=1 POST=1 ALLOW_RESTARTS=1`) | écriture + SIGHUP en 0,05 s ; `verify()` vrai en 0,5 s (16 workers, CRS complet) |
| Attaquant / autre client d'edge / hôte via 127.0.0.1:8088 | 403 JSON (8080 et 8443) / 200 / 200 ; sondes blackbox `probe_success=1` |
| Injection SQL de l'attaquant bloqué | 403 de remédiation, **aucune** ligne d'audit ModSecurity |
| Loki | `{service="waf", event_type="waf_remediation_block"}` : 15 lignes pour l'attaquant ; expression de `WafAttackBlocked` : rien de nouveau pour lui |
| Fichier invalide + SIGHUP | `[emerg] … blocked-ips.conf:3` ; ancienne config conservée, WAF `healthy`, aucun redémarrage |
| Puis `expire()` du moteur | fichier réécrit depuis l'état JSON, rechargé, `verify()` vrai |
| Fichier invalide + redémarrage du conteneur (conteneur jetable, même image et durcissement) | le garde-fou neutralise l'include, le WAF démarre sans liste et journalise `event_type=waf_blocklist_invalid` |
| `unblock()` ; blocage de 5 s puis `expire()` ; second `expire()` | 200 de nouveau ; IP retirée puis rechargée une fois ; aucun rechargement |
| `block("172.25.0.1")` (passerelle edge), `block("172.31.250.2")` (blackbox) | refusés (`ActionError`) |

## Réponse bloquée, journaux et SOC

- Réponse : `HTTP 403`, `Content-Type: application/json`, corps `{"detail":"blocked_by_remediation"}`.
- Journal : une ligne JSON par requête refusée, et une seule (le journal d'accès texte n'est pas doublé) :
  `{"level":"warning","service":"waf","event_type":"waf_remediation_block","client_ip":…,"method":…,"uri":…,"status":403,…}`.
  Alloy en fait le label Loki `event_type=waf_remediation_block`. Requête pour le dashboard ou le SOC :
  `sum by (client_ip) (count_over_time({service="waf", event_type="waf_remediation_block"} | json [5m]))`.
- **Règle `WafAttackBlocked` inchangée** : elle ne lit que l'audit ModSecurity (`|= "\"transaction\""`, `http_code=403`),
  que ces requêtes n'atteignent plus. Une fois l'IP bloquée, l'alerte retombe d'elle-même (fenêtre de 2 min) même si
  l'attaquant insiste ; de même `AuthBruteForce` et `InvalidTokenFlood`, car les requêtes n'atteignent plus les API.
  Les variables `waf_blocks_per_min` du détecteur d'anomalies et les panneaux Grafana existants lisent aussi l'audit :
  ils ne comptent pas les refus de remédiation.
- Côté moteur : `remediation_waf_block`, `remediation_waf_unblock`, `remediation_waf_expire`, `remediation_waf_reload`
  (`result=ok|failed`), `remediation_waf_refused`, `remediation_waf_verify` (échecs), `remediation_waf_discovery`.

## IP source vue par le WAF

Le WAF n'est derrière aucun proxy : `$remote_addr` est l'adresse TCP du client, c'est aussi le `client_ip` des journaux
ModSecurity, des API (via `X-Real-IP`) et donc des alertes. Mesures sur la pile locale (Docker 29, proxy userland actif,
comme sur la VM) :

| Client | IP vue par le WAF |
|---|---|
| Autre machine du réseau → port publié (DNAT de Docker) | son IP réelle ; au labo **172.16.255.252** pour tous (NAT du labo) |
| Hôte → `127.0.0.1:<port>` (proxy userland de Docker) | passerelle d'edge (ici 172.25.0.1) |
| Tunnel SSH `ssh -N -L 8080:127.0.0.1:8080 resilience@172.16.147.10` | passerelle d'edge (sshd se connecte à 127.0.0.1) |
| Hôte → sa propre IP LAN (`curl http://<ip LAN>:<port>`) | l'IP LAN de l'hôte (DNAT, adresse source conservée) |
| Conteneur d'un autre réseau Docker → IP de l'hôte | passerelle d'edge (masquerade de Docker) |
| Conteneur du réseau edge → `waf:8080` | son IP sur edge |
| Conteneur du réseau dmz → `waf:8080` (blackbox, moteur, frontal) | son IP dans `172.31.<DMZ_OCTET>.0/24` |
| Healthcheck du WAF (`curl https://localhost:8443/healthz`) | 127.0.0.1 |

## Liste d'exclusion (IP jamais bloquées)

Toute demande de blocage d'une IP exclue lève `ActionError` (et une ligne `remediation_waf_refused`).

| Source | Réseaux | Pourquoi |
|---|---|---|
| Toujours, non désactivable | `127.0.0.0/8`, `::1/128` | healthcheck du WAF |
| Défaut | `172.31.248.0/21` | toute dmz possible (`DMZ_OCTET` 248 à 255) : sondes blackbox, frontal, transaction témoin du moteur |
| Découvert : `/proc/net/route` du moteur | ses sous-réseaux directement connectés (≥ /16) | le moteur ne peut pas se bloquer lui-même, quel que soit le réseau par lequel il joint le WAF |
| Découvert : `docker inspect` du WAF via le proxy | passerelle de chaque réseau du WAF (/32) | clients locaux de l'hôte et tunnels SSH (opérateurs) |
| `WAF_BLOCK_ALLOWLIST` | CIDR séparés par virgules ou espaces | **s'ajoute** aux défauts (ne les remplace pas) ; une entrée invalide est une erreur |

La découverte du WAF utilise `DockerProxy.inspect(service)` s'il existe, sinon `container_id()` + `GET
{base_url}/containers/{id}/json` (lecture seule, déjà autorisée par `CONTAINERS=1`). Tant qu'elle n'a pas abouti
(proxy injoignable), `block()` refuse plutôt que de bloquer à l'aveugle. Seules les passerelles sont ajoutées, pas le
sous-réseau edge entier : un client distant garde son IP réelle, la dmz est déjà couverte, et un réseau découvert plus
large qu'un /16 n'est jamais ajouté. **172.16.0.0/12 n'est jamais exclu en bloc** : l'IP NAT du labo en fait partie.

## NAT du labo : à connaître avant la démonstration

Au labo, tous les postes (PC attaquant, jury, opérateurs en wifi) arrivent sur la VM avec la **même IP
172.16.255.252**. Bloquer l'attaquant bloque donc **tous les clients du labo** pendant la durée du blocage, y compris
le navigateur du jury et le test de fin de déploiement d'Ansible (lancé depuis le poste de l'opérateur). Ce n'est pas
masqué : l'adresse n'est pas exclue en silence (sinon aucune attaque du labo ne serait jamais bloquée).

- Durée courte par défaut : `WAF_BLOCK_TTL_SECONDS=300` (5 min ; 1 à 86 400). Pour la démonstration, 60 à 120 s
  suffisent à montrer l'effet et la levée automatique.
- L'expiration est appliquée par `expire()` (tâche périodique du moteur) : le blocage dure au plus TTL + une période.
- Pendant le blocage, la reprise reste prouvée : la transaction témoin du moteur part de la dmz (exclue).
- Pour faire une transaction « humaine » pendant le blocage : passer par le tunnel SSH (passerelle edge, exclue), ou
  lever le blocage par anticipation (`unblock`).

## Privilèges

- **Moteur** : écrit dans le seul volume `waf-blocklist` (monté rw, uid 10001) ; envoie SIGHUP au conteneur `waf` par
  `docker-socket-proxy` (`POST /containers/{id}/kill`, permis par `ALLOW_RESTARTS=1` + `POST=1`, déjà nécessaires aux
  redémarrages : aucun droit supplémentaire) ; lit `GET /containers/{id}/json` (`CONTAINERS=1`). Jamais le socket brut.
- **WAF** : volume en **lecture seule** ; rien d'autre ne change (utilisateur nginx, `cap_drop: ALL`,
  `no-new-privileges`). Le port 8081 n'est pas publié (injoignable depuis le labo), n'accepte que les plages privées (`allow`),
  ne passe pas par ModSecurity et ne renvoie que `{"blocked":0|1}`.
- **Pire cas d'un moteur compromis** via ce mécanisme : bloquer des IP non exclues (déni de service ciblé, qu'il pourrait
  déjà provoquer en arrêtant le WAF via le proxy) ou rendre la liste invalide (rechargement refusé, ancienne
  configuration conservée ; au redémarrage, le garde-fou démarre le WAF sans liste). Il ne peut pas modifier le routage,
  les règles CRS ni lire de secret du WAF.
- Alternative sans proxy Docker, si `ALLOW_RESTARTS` devait être retiré : un processus dans le WAF qui surveille le
  fichier (`inotifyd` est présent dans l'image) et lance `nginx -s reload`. Non retenue : processus supplémentaire hors
  supervision dans le conteneur, alors que le proxy est de toute façon requis pour les redémarrages.

## Robustesse

| Situation | Comportement |
|---|---|
| Volume neuf, fichier absent | WAF démarre (glob vide) ; `expire()` au démarrage du moteur crée une liste vide, sans rechargement |
| Fichier invalide au rechargement | nginx garde l'ancienne config ; `verify()` faux ; `expire()` suivant réécrit depuis l'état JSON et recharge |
| Fichier invalide au démarrage du WAF | `/docker-entrypoint.d/99-remediation-blocklist-guard.sh` teste la liste seule (`nginx -t` sur une config minimale) et neutralise ses `include` : le WAF démarre sans liste (CRS actif), ligne `waf_blocklist_invalid` ; un redémarrage du WAF après correction réactive la liste |
| Écriture interrompue | fichier temporaire `.blocked-ips.conf.*.tmp` (hors glob), `fsync`, `os.replace` : jamais de contenu partiel |
| Arrêt du moteur entre l'état et le fichier rendu | `expire()` détecte la désynchronisation, réécrit et recharge |
| SIGHUP en échec (proxy injoignable) | `ActionError` ; `reload_pending` persisté ; `expire()` réessaie, même après un redémarrage du moteur |
| État JSON illisible | mis de côté (`.corrupt-<ts>`), entrées reconstruites depuis le fichier rendu avec la durée par défaut |
| IP déjà bloquée | expiration prolongée (jamais raccourcie), pas de rechargement |
| Appels concurrents | verrou de thread + `flock` sur `.blocked-ips.lock` (deux processus possibles) |
| Liste pleine (`MAX_ENTRIES=1000`) | `ActionError` |

## Vérification (`verify(ip)`)

1. l'IP figure dans `blocked-ips.conf` ;
2. le conteneur `waf` est `healthy` (ou `running`) ;
3. le contrôle interne `http://waf:8081/remediation/blocklist?ip=<ip>` répond `{"blocked":1}` : c'est la configuration
   **réellement chargée** par les workers nginx, donc la preuve que le rechargement a réussi (un rechargement refusé
   laisse `0`). Réessai toutes les 250 ms pendant `verify_timeout_s` (5 s ; observé : 0,5 s).

Le moteur doit partager un réseau avec le WAF (dmz, déjà nécessaire à la transaction témoin). `WAF_BLOCK_CHECK_URL=`
(vide) désactive l'étape 3 ; à éviter.

## Intégration dans le moteur

```python
from .actions.waf_block import WafBlocklist, ttl_from_env
blocklist = WafBlocklist.from_env(docker)        # WAF_BLOCKLIST_PATH, WAF_BLOCK_ALLOWLIST, WAF_BLOCK_CHECK_URL, WAF_SERVICE
await asyncio.to_thread(blocklist.expire)        # au démarrage, puis à chaque tour de la tâche de fond
entry = await asyncio.to_thread(blocklist.block, client_ip, ttl_from_env(), alertname, incident_id)
ok = await asyncio.to_thread(blocklist.verify, client_ip)
```

| Variable | Défaut | Rôle |
|---|---|---|
| `WAF_BLOCKLIST_PATH` | `/waf-blocklist/blocked-ips.conf` | fichier rendu ; **ne pas changer** sans adapter `infra/waf/` |
| `WAF_BLOCK_TTL_SECONDS` | `300` | durée d'un blocage |
| `WAF_BLOCK_ALLOWLIST` | (vide) | réseaux exclus en plus des défauts |
| `WAF_BLOCK_CHECK_URL` | `http://waf:8081/remediation/blocklist` | contrôle interne utilisé par `verify()` |

Compose : volume nommé `waf-blocklist`, monté `rw` sur `/waf-blocklist` dans le moteur et `ro` dans le WAF. Le
Dockerfile du moteur crée `/waf-blocklist` (propriétaire 10001, 0755) : au premier montage d'un volume vide, Docker
recopie ce répertoire et donc ses droits. Sans cela le volume appartient à root et `block()` lève `ActionError`
(« volume … inaccessible »). Le script `infra/waf/99-remediation-blocklist-guard.sh` doit rester exécutable (mode
suivi par git et conservé par `git archive` au déploiement).

## Risques résiduels

- **NAT du labo** : un blocage coupe tous les clients du labo pendant le TTL (voir plus haut).
- **Attaquant distribué ou IP changeante** : une IP à la fois, réaction après détection (≈ 15 à 30 s : évaluation des
  règles + délai d'Alertmanager) ; le CRS reste la première barrière.
- **Connexions déjà ouvertes** : un rechargement ferme les connexions keep-alive inactives des anciens workers, mais
  une requête longue déjà en cours (WebSocket, téléchargement) se termine sur l'ancienne configuration.
- **Coût du rechargement** : nginx relit tout le CRS et double brièvement ses workers ; sans conséquence au rythme des
  alertes, à surveiller si les blocages devenaient très fréquents (une seule action par changement de la liste).
- **Garde-fou au démarrage** : il préfère démarrer sans liste plutôt que ne pas démarrer ; la liste ne revient qu'au
  redémarrage suivant du WAF. `verify()` le révèle (`blocked=0`), la ligne `waf_blocklist_invalid` aussi.
- **Montée de version de l'image WAF** : `location_common.conf.template` remplace celui de l'image (ses blocs
  d'origine sont recopiés à l'identique) ; à resynchroniser si l'image change. Le test `test_waf_config_reads_the_rendered_file` vérifie
  la cohérence des chemins.
- **IPv6** : pris en charge par la liste et la validation ; la découverte de `/proc/net/route` est IPv4 seulement
  (les réseaux de la pile n'ont pas d'IPv6).

## Tester

Tests unitaires (sans Docker) : `.venv/bin/python -m pytest tests/unit/test_waf_block.py`.

Essai manuel sur la pile (le moteur pas encore déployé, la liste écrite à la main comme il le ferait) :

```bash
# Client « attaquant » sur edge, et son IP
docker run -d --name demo-attacker --network resilience-alpha_edge --entrypoint sleep curlimages/curl 600
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' demo-attacker)
# Bloquer : écrire la liste en uid 10001 puis recharger
docker run --rm --user 10001:10001 -v resilience-alpha_waf-blocklist:/w curlimages/curl \
  sh -c "printf '\"%s\" 1;\n' $IP > /w/blocked-ips.conf"
docker kill -s HUP resilience-alpha-waf-1
docker exec demo-attacker curl -s -i http://waf:8080/ | sed -n '1p;$p'     # 403 {"detail":"blocked_by_remediation"}
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8088/             # 200 : les autres ne sont pas touchés
docker logs --since 1m resilience-alpha-waf-1 | grep waf_remediation_block
# Lever : liste vide puis rechargement
docker run --rm --user 10001:10001 -v resilience-alpha_waf-blocklist:/w curlimages/curl sh -c ': > /w/blocked-ips.conf'
docker kill -s HUP resilience-alpha-waf-1 && docker rm -f demo-attacker
```

Avec le moteur déployé : déclencher `AuthBruteForce` depuis un second poste (ou un conteneur sur edge), puis suivre
l'incident (`GET /api/incidents`) : action `block`, `verify` vrai, 403 pour l'attaquant, transaction témoin réussie,
levée automatique après `WAF_BLOCK_TTL_SECONDS`.
