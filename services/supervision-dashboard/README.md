# supervision-dashboard — écran de supervision de la reprise (pilier DEV)

Interface **React + Tailwind** (imposé, sujet §3.1) qui montre au jury les composants, les alertes, les événements et
l'avancement de la reprise, en direct. C'est **l'écran du Clip Chrono** (§7.3) : pensé pour une capture **1080p**
(1920 × 1080, sans défilement), contrastes forts, changements d'état évidents, horloge à la seconde (preuve d'une
séquence continue).

- **URL** : http://127.0.0.1:8091 (`MGMT_BIND`, `SUPERVISION_PORT`) — identifiant **`admin`** / `secrets/supervision_password`
  (généré par `python scripts/init_secrets.py`).
- **Sur la VM PC Hôte** : `ssh -N -L 8091:127.0.0.1:8091 resilience@172.16.147.10`, puis http://127.0.0.1:8091 sur le poste.
- Rafraîchissement toutes les **2 s** (`?refresh=1000` à `10000` ms dans l'URL pour changer).

## Architecture : un back-for-front

```
navigateur ──HTTP basique (admin)──▶ supervision-dashboard :8000 (publié sur 127.0.0.1:8091, réseau mgmt)
                                       │  FastAPI : sert l'interface construite (/, /assets) + API JSON en lecture seule
                                       │  vues prédéfinies, cache 1,5 s partagé, délais 1 s (connexion) / 2 s (réponse)
                         réseau obs ───┼──▶ Prometheus :9090      (admin / secret prometheus_password)   /api/v1/query, /api/v1/alerts
                         (interne)     ├──▶ Alertmanager :9093    (admin / secret alertmanager_password) /api/v2/alerts
                                       ├──▶ Loki :3100            (sans identifiant sur obs)            /loki/api/v1/query_range
                                       └──▶ remediation-engine :8000 (API d'état, sans identifiant)     /api/state, /api/incidents[/{id}]
```

Le navigateur ne joint **que** ce service : réseaux internes et identifiants des sources restent côté serveur. Une seule
image, construite en deux étapes (`Dockerfile`, contexte `./services`) : **node** construit l'interface (`npm ci`,
`npm run build`), **python 3.12** la sert avec le back-for-front (utilisateur 10001, `read_only`, `cap_drop: ALL`,
`no-new-privileges`, `/tmp` en tmpfs, comme les autres services Python).

| Fichier | Rôle |
|---|---|
| `app/main.py` | application FastAPI : authentification, en-têtes de sécurité, routes, service des fichiers construits |
| `app/sources.py` | clients **GET uniquement** des quatre sources, chemins autorisés par source, requêtes PromQL/LogQL **constantes**, cache |
| `app/shaping.py` | fonctions pures : carte des composants, bandeau d'état global, alertes, événements, blocages, incidents |
| `app/config.py` | configuration (variables d'environnement), secrets relus à chaque usage |
| `src/` | interface React 19 + Tailwind 4 + TypeScript (Vite 8), mêmes versions et même identité que `services/frontend` |
| `src/lib/timeline.ts` | chronologie affichée, construite depuis la chronologie brute du moteur |

## L'écran

| Zone | Contenu |
|---|---|
| En-tête | marque, indicateur **EN DIRECT** (heure du dernier rafraîchissement ; « données figées » ou « supervision injoignable » sinon), horloge du serveur à la seconde |
| **Bandeau d'état** | **Opérationnel** (fond sombre, vert) · **Incident en cours** (rouge) · **Remédiation en cours** (ambre) · **Service rétabli** (vert plein) · État inconnu ; étape en cours en clair, chronomètre depuis la première anomalie observée (ou durée figée du rétablissement + temps de réaction du moteur), décision du moteur (nature + action), identifiant d'incident, pastilles d'avancement *Anomalie → Alerte et décision → Action → Vérification → Rétabli* |
| Carte des composants | parcours client **WAF → frontal → auth-service → payment-api → PostgreSQL**, puis chaîne de résilience **observation → détecteur ML → moteur → pont de restauration** ; vert / ambre / rouge / bleu (en action) / gris (inconnu), avec la raison ; intégrité du registre et scores ML |
| Chronologie de la reprise | incident en cours (ou dernier incident) **horodaté par le moteur** : alerte → détecté → décision (*Disponibilité* / *Compromission* + redémarrage / blocage d'IP / restauration, avec la justification) → action et son résultat → vérification (**conteneurs, blocage WAF, intégrité, sondes, transaction témoin**, chacun OK / échec / indisponible) → rétabli ou échec / escalade ; heure, écart `T+` depuis l'alerte, durée de chaque étape. Avant que le moteur ne reçoive l'alerte : « Anomalie observée », étapes suivantes à venir |
| Alertes actives | Alertmanager (règles Prometheus **et** SOC Loki) + règles encore *en confirmation* dans Prometheus ; gravité, domaine, source, service, IP |
| IP bloquées au WAF | IP, motif, **compte à rebours jusqu'à la levée automatique** (heure du serveur) et barre de TTL ; état de la liste WAF et du pont de restauration |
| Événements en direct | journaux Loki en liste blanche, les plus récents surlignés ; rafales d'attaque regroupées (« Échec d'authentification ×37 depuis 172.25.0.3 ») |
| Derniers incidents | heure, alerte, nature, réponse exécutée, issue, durée ; les incidents **rattachés** (même panne, déjà traitée, seulement vérifiée) sont signalés |

**Ce que montre chaque phase** (arrêt de `payment-api`, relevé en direct le 20/10, voir « Recette ») :

1. **Avant** : *Opérationnel*, tout est vert (le pont de restauration est ambre en local : runner de développement non lancé).
2. **Panne** (+6 s) : *Incident en cours — Anomalie détectée par les sondes : payment-api en échec* ; tuile payment-api
   rouge (« /health en échec à travers le WAF (HTTP 502) »), chronomètre lancé, chronologie « Anomalie observée ».
3. **Alerte** (+28 s Prometheus, +33 s à l'écran) : *Alerte EndToEndProbeFailed, ServiceDown déclenchée : transmission au
   moteur* ; alertes critiques dans le panneau, `AnomalyDetected` en confirmation, score ML de payment-api en rouge.
4. **Réaction** (+36 s) : *Remédiation en cours — Action : redémarrage de payment-api*, décision *Disponibilité ·
   redémarrage de payment-api*, moteur en bleu « en action », événements « Incident ouvert », « Décision », « Démarrage ».
5. **Vérification** (+43 s) : contrôles conteneurs 4/4, sondes 3/3, **transaction témoin** (virement 1,00 € à travers le WAF).
6. **Rétabli** (+43 s) : *Service rétabli* plein écran vert, **37 s** de la première anomalie au service vérifié, réaction du
   moteur **7,0 s** ; puis *incident clos* à la retombée des alertes (+66 s). Le bandeau reste « Service rétabli » 3 min
   (`RESTORED_WINDOW_SECONDS`), puis repasse à *Opérationnel*.

Pendant une **restauration de la base**, `resilience-pg-restore` arrête exprès les API : leurs tuiles et PostgreSQL passent en
bleu « arrêtée volontairement pendant la restauration », le pont en « restauration en cours », le bandeau en *Remédiation en
cours — Action : restauration de la base par le pont de l'hôte*.

## API du back-for-front

Toutes les routes sont en **GET**, derrière l'authentification basique sauf `/health`. Chaque réponse porte
`server_time` (les chronomètres suivent l'horloge du serveur) et `sources.<nom> = {ok, error, age_s, latency_ms}` pour
chaque source lue ; une source en panne donne `ok: false` et des données vides, **jamais** une erreur HTTP. Schéma :
[`docs/api/supervision-dashboard.openapi.json`](../../docs/api/supervision-dashboard.openapi.json)
(`python scripts/export_openapi.py`, vérifié par `--check`).

| Route | Sources | Contenu |
|---|---|---|
| `GET /health` | aucune | `{"service", "status": "ok"}` : le healthcheck Docker ne dépend d'aucune source (`up --wait` passe moteur, Loki ou Prometheus arrêtés) |
| `GET /api/overview` | Prometheus (métriques, règles), Alertmanager, moteur (`/api/state` + incident suivi) | `status` (bandeau : `phase`, `step_key`, `step`, `since`, `duration_s`, `reaction_s`, `incident_id`, `alertname`, `service`, `nature`, `decision`, `escalated`, `open_incidents`, `notes`), `components[]` (`id`, `label`, `role`, `state`, `reason`), `integrity`, `anomaly` |
| `GET /api/alerts` | Alertmanager, Prometheus | `alerts[]` : `name`, `severity`, `domain`, `service`, `client_ip`, `summary`, `starts_at`, `state` (`firing` / `pending`), `source` (`prometheus` / `loki`), `silenced` |
| `GET /api/incidents?limit=8` | moteur | 20 incidents lus au plus (requête fixe), `limit` de 1 à 20 ; résumé + `follow_up_of` (incident principal d'un incident rattaché) |
| `GET /api/incidents/current` | moteur | incident complet à raconter : l'incident métier ouvert le plus actif, sinon le dernier clos (rattachés écartés) |
| `GET /api/incidents/{id}` | moteur | incident complet ; identifiant validé (`inc-AAAAMMJJ-HHMMSS-xxxxxx`) **avant** tout appel, sinon 404 |
| `GET /api/blocks` | moteur | `blocks[]` (`ip`, `expires_at`, `remaining_s`, `ttl_s`, `blocked_at`, `reason`, `incident_id`), `waf_blocklist`, `bridge` |
| `GET /api/events?limit=40` | Loki | événements des 30 dernières minutes, `limit` de 1 à 100 ; types en liste blanche, champs en liste blanche, bornés |

**Requêtes prédéfinies** (`app/sources.py`, constantes) :
- Prometheus, une requête instantanée : `{__name__=~"up|probe_success|probe_http_status_code|payment_ledger_integrity_ok|payment_ledger_integrity_last_check_timestamp|anomaly_score|anomaly_threshold|anomaly_detector_source_up"}` ;
  et `GET /api/v1/alerts` (règles *pending* : l'anomalie se voit avant la confirmation de l'alerte) ;
- Alertmanager : `GET /api/v2/alerts` (actives, silencieuses comprises pour les signaler) ;
- Loki : `{event_type=~"remediation_.+|anomaly_detected|anomaly_cleared|integrity_violation|dependency_failure", event_type!~"remediation_(webhook|duplicate)"}`
  (80 lignes) et `{event_type=~"auth_failure|waf_remediation_block"}` (300 lignes, regroupées), fenêtre de 30 min.

### Règles d'affichage

**Bandeau** (`shaping.global_status`) : incident métier ouvert → *Incident en cours* (détecté, décidé, observé, escaladé)
ou *Remédiation en cours* (action, vérification, nouvelle tentative, attente d'un maillon qui démarre) ; incident rétabli
et vérifié (encore ouvert, ou clos depuis moins de 3 min) → *Service rétabli* ; sinon, maillon métier en panne, alerte
métier en attente ou active, ou score ML au-dessus du seuil → *Incident en cours* avant même que le moteur ne soit
prévenu ; sinon *Opérationnel*. Les incidents d'exploitation (hôte, sauvegardes, détecteur, moteur) ne pilotent pas le
bandeau : ils apparaissent en remarque. La durée « de la première anomalie au service vérifié » part de la première
anomalie **vue par le back-for-front** (mémoire du processus) ou, à défaut, du déclenchement de l'alerte.

**Incidents rattachés** : une même panne déclenche souvent plusieurs incidents (ex. `AnomalyDetected` 18 s après
`ServiceDown`) ; le second n'a pas d'action propre (« payment-api déjà redémarré ») et est seulement vérifié. Il est écarté
de la chronologie et du bandeau tant qu'il se passe bien (`shaping.follow_up_of`), pour que l'écran raconte l'incident qui
a agi ; s'il échoue ou est escaladé, il est affiché.

**Composants** (`shaping.components`) :

| Tuile | Vert | Ambre | Rouge / bleu |
|---|---|---|---|
| WAF | répond aux sondes (tout code HTTP), N IP bloquées | blocage d'IP indisponible | aucune sonde ne reçoit de réponse (code 0) |
| Frontal | sonde de la page d'accueil OK | — | sonde en échec avec un code du WAF (502…) ; inconnu si le WAF est muet |
| auth-service, payment-api | `/health` OK à travers le WAF (registre cohérent pour payment-api) | processus actif mais parcours coupé en amont ; sonde revenue avant le scrape | `up = 0`, `/health` en échec (HTTP 503…), registre incohérent ; **bleu** pendant une restauration |
| PostgreSQL | une API lit la base | — | les deux API en 503 alors que le frontal répond ; **bleu** pendant une restauration ; inconnu si les API sont coupées |
| Observation | Prometheus, Alertmanager, Loki, Alloy, blackbox OK | l'un d'eux en panne | Prometheus injoignable |
| Détecteur ML | scores sous le seuil | anomalie détectée (score ≥ seuil), source aveugle | arrêté |
| Moteur | à l'écoute d'Alertmanager | dépendance en défaut (proxy Docker…) | API d'état injoignable ; **bleu** en action |
| Pont de restauration | runner prêt (signe de vie récent) | runner absent : une corruption serait escaladée | **bleu** restauration en cours |

## Modèle de sécurité

- **Authentification basique** sur l'interface et l'API (`admin` / secret Compose `supervision_password`, relu à chaque
  requête : rotation sans redémarrage), comparaison **à temps constant** (`hmac.compare_digest`) ; refus 401 avec défi
  `WWW-Authenticate`, journalisé (`event_type=auth_failure`, IP) ; mot de passe absent : 503 partout (fermé par défaut).
  Seule `/health` est publique, réduite à `{"status": "ok"}`.
- **Lecture seule** : toute méthode autre que GET/HEAD est refusée (405) avant le routage ; les clients n'émettent que des
  GET vers une **liste fermée de chemins par source** (`Upstream.routes`) — ni `POST /alerts` du moteur, ni silence
  Alertmanager, ni écriture Loki, même par erreur de code (un test le vérifie).
- **Aucune requête du client** : PromQL et LogQL sont des constantes ; les paramètres reçus (`query`, `promql`, `logql`…)
  sont ignorés ; seuls `limit` (bornés) et un identifiant d'incident validé par expression régulière sont acceptés.
- **Identifiants côté serveur** : les mots de passe Prometheus et Alertmanager sont lus dans des secrets Compose et ne
  sont jamais renvoyés au navigateur ; les documents du moteur sont recopiés sans aucune clé sensible
  (`pass|secret|token|authorization|cookie|credential`), avec des tailles bornées ; les journaux d'attaque sont tronqués et
  affichés comme du texte (React échappe tout).
- **Page** : CSP stricte (`default-src 'self'`, ni script ni style en ligne, `frame-ancestors 'none'`), `X-Frame-Options:
  DENY`, `nosniff`, `no-referrer`, `Cache-Control: no-store`.
- **Réseau** : `obs` (interne) pour les sources, `mgmt` (non interne, comme Grafana et Prometheus) pour publier le port,
  sur `127.0.0.1` uniquement (`MGMT_BIND`). Aucun accès au socket Docker, à la base ni aux API métier.

**Risques résiduels** : le compte Alertmanager est unique (`admin`) et permet aussi de poser des silences ; le back-for-front
le détient mais n'émet que des GET vers `/api/v2/alerts` (un service compromis pourrait toutefois s'en servir). Le compte
du dashboard est partagé (pas de comptes nominatifs). L'API d'état du moteur reste joignable sans identifiant depuis `obs`.

## Configuration

Variables (défauts dans `docker-compose.yml`) : `ENGINE_URL`, `PROMETHEUS_URL` / `PROMETHEUS_USER` /
`PROMETHEUS_PASSWORD_FILE`, `ALERTMANAGER_URL` / `ALERTMANAGER_USER` / `ALERTMANAGER_PASSWORD_FILE`, `LOKI_URL`,
`SUPERVISION_USER` / `SUPERVISION_PASSWORD_FILE`, `SOURCE_TIMEOUT_SECONDS` (2), `CACHE_TTL_SECONDS` (1,5),
`RESTORED_WINDOW_SECONDS` (180, `SUPERVISION_RESTORED_WINDOW_SECONDS` dans `.env`), `EVENTS_WINDOW_SECONDS` (1800),
`STATIC_DIR`. Port publié : `SUPERVISION_PORT` (8091).

```bash
python scripts/init_secrets.py                          # crée secrets/supervision_password (conserve les autres)
docker compose up -d --build supervision-dashboard      # healthy même si le moteur, Loki ou Prometheus sont arrêtés
```

## Développer et tester

```bash
cd services/supervision-dashboard
npm ci && npm test        # Vitest + React Testing Library (jsdom, fetch simulé, horloge simulée)
npm run build             # tsc -b (typage des tests compris) puis vite build → dist/
npm run dev               # rechargement à chaud ; /api relayé vers le back-for-front de la stack (127.0.0.1:8091)
.venv/bin/python -m pytest tests/unit/test_supervision_bff.py   # depuis la racine : back-for-front, fausses sources
```

- **Interface** (`src/**/*.test.tsx`, 19 tests) : bandeau dans chaque phase (chronomètre qui avance, durée figée,
  escalade, sans données) ; chronologie construite depuis **trois incidents réels du moteur** (`src/test/fixtures.ts` :
  redémarrage de payment-api, restauration par le pont, blocage d'IP) et pendant la vérification ; affichage quand des
  sources tombent (tout arrêté, Loki seul, back-for-front injoignable : jamais de page blanche ni de « aucun incident »
  trompeur) ; compte à rebours du TTL des blocages (heure du serveur) ; historique avec incident rattaché.
- **Back-for-front** (`tests/unit/test_supervision_bff.py`, 55 tests, transport httpx factice) : authentification,
  routes en lecture seule, requêtes constantes, limites, identifiant validé, chemins fermés par source, sources en
  panne, identifiants jamais renvoyés, cache partagé, mise en forme (phases du bandeau, composants, alertes, événements,
  blocages, incidents rattachés), documentation OpenAPI exportée.

## Recette en direct (20/10, pile locale)

`docker compose stop payment-api` à T0, écran filmé en 1920 × 1080 (navigateur sans tête), vue d'ensemble relevée chaque
seconde. Jalons du moteur : alerte `EndToEndProbeFailed` + `ServiceDown` déclenchée à **+28 s**, reçue à **+36 s**,
`start` de payment-api à **+37 s**, conteneur sain à **+43 s**, conteneurs / sondes / **transaction témoin** OK à **+43 s**,
incident clos à **+66 s**. Écran : anomalie à +6 s, alerte à +33 s, remédiation à +37 s, *Service rétabli* à +44 s
(« 37 s de la première anomalie au service vérifié », « réaction du moteur : 7,0 s »). Deux défauts trouvés et corrigés
pendant la recette, avec un test chacun : l'incident rattaché `AnomalyDetected` remplaçait l'incident principal à
l'écran (réaction affichée 0,8 s au lieu de 7,0 s) ; la tuile payment-api restait rouge ~3 s après la reprise vérifiée
(scrape Prometheus plus lent que la sonde). Panne des sources simulée en détachant le seul conteneur du dashboard du
réseau `obs` : conteneur toujours `healthy`, toutes les routes en 200, moteur et Loki signalés « délai dépassé » panneau par
panneau.

## Limites et suites

- La durée « depuis la première anomalie » est une mémoire du processus : après un redémarrage du back-for-front pendant
  un incident, elle part du déclenchement de l'alerte (plus tardif).
- Pas de métriques propres (`/metrics`) ni de cible Prometheus : la santé du service se lit dans `docker compose ps`.
- Grafana garde les vues d'analyse (« Santé du service », « SOC ») : l'écran ne trace pas de courbes.
- Le « second poste » qui déclenche l'incident n'apparaît pas à l'écran : le Clip Chrono doit filmer les deux postes.
