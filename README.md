# Resilience-Alpha — SI de paiement fictif

Démonstrateur du Workshop EPSI 2026 « PROJECT RESILIENCE-ALPHA » : une plateforme de virements entre comptes fictifs,
protégée par un WAF, observée par Prometheus / Loki / Grafana, avec une fonction SOC, une détection d'anomalies par ML
et un moteur de remédiation qui répond aux alertes (redémarrage, blocage d'IP au WAF, restauration de la base) puis
vérifie la reprise par une transaction témoin.

**Reste à faire, par domaine : [docs/TODO.md](docs/TODO.md).**

> Toutes les données sont fictives. Aucune donnée bancaire réelle ne doit être saisie.

## Architecture

```
                PA du groupe (192.168.137.0/24)
                           │  :8080
                 ┌─────────▼─────────┐   réseau "edge"
                 │ waf (ModSecurity  │   OWASP CRS, journal d'audit JSON
                 │   + OWASP CRS)    │
                 └─────────┬─────────┘   réseau "dmz" (interne)
                 ┌─────────▼─────────┐
                 │ frontend (nginx)  │   React + Tailwind, reverse proxy /api/*
                 └───┬───────────┬───┘
        /api/auth/*  │           │  /api/payments/*        réseau "app" (interne)
          ┌──────────▼───┐   ┌───▼──────────┐
          │ auth-service │   │ payment-api  │   FastAPI
          │  JWT RS256   │   │  registre    │   (vérifie les JWT avec la clé publique, sans appel à auth)
          └──────┬───────┘   └──────┬───────┘
                 │ authdb           │ paydb                 réseau "data" (interne)
                 └───────┬──────────┘
                  ┌──────▼──────┐
                  │ PostgreSQL  │   une base + un rôle par service
                  └─────────────┘
```

| Service | Rôle | Exposé |
|---|---|---|
| `waf` | ModSecurity + OWASP CRS (paranoïa 1), unique point d'entrée | **oui**, port 8080 |
| `frontend` | SPA React/Vite/Tailwind servie par nginx non privilégié, reverse proxy vers les API | non (derrière le WAF) |
| `auth-service` | Inscription, connexion (argon2id), **double authentification TOTP** (optionnelle pour les clients, imposée à l'admin ; codes de secours), émission de JWT RS256 (15 min), compte admin initial | non |
| `payment-api` | Comptes, virements en partie double, idempotence, contrôle d'intégrité | non |
| `postgres` | `authdb` (rôle `auth_svc`) et `paydb` (rôle `pay_svc`), isolées | non |

### Observabilité, SOC et remédiation (piliers Infrastructure / Sécurité / Développement)

```
 conteneurs ──stdout JSON──▶ fichiers json-file ──▶ alloy ──▶ loki ──règles SOC──┐
 API /metrics, sondes blackbox (à travers le WAF) ──▶ prometheus ──règles──────────┼──▶ alertmanager ──webhook (jeton porteur)──▶ remediation-engine ──▶ docker-socket-proxy / WAF / pont hôte
                                       grafana ◀── prometheus, loki, alertmanager ┘
 anomaly-detector (ML) ◀── prometheus + loki, toutes les 10 s ; anomaly_score{service} ──▶ prometheus (règle AnomalyDetected)
 remediation-engine ──▶ vérification de la reprise : conteneurs (proxy Docker), sondes (prometheus), transaction témoin (WAF)
```

| Service | Rôle | Accès (PC Hôte uniquement) |
|---|---|---|
| `grafana` | tableaux « Santé du service » et « SOC » provisionnés (générés par `infra/grafana/generate_dashboards.py`) ; « Santé du service » a une rangée **Remédiation** : incidents ouverts, IP bloquées, actions par type, cible et résultat, escalades par motif, vérifications, durées détection → rétablissement vérifié et alerte → rétablissement vérifié (p50 / p95 / moyenne, incidents où le moteur a agi), dépendances du moteur, alertes reçues et refus du webhook, journal `remediation_*` + `waf_remediation_block`, et annotations d'incident sur tous les graphiques | http://127.0.0.1:3000 (admin / `secrets/grafana_admin_password`) |
| `prometheus` | métriques, sondes de bout en bout, 16 règles (`infra/prometheus/rules` : service, intégrité, détection ML `AnomalyDetected` et santé du détecteur, PC Hôte, sauvegardes, moteur de remédiation) | http://127.0.0.1:9090 (admin / `secrets/prometheus_password`) |
| `alertmanager` | regroupe les alertes et les envoie au moteur de remédiation (`firing` et `resolved`, webhook authentifié par jeton porteur) | http://127.0.0.1:9093 (admin / `secrets/alertmanager_password`) |
| `loki` | journaux centralisés + 5 règles SOC LogQL (`infra/loki/rules/fake/soc.yml`) | via `loki-proxy` |
| `loki-proxy` | nginx : authentification basique devant Loki, qui n'en a pas (les accès internes d'Alloy et Grafana restent directs) | http://127.0.0.1:3100 (admin / `secrets/loki_password`) |
| `alloy` | collecte les journaux en lisant les fichiers Docker (aucun accès au socket) | — |
| `blackbox` | sonde le parcours client WAF → nginx → API → base | — |
| `node-exporter` | ressources du PC Hôte (CPU, mémoire, disque) et état des sauvegardes PostgreSQL, sans accès au socket Docker | — |
| `ollama` | LLM local de l'assistant RAG (CPU), profil `ai` (`--profile ai` ou `COMPOSE_PROFILES=ai`) ; sinon PC de délestage IA via `OLLAMA_BASE_URL` | non publié (réseau `ai`) |
| `anomaly-detector` | détection d'anomalies ML (z-score robuste calibré, `ml/`) : `anomaly_score{service}` 0..1 pour auth-service, payment-api, frontend (NaN si pas de donnée) ; sa propre santé est surveillée (`AnomalyDetectorBlind`, `AnomalyDetectorDown`) ; `AnomalyDetected` est triée par le moteur de remédiation selon la variable dominante ([README](services/anomaly-detector/README.md)) | — (scrapé par Prometheus, réseau `obs`) |
| `remediation-engine` | moteur de remédiation : webhook Alertmanager authentifié → table de décision (toutes les règles Prometheus et Loki, vérifié par un test) → redémarrage (disponibilité) ou blocage d'IP au WAF / restauration de la base par le pont de l'hôte (compromission) → vérification (conteneurs, sondes, transaction témoin) ; anti-boucle et escalade ; API d'état en lecture seule ([README](services/remediation-engine/README.md)) | non publié (réseaux `obs`, `app`, `dmz`, `docker-api`) |
| `docker-socket-proxy` | seule porte vers le démon Docker, réservée au moteur : lecture d'état et restart / start / kill uniquement | non publié (réseau interne `docker-api`) |
| `ops-assistant` | assistant RAG des opérateurs (Ollama + LangChain) : procédures et architecture, réponses sourcées, aucune action ([README](services/ops-assistant/README.md)) | http://127.0.0.1:8090 (admin / `secrets/ops_assistant_password`) |
| `supervision-dashboard` | **écran de supervision du jury et du Clip Chrono** (React + Tailwind) : état global (opérationnel / incident / remédiation / rétabli), carte des composants, chronologie horodatée de la reprise, alertes, IP bloquées avec TTL, événements, historique ; back-for-front FastAPI en lecture seule (requêtes prédéfinies vers Prometheus, Alertmanager, Loki et l'API d'état du moteur, identifiants côté serveur) ([README](services/supervision-dashboard/README.md)) | http://127.0.0.1:8091 (admin / `secrets/supervision_password`) |

Les interfaces de gestion ne sont publiées que sur `127.0.0.1` (`MGMT_BIND`), conformément au §4 du sujet.

**Revue de durcissement** (Trivy sur les 19 images, secrets, authentification des interfaces, en-têtes HTTP, niveau de
paranoïa du WAF mesuré, conteneurs, risques résiduels, commandes pour la rejouer) : [docs/securite/revue-durcissement.md](docs/securite/revue-durcissement.md).

**PCA / PRA** (fonctions critiques et coût d'indisponibilité fictif, RTO / RPO cibles et mesurés, scénarios, choix de
restauration, RACI, tests, risques résiduels, recommandations) : [docs/governance/pca-pra.md](docs/governance/pca-pra.md).

**Réponse à incident** (runbook alerte par alerte pour les 21 règles : déclenchement exact, réponse automatique du moteur,
vérification, reprise manuelle, escalade ; où regarder, silence Alertmanager ciblé avant une restauration manuelle,
moteur arrêté ou compromis, preuves et notification) : [docs/runbooks/incident-response.md](docs/runbooks/incident-response.md) ;
restauration de la base : [docs/runbooks/restauration-base.md](docs/runbooks/restauration-base.md).

### Modèle métier

- Chaque utilisateur reçoit un compte `RA` + 10 chiffres à sa première connexion, crédité de 1 000,00 € par la trésorerie fictive.
- Un virement = 1 ligne `transfers` + 2 écritures `ledger_entries` (−montant / +montant) + mise à jour des soldes, **dans une seule transaction**,
  comptes verrouillés dans un ordre fixe (pas d'interblocage).
- En-tête `Idempotency-Key` obligatoire : un virement renvoyé (double clic, nouvel essai après un incident) n'est jamais débité deux fois.
- **Contrôle d'intégrité** (`ledger.check_integrity`) : somme des écritures nulle, soldes égaux aux écritures, virements équilibrés, aucun solde négatif.
  C'est la preuve que les **données** sont saines après une reprise, au-delà du simple redémarrage d'un conteneur.

## Démarrage

Prérequis : Docker Desktop (WSL2) et Python 3.10+ (pour les scripts). OpenSSL ou `pip install cryptography` pour générer la clé JWT.

```bash
python scripts/init_secrets.py      # crée ./secrets (mots de passe, hash bcrypt, paire RSA), jamais versionné
cp .env.example .env                # facultatif
docker compose up -d --build
python tests/smoke_test.py          # 28 vérifications de bout en bout
python tests/observability_check.py # 23 vérifications : WAF, Prometheus, Loki, règles SOC, Alertmanager, Grafana, refus sans identifiant
```

Secrets versionnés chiffrés (SOPS + age) : `python scripts/sops_secrets.py keygen|encrypt|decrypt` (voir l'en-tête du script).
Déploiement automatisé sur le PC Hôte (VM Proxmox `172.16.147.10`), depuis WSL : `ansible-playbook -i ansible/inventory.ini ansible/deploy.yml`
(création et préparation de la VM, retour arrière, accès aux interfaces de gestion : voir `ansible/README.md`).

- Application : http://127.0.0.1:8080 (depuis un autre poste : `http://192.168.137.1:8080`)
- Documentation OpenAPI : http://127.0.0.1:8080/api/auth/docs et http://127.0.0.1:8080/api/payments/docs ;
  version exportée pour le rendu dans `docs/api/` (`python scripts/export_openapi.py`, `--check` pour vérifier qu'elle est à jour),
  avec celle du moteur de remédiation (`docs/api/remediation-engine.openapi.json` : webhook et API d'état), qui n'a ni
  port publié ni `/docs` en direct
- Admin : `admin@resilience.local`, mot de passe dans `secrets/admin_password` ; **double authentification imposée** :
  secret TOTP dans `secrets/admin_totp_secret` (base32), à ajouter dans une appli d'authentification (Google Authenticator,
  FreeOTP…) avec l'URI `otpauth://` affichée par `init_secrets.py` ; le smoke test calcule les codes lui-même
- Double authentification des clients : à activer dans **Paramètres → Sécurité** (bouton de l'en-tête : QR code,
  premier code, 10 codes de secours affichés une fois). Connexion en deux étapes : `POST /api/auth/login` renvoie
  `mfa_required` et un jeton d'étape (5 min, 5 essais), puis `POST /api/auth/login/mfa` avec le code TOTP ou un code de
  secours. Un code TOTP ne sert qu'une fois ; un code refusé est journalisé en `auth_failure` (règles SOC, détecteur ML,
  blocage d'IP) ; le jeton d'accès porte `amr: ["pwd", "otp"]`. Les automates (transaction témoin, trafic ML,
  scénarios d'attaque) utilisent des comptes sans double authentification

Le moteur de remédiation rejoue lui-même une **transaction témoin** à travers le WAF après chaque action
(`services/remediation-engine/app/witness.py`, même parcours que `tests/smoke_test.py`). À la main :
`python tests/smoke_test.py http://192.168.137.1:8080`, code de sortie 0 = service métier rétabli.

## Points d'intégration pour les autres piliers

| Besoin | Où | Détail |
|---|---|---|
| Métriques Prometheus | `http://auth-service:8000/metrics`, `http://payment-api:8000/metrics` (réseau `app`) | `http_requests_total`, `http_request_duration_seconds`, `auth_login_attempts_total{result}`, `payment_transfers_total{result}`, `payment_ledger_integrity_ok`, `payment_accounts`, `payment_transfers_stored` |
| Santé réelle | `GET /health` sur chaque service, `GET /healthz` sur nginx | 200 si le processus **et** la base répondent, 503 sinon (moteur de remédiation : 200 tant qu'il sert, dépendances manquantes détaillées sous `status=degraded`) |
| Intégrité des données | `GET http://payment-api:8000/internal/integrity` (réseau interne) / `GET /api/payments/admin/integrity` (admin) | 200 si cohérent, 409 sinon, rapport JSON détaillé |
| Journaux (Loki) | stdout de chaque conteneur, **une ligne JSON par événement** | champs `service`, `msg`, `request_id`, `client_ip`, `user_id`, `status`, `duration_ms`, `event_type` (`auth_failure`, `auth_success`, `transfer`, `integrity_violation`, `dependency_failure` ; `anomaly_detected` du détecteur, `remediation_*` du moteur avec `incident_id`, `waf_remediation_block` du WAF) |
| Corrélation | en-tête `X-Request-ID` | généré par nginx, propagé et journalisé par les API |
| Webhook de remédiation | `POST http://remediation-engine:8000/alerts` (réseau `obs`), appelé par Alertmanager | `Authorization: Bearer` (secret `remediation_webhook_token`, comparaison à temps constant) ; 202 immédiat, traitement en tâche de fond ; 401 sans jeton valide, 503 si le jeton n'est pas configuré, 413 au-delà de 1 Mio |
| État de la remédiation (lecture seule) | `GET http://remediation-engine:8000/api/state`, `/api/incidents`, `/api/incidents/{id}`, `/api/decision-table` (réseaux `obs`, `app`, `dmz`) | incidents ouverts et récents avec chronologie horodatée, IP bloquées, état du pont de restauration, table de décision ; aucune route d'action, sans authentification (le dashboard de supervision la lit par son back-for-front, qui porte le contrôle d'accès) ; schéma : `docs/api/remediation-engine.openapi.json` |

`/metrics` et `/internal/*` sont bloqués par nginx : ils ne sont joignables que depuis les réseaux Docker internes.
Le moteur de remédiation n'est pas derrière nginx et n'a aucun port publié : son webhook et son API d'état ne sont
joignables que depuis ces réseaux internes. Ses métriques (`remediation_*`) sont décrites dans son [README](services/remediation-engine/README.md#sorties).

## Comportements de résilience déjà vérifiés

| Perturbation | Comportement |
|---|---|
| Arrêt de PostgreSQL | API en 503 `database_unavailable` (pas de 500), `/health` en 503, front « Service indisponible » (les deux `/health`, auth et paiements, en échec) ; retour automatique dès que la base revient (connexions testées avant usage) |
| Redémarrage / recréation d'une API | nginx la retrouve via le DNS Docker (`resolver 127.0.0.11`), sans redémarrage de nginx |
| API de paiement coupée, auth disponible | l'utilisateur garde sa session ; le front affiche l'incident puis revient seul à l'état « opérationnel » |
| Base absente au démarrage d'un service | 30 tentatives de connexion espacées de 2 s |
| 40 virements croisés simultanés | aucun interblocage, masse monétaire conservée, registre cohérent |
| API arrêtée (`docker compose stop payment-api`), sans intervention | le moteur de remédiation corrèle `ServiceDown` et `EndToEndProbeFailed` en un seul incident, relance l'API par le proxy Docker, vérifie la reprise (conteneurs, sondes, transaction témoin) puis clôt l'incident à la retombée des alertes ; mesures dans le [README du moteur](services/remediation-engine/README.md#tester) |

## Arborescence

```
ansible/                 playbooks de déploiement et de reprise, pont de restauration de l'hôte (files/, tasks/)
db/init/                 création des bases et rôles (1er démarrage du volume)
docs/                    TODO par domaine, gouvernance (EBIOS RM, PCA/PRA, NIS2/DORA), runbooks (corpus du RAG)
docs/api/                OpenAPI exportée : auth-service, payment-api, remediation-engine (scripts/export_openapi.py)
docs/securite/           revue de durcissement (Trivy, secrets, en-têtes, paranoïa du WAF, conteneurs)
infra/                   configuration Prometheus, Alertmanager, Blackbox, Loki, Alloy, Grafana, WAF
ml/                      jeu de données, entraînement et évaluation du détecteur d'anomalies (dossier technique : ml/README.md)
scripts/init_secrets.py  génération des secrets locaux
scripts/sops_secrets.py  chiffrement des secrets (SOPS + age)
scripts/export_openapi.py  export de la documentation OpenAPI (scripts/service_loader.py : chargement des services hors conteneur)
scripts/remediation_bridge_dev.py  pont de restauration local (développement, sans systemd)
services/anomaly-detector/  service d'inférence ML (variables + modèle partagés avec ml/), expose anomaly_score
services/remediation-engine/  moteur de remédiation (FastAPI) : décision, actions, vérification, API d'état ; modèle durci du proxy Docker (proxy/)
services/supervision-dashboard/  écran de supervision : React + Tailwind (src/) servi par un back-for-front FastAPI en lecture seule (app/)
services/ops-assistant/  assistant RAG des opérateurs (FastAPI + LangChain + Ollama) et son évaluation (eval/)
services/common/         journaux JSON, métriques, pool PostgreSQL, lecture des secrets (partagé)
services/auth-service/   FastAPI — authentification
services/payment-api/    FastAPI — registre et virements
services/frontend/       React + Vite + Tailwind, nginx ; tests Vitest + React Testing Library (src/**/*.test.ts[x])
tests/smoke_test.py      test de bout en bout = transaction témoin (stdlib uniquement)
tests/observability_check.py  vérification de la chaîne d'observation et de défense
tests/unit/              tests unitaires pytest (auth, paiement, paquet commun, doc OpenAPI, détecteur d'anomalies, assistant RAG,
                         moteur de remédiation, blocage WAF, pont de restauration, back-for-front du dashboard), sans la stack
```

### Tests unitaires

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements-dev.txt   # Linux/WSL : .venv/bin/python
.venv/Scripts/python -m pytest                                                         # toute la suite tests/unit/
```

Les tests de l'auth et du paiement démarrent les vraies applications FastAPI (lifespan compris) sur un PostgreSQL 17
jetable, avec les `schema.sql` des services : une base neuve par test. Ce serveur est celui de `RA_TEST_DATABASE_URL`
(utilisé par la CI GitHub Actions), sinon un conteneur `postgres:17-alpine` lancé puis supprimé par pytest ; sans Docker
ni variable, ces tests sont ignorés. Ils couvrent notamment l'idempotence (y compris en concurrence), les règles métier,
la validation des jetons RS256, la détection d'un registre altéré (409) et la réponse 503 quand la base tombe.
Le moteur de remédiation, le blocage WAF et le pont de restauration se testent sans Docker : faux proxy Docker, WAF,
Prometheus, Loki, pont et transaction témoin (table de décision pour chaque alerte des règles, webhook authentifié,
machine d'états, anti-boucle, persistance). La CI (`.github/workflows/unit-tests.yml`, Python 3.12) lance aussi
`python scripts/export_openapi.py --check`.

### Tests du front

```bash
cd services/frontend && npm ci && npm test   # Vitest + React Testing Library sur jsdom, fetch simulé (aucun appel réseau)
npm run build                                # tsc -b vérifie aussi le typage des tests (tsconfig.test.json)
```

Les tests sont à côté du code (`src/**/*.test.ts[x]`, aides communes dans `src/test/`) : règles de saisie Zod (montant
plafonné à 10 000 €, compte `RA` + 10 chiffres, libellé ≤ 60 caractères), client HTTP (clé d'idempotence, jeton porteur,
503 `database_unavailable`, messages d'erreur), formulaire de virement (même clé au renvoi après incident, double envoi
bloqué), connexion et inscription, bandeau d'incident et état des services jusqu'au retour à la normale, sondage `/health`
toutes les 5 s (horloge simulée). La CI (`.github/workflows/front-tests.yml`, Node 24, cache npm) lance `npm ci`,
`npm test` et `npm run build` pour `services/frontend` et `services/supervision-dashboard`.
Le dashboard de supervision a ses propres tests (`cd services/supervision-dashboard && npm ci && npm test`) : bandeau
d'état dans chaque phase, chronologie construite depuis des incidents réels du moteur, sources en panne, compte à rebours
des blocages ; son back-for-front est testé par `tests/unit/test_supervision_bff.py` ([README](services/supervision-dashboard/README.md#développer-et-tester)).

Développement du front avec rechargement à chaud : `cd services/frontend && npm install && npm run dev` (les appels `/api` sont relayés vers la stack sur le port 8080).
