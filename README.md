# Resilience-Alpha — SI de paiement fictif

Démonstrateur du Workshop EPSI 2026 « PROJECT RESILIENCE-ALPHA » : une plateforme de virements entre comptes fictifs,
protégée par un WAF, observée par Prometheus / Loki / Grafana, avec une fonction SOC et une chaîne d'alertes prête à
alimenter le moteur de remédiation.

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
| `auth-service` | Inscription, connexion (argon2id), émission de JWT RS256 (15 min), compte admin initial | non |
| `payment-api` | Comptes, virements en partie double, idempotence, contrôle d'intégrité | non |
| `postgres` | `authdb` (rôle `auth_svc`) et `paydb` (rôle `pay_svc`), isolées | non |

### Observabilité et SOC (pilier Infrastructure / Sécurité)

```
 conteneurs ──stdout JSON──▶ fichiers json-file ──▶ alloy ──▶ loki ──règles SOC──┐
 API /metrics, sondes blackbox (à travers le WAF) ──▶ prometheus ──règles──────────┼──▶ alertmanager ──▶ remediation-engine (à développer)
                                       grafana ◀── prometheus, loki, alertmanager ┘
 anomaly-detector (ML) ◀── prometheus + loki, toutes les 10 s ; anomaly_score{service} ──▶ prometheus (règle AnomalyDetected)
```

| Service | Rôle | Accès (PC Hôte uniquement) |
|---|---|---|
| `grafana` | tableaux « Santé du service » et « SOC » provisionnés | http://127.0.0.1:3000 (admin / `secrets/grafana_admin_password`) |
| `prometheus` | métriques, sondes de bout en bout, 12 règles (`infra/prometheus/rules` : service, intégrité, détection ML `AnomalyDetected`, PC Hôte, sauvegardes) | http://127.0.0.1:9090 (admin / `secrets/prometheus_password`) |
| `alertmanager` | regroupe les alertes et les envoie au moteur de remédiation | http://127.0.0.1:9093 (admin / `secrets/alertmanager_password`) |
| `loki` | journaux centralisés + 5 règles SOC LogQL (`infra/loki/rules/fake/soc.yml`) | via `loki-proxy` |
| `loki-proxy` | nginx : authentification basique devant Loki, qui n'en a pas (les accès internes d'Alloy et Grafana restent directs) | http://127.0.0.1:3100 (admin / `secrets/loki_password`) |
| `alloy` | collecte les journaux en lisant les fichiers Docker (aucun accès au socket) | — |
| `blackbox` | sonde le parcours client WAF → nginx → API → base | — |
| `node-exporter` | ressources du PC Hôte (CPU, mémoire, disque) et état des sauvegardes PostgreSQL, sans accès au socket Docker | — |
| `ollama` | LLM local de l'assistant RAG (CPU), profil `ai` (`--profile ai` ou `COMPOSE_PROFILES=ai`) ; sinon PC de délestage IA via `OLLAMA_BASE_URL` | non publié (réseau `ai`) |
| `anomaly-detector` | détection d'anomalies ML (z-score robuste calibré, `ml/`) : `anomaly_score{service}` 0..1 pour auth-service, payment-api, frontend | — (scrapé par Prometheus, réseau `obs`) |
| `ops-assistant` | assistant RAG des opérateurs (Ollama + LangChain) : procédures et architecture, réponses sourcées, aucune action ([README](services/ops-assistant/README.md)) | http://127.0.0.1:8090 (tunnel SSH `-L 8090:127.0.0.1:8090`) |

Les interfaces de gestion ne sont publiées que sur `127.0.0.1` (`MGMT_BIND`), conformément au §4 du sujet.

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
  version exportée pour le rendu dans `docs/api/` (`python scripts/export_openapi.py`, `--check` pour vérifier qu'elle est à jour)
- Admin : `admin@resilience.local`, mot de passe dans `secrets/admin_password`

`python tests/smoke_test.py http://192.168.137.1:8080` sert de **transaction témoin** après une remédiation : code de sortie 0 = service métier rétabli.

## Points d'intégration pour les autres piliers

| Besoin | Où | Détail |
|---|---|---|
| Métriques Prometheus | `http://auth-service:8000/metrics`, `http://payment-api:8000/metrics` (réseau `app`) | `http_requests_total`, `http_request_duration_seconds`, `auth_login_attempts_total{result}`, `payment_transfers_total{result}`, `payment_ledger_integrity_ok`, `payment_accounts`, `payment_transfers_stored` |
| Santé réelle | `GET /health` sur chaque service, `GET /healthz` sur nginx | 200 si le processus **et** la base répondent, 503 sinon |
| Intégrité des données | `GET http://payment-api:8000/internal/integrity` (réseau interne) / `GET /api/payments/admin/integrity` (admin) | 200 si cohérent, 409 sinon, rapport JSON détaillé |
| Journaux (Loki) | stdout de chaque conteneur, **une ligne JSON par événement** | champs `service`, `msg`, `request_id`, `client_ip`, `user_id`, `status`, `duration_ms`, `event_type` (`auth_failure`, `auth_success`, `transfer`, `integrity_violation`, `dependency_failure`) |
| Corrélation | en-tête `X-Request-ID` | généré par nginx, propagé et journalisé par les API |

`/metrics` et `/internal/*` sont bloqués par nginx : ils ne sont joignables que depuis les réseaux Docker internes.

## Comportements de résilience déjà vérifiés

| Perturbation | Comportement |
|---|---|
| Arrêt de PostgreSQL | API en 503 `database_unavailable` (pas de 500), `/health` en 503, front « Service dégradé » ; retour automatique dès que la base revient (connexions testées avant usage) |
| Redémarrage / recréation d'une API | nginx la retrouve via le DNS Docker (`resolver 127.0.0.11`), sans redémarrage de nginx |
| API de paiement coupée, auth disponible | l'utilisateur garde sa session ; le front affiche l'incident puis revient seul à l'état « opérationnel » |
| Base absente au démarrage d'un service | 30 tentatives de connexion espacées de 2 s |
| 40 virements croisés simultanés | aucun interblocage, masse monétaire conservée, registre cohérent |

## Arborescence

```
ansible/                 playbooks de déploiement et de reprise
db/init/                 création des bases et rôles (1er démarrage du volume)
docs/                    TODO par domaine, gouvernance (EBIOS RM, PCA/PRA, NIS2/DORA), runbooks (corpus du RAG)
infra/                   configuration Prometheus, Alertmanager, Blackbox, Loki, Alloy, Grafana, WAF
ml/                      jeu de données, entraînement et évaluation du détecteur d'anomalies (dossier technique : ml/README.md)
scripts/init_secrets.py  génération des secrets locaux
scripts/sops_secrets.py  chiffrement des secrets (SOPS + age)
services/anomaly-detector/  service d'inférence ML (variables + modèle partagés avec ml/), expose anomaly_score
services/remediation-engine/, supervision-dashboard/   contrats d'intégration (à développer)
services/ops-assistant/  assistant RAG des opérateurs (FastAPI + LangChain + Ollama) et son évaluation (eval/)
services/common/         journaux JSON, métriques, pool PostgreSQL, lecture des secrets (partagé)
services/auth-service/   FastAPI — authentification
services/payment-api/    FastAPI — registre et virements
services/frontend/       React + Vite + Tailwind, nginx
tests/smoke_test.py      test de bout en bout = transaction témoin (stdlib uniquement)
tests/observability_check.py  vérification de la chaîne d'observation et de défense
tests/unit/              tests unitaires pytest (auth, paiement, paquet commun, doc OpenAPI, détecteur d'anomalies, assistant RAG), sans la stack
```

### Tests unitaires

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements-dev.txt   # Linux/WSL : .venv/bin/python
.venv/Scripts/python -m pytest                                                         # 87 tests, ~20 s
```

Les tests de l'auth et du paiement démarrent les vraies applications FastAPI (lifespan compris) sur un PostgreSQL 17
jetable, avec les `schema.sql` des services : une base neuve par test. Ce serveur est celui de `RA_TEST_DATABASE_URL`
(utilisé par la CI GitHub Actions), sinon un conteneur `postgres:17-alpine` lancé puis supprimé par pytest ; sans Docker
ni variable, ces tests sont ignorés. Ils couvrent notamment l'idempotence (y compris en concurrence), les règles métier,
la validation des jetons RS256, la détection d'un registre altéré (409) et la réponse 503 quand la base tombe.

Développement du front avec rechargement à chaud : `cd services/frontend && npm install && npm run dev` (les appels `/api` sont relayés vers la stack sur le port 8080).
