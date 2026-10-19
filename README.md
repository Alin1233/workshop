# Resilience-Alpha — SI de paiement fictif

Démonstrateur du Workshop EPSI 2026 « PROJECT RESILIENCE-ALPHA ». Ce dépôt contient pour l'instant le **SI métier** (pilier Développement) :
une plateforme de virements entre comptes fictifs, conteneurisée, observable et conçue pour être remise en service automatiquement.

> Toutes les données sont fictives. Aucune donnée bancaire réelle ne doit être saisie.

## Architecture

```
                PA du groupe (192.168.137.0/24)
                           │  :8080
                 ┌─────────▼─────────┐   réseau "edge"
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
| `frontend` | SPA React/Vite/Tailwind servie par nginx non privilégié, reverse proxy vers les API | **oui**, port 8080 |
| `auth-service` | Inscription, connexion (argon2id), émission de JWT RS256 (15 min), compte admin initial | non |
| `payment-api` | Comptes, virements en partie double, idempotence, contrôle d'intégrité | non |
| `postgres` | `authdb` (rôle `auth_svc`) et `paydb` (rôle `pay_svc`), isolées | non |

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
python scripts/init_secrets.py      # crée ./secrets (mots de passe + paire RSA), jamais versionné
cp .env.example .env                # facultatif
docker compose up -d --build
python tests/smoke_test.py          # 28 vérifications de bout en bout
```

- Application : http://127.0.0.1:8080 (depuis un autre poste : `http://192.168.137.1:8080`)
- Documentation OpenAPI : http://127.0.0.1:8080/api/auth/docs et http://127.0.0.1:8080/api/payments/docs
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
db/init/                 création des bases et rôles (1er démarrage du volume)
scripts/init_secrets.py  génération des secrets locaux
services/common/         journaux JSON, métriques, pool PostgreSQL, lecture des secrets (partagé)
services/auth-service/   FastAPI — authentification
services/payment-api/    FastAPI — registre et virements
services/frontend/       React + Vite + Tailwind, nginx
tests/smoke_test.py      test de bout en bout (stdlib uniquement)
```

Développement du front avec rechargement à chaud : `cd services/frontend && npm install && npm run dev` (les appels `/api` sont relayés vers la stack sur le port 8080).
