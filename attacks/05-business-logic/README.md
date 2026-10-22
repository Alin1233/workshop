# 05 — Abus de logique métier / BOLA

**Objectif** — Se connecter comme un vrai utilisateur et **tenter d'abuser le métier** : gonfler son propre solde, déplacer de l'argent qu'on ne possède pas, lire les données d'un autre utilisateur, atteindre les routes admin, forger un jeton. Répond à la question « l'attaquant peut-il utiliser un compte pour s'enrichir ou accéder à un autre compte ? ».

**Pas une attaque réseau** — Pur niveau applicatif (HTTP sur l'API), aucun flood. Lançable depuis le PC Attaquant. Crée 3 utilisateurs de test (A attaquant, B et C victimes).

**Prérequis** — `curl`, `jq`, `python3`. Service **sain** (si un DoS tourne en parallèle, l'API répond `503 service_unavailable` et le test ne peut pas s'exécuter — le lancer hors fenêtre d'attaque).

**Commande**
```bash
TARGET=172.16.147.10 ./abuse.sh
```

**Batterie d'essais** (chaque ligne notée `BLOCKED` = bon, `>>> POTENTIAL ISSUE` = à investiguer) :
- *Auto-enrichissement* : montant négatif, dépassement du plafond 10 000 €, virement vers soi-même, découvert, **mass-assignment** (`balance_cents`, `from_account_number`, `role` injectés dans le corps) → vérifie que le solde de A n'est jamais gonflé.
- *BOLA / IDOR* : lire un virement B→C en tant que tiers A, lire un id de virement aléatoire, atteindre `/admin/integrity` sans rôle admin, atteindre `/internal/integrity` à travers le WAF.
- *Forge de jeton* : `alg=none` + `role=admin`.
- *Idempotence / double-dépense* : rejeu de la même `Idempotency-Key`, puis réutilisation avec un montant différent.

**Résultat attendu (conception saine)** — Tout `BLOCKED` : le solde ne se mint pas (on ne peut recevoir que d'un virement entrant, pas de champ `from_account`), pas d'accès inter-utilisateur (`/transfers/{id}` vérifie l'appartenance, pas de route `/accounts/{id}`), montants bornés `gt=0,le=1_000_000`, rôle issu d'un JWT RS256 signé, champs superflus ignorés par Pydantic.

**Détection attendue** — Faible : ce sont surtout des `422`/`403`/`404` légitimes. Les tentatives peuvent apparaître dans Loki (`invalid_token` → `event_type=auth_failure` pour la forge de jeton). La vraie valeur est la **preuve d'absence de faille** pour le dossier.
