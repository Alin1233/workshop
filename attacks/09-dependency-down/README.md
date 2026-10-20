# 09 — Panne de dépendance (chaos, Hôte only)

**Objectif** — Provoquer `DependencyFailures` en rendant PostgreSQL indisponible quelques secondes, puis vérifier que le service répond à nouveau et que les données sont intactes.

**Prérequis** — Sur le PC Hôte, stack démarrée, `docker` accessible.

**Commande**
```bash
./dependency-down.sh check
CONFIRM=1 ./dependency-down.sh inject
```

**Effet attendu** — `postgres` est en pause pendant `PAUSE_SECONDS` (défaut 25 s). Les services renvoient `503` (`code=database_unavailable`, `event_type=dependency_failure`). Au unpause, `/api/payments/health` revient à `200` avec `checks.database=true`.

**Détection attendue** — `DependencyFailures` (Loki : plus de 3 `dependency_failure` en 1 min). `ServiceDown` peut aussi se déclencher selon le timing.

**Remédiation attendue** — Reprise de la dépendance (unpause / redémarrage de `postgres`), **pas** de restauration : aucune donnée n'est corrompue. Une transaction témoin après reprise prouve l'usage réel.

**Sécurité** — `trap` de unpause, refus au-delà de 40 s (le healthcheck Docker marquerait `postgres` unhealthy), refus sans `CONFIRM=1`.
