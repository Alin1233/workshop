# 08 — Contrôle d'intégrité figé (chaos, Hôte only)

**Objectif** — Provoquer `LedgerIntegrityCheckStale` en arrêtant le contrôleur d'intégrité, **sans corrompre les données**. Puis vérifier que le timestamp repart après reprise.

**Différence avec le scénario 04** — En 04, le registre est faux et le contrôleur tourne : la réponse est une **restauration**. Ici, le registre est sain mais plus vérifié : la réponse est de **relancer le contrôleur**. Deux alertes, deux actions.

**Prérequis** — Sur le PC Hôte, stack démarrée, `docker` accessible. `payment-api` tourne.

**Commande**
```bash
./stale-watcher.sh check
CONFIRM=1 ./stale-watcher.sh inject
```

**Effet attendu** — `payment-api` est en pause pendant `PAUSE_SECONDS` (défaut 100 s) : l'API est indisponible pendant ce temps. `payment_ledger_integrity_last_check_timestamp` cesse d'avancer. L'alerte `LedgerIntegrityCheckStale` (`time() - timestamp > 60`, `for: 30s`) se déclenche. Au unpause, le timestamp repart et l'alerte se résout.

**Détection attendue** — `LedgerIntegrityCheckStale` (Prometheus). L'API en pause peut aussi déclencher `ServiceDown` / `EndToEndProbeFailed` : c'est un effet de bord assumé, à expliquer dans la démo.

**Remédiation attendue** — Redémarrer `payment-api` (le contrôleur repart). **Pas** de restauration de base : les données n'ont pas bougé.

**Sécurité** — `trap` de unpause sur sortie. Refus sans `CONFIRM=1`. Garder la pause sous 120 s.
