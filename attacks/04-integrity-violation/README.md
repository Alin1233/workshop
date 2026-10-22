# 04 — Altération du registre (injection d'intégrité)

**Objectif** — Corrompre le registre de paiement pour déclencher la **détection d'intégrité** (`LedgerIntegrityBroken`) puis démontrer la **restauration** (reprise par sauvegarde), sans intervention manuelle non tracée. C'est un scénario de **compromission des données** — à ne pas confondre avec le DoS (disponibilité).

**Pas un exploit distant** — L'API est paramétrée (pas d'injection SQL, cf. `03-sqli`) et la base n'est pas exposée : il n'existe pas de chemin depuis le PC Attaquant. Ce scénario s'exécute **sur le PC Hôte** en injection de défaillance contrôlée (chaos engineering, cf. jeudi du sujet), là où la base est joignable via Docker.

**Prérequis** — Exécuté sur le Hôte, stack démarrée, `docker` accessible. Le conteneur `postgres` doit tourner.

**Comment ça déclenche** — Le `payment-api` lance une boucle `integrity_watch` (~15 s) qui appelle `ledger.check_integrity`. Le script déséquilibre le solde d'un compte non-système : `balance_cents` ne correspond plus à la somme de ses `ledger_entries`. Dans les ~15 s : `payment_ledger_integrity_ok=0`, log `event_type=integrity_violation`, alerte `LedgerIntegrityBroken`, et `GET /api/payments/admin/integrity` répond `409`.

**Sécurité** — Destructif, donc : **sauvegarde `pg_dump` d'abord**, enregistrement d'un **delta inverse exact**, et refus d'injecter sans `CONFIRM=1`. Restauration par le delta inverse ou par la sauvegarde complète.

**Commande**
```bash
# sur le Hôte, depuis attacks/04-integrity-violation/
./corrupt-ledger.sh check                 # état d'intégrité courant
CONFIRM=1 ./corrupt-ledger.sh corrupt     # sauvegarde + injection de la violation
# ... l'équipe observe l'alerte sur Grafana/Alertmanager/Loki ...
./corrupt-ledger.sh restore               # réparation (delta inverse)
# ou restauration complète depuis la sauvegarde :
./corrupt-ledger.sh restore attacks/logs/integrity-<ts>/paydb-backup.sql
```

**Détection attendue** — `LedgerIntegrityBroken` (Prometheus sur `payment_ledger_integrity_ok=0`), `LedgerIntegrityViolationLogged` (Loki `integrity_violation`).

**Remédiation attendue** — Restauration des **données** (sauvegarde / correction du registre), **pas** un simple redémarrage de conteneur : un conteneur qui redémarre sur une base incohérente reste incohérent. La preuve de reprise est le retour de `check_integrity` à OK et une nouvelle transaction témoin cohérente.
