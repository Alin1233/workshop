# 03 — Sonde d'injection SQL

**Objectif** — Vérifier que le WAF bloque une tentative d'injection SQL sur l'API de paiement et que le blocage est journalisé. Scénario de **tentative de compromission**, en `--level 1 --risk 1` uniquement.

**Prérequis** — `sqlmap`. Depuis le PC Attaquant. Pas de `--risk 3`, pas de `--level 5`, pas de `--os-shell`, pas de dump de tables au-delà de `--dbs`.

**Commande**
```bash
TARGET=172.16.147.10 ./sqli.sh "http://172.16.147.10:8080/api/payments/accounts?id=1"
```

**Effet attendu** — Requêtes malveillantes rejetées en `403` par le WAF (OWASP CRS), journal d'audit ModSecurity (JSON).

**Détection attendue** — `WafAttackBlocked`.

**Remédiation attendue** — Blocage WAF, alerte SIEM. **Pas** de redémarrage de disponibilité : ne pas confondre avec le scénario DoS. Si une vulnérabilité réelle apparaît en labo, la signaler seulement — ne pas exfiltrer de données.
