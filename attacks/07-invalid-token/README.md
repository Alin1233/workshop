# 07 — Rafale de jetons invalides (détection SOC)

**Objectif** — Provoquer `InvalidTokenFlood` avec des jetons **manifestement invalides** (pas de forge, pas d'`alg=none`), puis vérifier que le service **reste disponible** et que personne ne redémarre un conteneur.

**Prérequis** — `curl`, depuis le PC Attaquant. Service sain.

**Commande**
```bash
TARGET=172.16.147.10 ./invalid-token.sh
```

**Effet attendu** — Environ 40 × `401` sur `/api/payments/accounts/me`, `event_type=auth_failure` côté `payment-api`, `/api/payments/health` toujours `200` avant et après.

**Détection attendue** — `InvalidTokenFlood` (Loki : plus de 20 `auth_failure` en 1 min depuis une IP sur `payment-api`).

**Remédiation attendue** — Alerte SOC conservée, **aucun redémarrage**. C'est un scénario de tentative de compromission ; la disponibilité n'est pas affectée. Redémarrer ici serait la mauvaise réponse.

**Ce que ce scénario n'est pas** — Une attaque de disponibilité, une forge de jeton, ou une recherche de faille JWT. Les jetons envoyés ne prétendent pas être valides.
