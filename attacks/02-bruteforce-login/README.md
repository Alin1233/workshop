# 02 — Force brute sur la connexion

**Objectif** — Enchaîner des tentatives de connexion échouées sur `POST /api/auth/login` pour déclencher les signaux d'authentification et la réponse WAF/SIEM. Scénario de **tentative de compromission** — la disponibilité n'est pas affectée.

**Prérequis** — `curl` (mode `json`, défaut) ou `hydra` (mode `form`). Depuis le PC Attaquant. L'API attend un corps JSON `{email, password}` (argon2id), d'où le mode `json` par défaut : `hydra http-post-form` envoie de l'urlencodé et ne conviendrait qu'à un endpoint form.

**Commande**
```bash
TARGET=172.16.147.10 ./bruteforce.sh
# variantes :
TARGET=172.16.147.10 USERNAME=admin@resilience.local ./bruteforce.sh
TARGET=172.16.147.10 MODE=form ./bruteforce.sh
```

**Effet attendu** — Rafale de `401` sur `/api/auth/login`, `event_type=auth_failure`, `auth_login_attempts_total{result="failure"}` en hausse.

**Détection attendue** — `AuthBruteForce` (Loki), `LoginFailureSpike` (Prometheus).

**Remédiation attendue** — Blocage de l'IP / rate-limit WAF, alerte SIEM. Pas de redémarrage de service (disponibilité ≠ compromission).
