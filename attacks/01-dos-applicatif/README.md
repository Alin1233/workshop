# 01 — Déni de service applicatif (L7) — **scénario principal**

**Objectif** — Provoquer un incident de **disponibilité** observable et reproductible, au niveau applicatif (couche 7), pour déclencher la chaîne détection ML → remédiation automatique → transaction témoin rétablie.

Pourquoi L7 et pas un flood SYN : la remédiation (rate-limit WAF, redémarrage de conteneur) agit sur la couche applicative/conteneur. Un flood SYN frappe la pile réseau de l'hôte, **sous** la couche que la remédiation sait soigner, et peut noyer Prometheus/Grafana/Loki. Le vecteur SYN reste disponible en option (`SYN_FLOOD=1`, débit plafonné) pour un scénario secondaire, jamais pour la démo de reprise.

**Note terrain (vérifiée sur 172.16.147.10, 20/10/2026)** — Le slowloris d'en-têtes (`-H`) est **mitigé** par le tier frontal. Le slow-read (`-X`) sur `/` ne suffit plus : la page ne fait que 464 octets, et 30 s à 8000 connexions n'ont produit **aucune** sonde en échec. Le vecteur qui **aboutit** est le slow-read sur le **bundle JS** (~321 Ko) : première panne à ~9 s, indisponibilité ~37 s sur 45 s d'attaque, reprise ~1 s après l'arrêt. Le script résout donc le bundle tout seul (`/assets/*.js`), avec repli sur `/`.

**Prérequis** — `slowhttptest` (ou `wrk` en repli). Depuis le PC Attaquant. `DURATION ≤ 60` s.

**Commande**
```bash
./dos.sh 172.16.147.10 8080 30                 # slow-read (défaut), bundle JS auto
ENDPOINT=/assets/index-xxxx.js ./dos.sh 172.16.147.10 8080 45   # forcer un asset précis
MODE=slowloris ./dos.sh 172.16.147.10 8080 30     # vecteur en-têtes (mitigé ici)
sudo SYN_FLOOD=1 ./dos.sh 172.16.147.10 8080 30    # secondaire L4, root
```

**Effet attendu** — Montée de la latence p95, 5xx, `probe_success=0`, pics req/s et CPU. Visibles dans Grafana « Santé du service ».

**Détection attendue** — Alertes Prometheus `HighLatencyP95`, `HighErrorRate`, `EndToEndProbeFailed`.

**Remédiation attendue** — Rate-limit WAF / redémarrage ou montée en charge via le moteur de remédiation, **sans intervention humaine**. Preuve de reprise : `tests/smoke_test.py` repasse au vert (voir `../clip-chrono.sh`).

**Piège de mesure** — Une remontée qui coïncide avec l'arrêt de l'attaque n'est **pas** une preuve de remédiation : les buffers se libèrent seuls. Avant de conclure, vérifier côté Hôte que l'alerte a déclenché une action (redémarrage, rate-limit) et que la transaction témoin passe **pendant** la fenêtre de reprise. `/health` renvoie le SPA (200 même si auth est HS) : toujours sonder `/api/auth/health` et `/api/payments/health`.
