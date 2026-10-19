# 01 — Déni de service applicatif (L7) — **scénario principal**

**Objectif** — Provoquer un incident de **disponibilité** observable et reproductible, au niveau applicatif (couche 7), pour déclencher la chaîne détection ML → remédiation automatique → transaction témoin rétablie.

Pourquoi L7 et pas un flood SYN : la remédiation (rate-limit WAF, redémarrage de conteneur) agit sur la couche applicative/conteneur. Un flood SYN frappe la pile réseau de l'hôte, **sous** la couche que la remédiation sait soigner, et peut noyer Prometheus/Grafana/Loki. Le vecteur SYN reste disponible en option (`SYN_FLOOD=1`, débit plafonné) pour un scénario secondaire, jamais pour la démo de reprise.

**Prérequis** — `slowhttptest` (ou `wrk` en repli). Depuis le PC Attaquant. `DURATION ≤ 60` s.

**Commande**
```bash
./dos.sh 172.16.147.10 8080 30
# secondaire, plafonné, root requis :
sudo SYN_FLOOD=1 ./dos.sh 172.16.147.10 8080 30
```

**Effet attendu** — Montée de la latence p95, 5xx, `probe_success=0`, pics req/s et CPU. Visibles dans Grafana « Santé du service ».

**Détection attendue** — Alertes Prometheus `HighLatencyP95`, `HighErrorRate`, `EndToEndProbeFailed`.

**Remédiation attendue** — Rate-limit WAF / redémarrage ou montée en charge via le moteur de remédiation, **sans intervention humaine**. Preuve de reprise : `tests/smoke_test.py` repasse au vert (voir `../clip-chrono.sh`).
