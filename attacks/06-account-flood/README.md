# 06 — Création massive de comptes (registration flood)

**Objectif** — Créer des milliers de comptes en masse pour éprouver l'absence de limitation à l'inscription, et deux effets de bord : la **saturation CPU** de l'auth-service (hachage argon2id coûteux à chaque inscription) et le **minage de crédit de bienvenue** (1 000 € par compte ouvert, ponctionnés sur la trésorerie fictive). Scénario volumétrique applicatif.

**Pas une attaque réseau** — Pur niveau applicatif (HTTP). Exploite l'inscription ouverte sans vérification d'e-mail (cf. V5 du rapport). Lançable depuis le PC Attaquant.

**Prérequis** — `curl`, `xargs`, `jq` (pour `MODE=full`). Service joignable.

⚠️ **Destructif / volumétrique** — Un run 10 000 / 100 le 20/10/2026 a **suspendu l'auth-service ~20 min** (argon2id) et laissé **10 000 comptes fictifs** + **10 000 000 € minés** depuis la trésorerie (en `MODE=full`). Il n'y a **pas de plafond** dans le script : le choix de `COUNT`/`CONCURRENCY` appartient à l'opérateur. À coordonner avec le Blue/infra, avec un `timeout`, et sauvegarde conseillée avant (cf. `04-integrity-violation` et la PRA infra).

**Commande**
```bash
# validation rapide, avec logs par compte
TARGET=172.16.147.10 COUNT=10 CONCURRENCY=2 ./account-flood.sh
# flood complet (10k) — coordonné et borné dans le temps
TARGET=172.16.147.10 COUNT=10000 CONCURRENCY=100 timeout 60 ./account-flood.sh
# comptes seuls, sans ouverture ni crédit
TARGET=172.16.147.10 COUNT=10000 MODE=register timeout 60 ./account-flood.sh
```
Réglages : `COUNT` (défaut 50), `CONCURRENCY` (défaut 5), `MODE=full|register`, `VERBOSE=1` (lignes par compte ; `0` pour un gros run). Arrêt : `Ctrl-C` / `pkill -f account-flood`.

**Logs en direct** — Chaque inscription affiche `register -> code`, puis `login -> code` et `account -> code acct=... balance=...`. Deux fichiers sont écrits dans `attacks/logs/acctflood-*` :
```bash
tail -f attacks/logs/acctflood-*/created.log   # un compte ouvert par ligne
column -s, -t attacks/logs/acctflood-*/accounts.csv | less -S
```

**Effet attendu** — Pic req/s et CPU auth-service, latence en hausse ; éventuels `503`/timeouts si l'inscription n'est pas limitée. Absence de `429` = pas de throttle d'inscription. En `MODE=full`, trésorerie débitée massivement (vérifier l'intégrité du registre sur le Hôte).

**Détection attendue** — Faible en l'état (pas de signal d'inscription dédié). Visible via `HighLatencyP95` / `HighErrorRate` si le service sature. Piste : ajouter un compteur `auth_registrations_total` + une règle d'alerte sur un pic d'inscriptions.

**Remédiation / durcissement** — Limiter l'inscription (rate-limit WAF par IP, CAPTCHA, vérification d'e-mail), plafonner / différer le crédit de bienvenue, surveiller la trésorerie.
