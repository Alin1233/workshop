# Revue de durcissement — 20/10/2026

Revue de sécurité de la stack Resilience-Alpha avant le gel du code (jeudi 22/10, 17 h) et la démonstration au jury
(vendredi 23/10) : vulnérabilités des images (Trivy), mots de passe et secrets, authentification des interfaces de
gestion, en-têtes HTTP, niveau de paranoïa du WAF, durcissement des conteneurs.

**Règle suivie : la stabilité de la démonstration passe avant le « zéro CVE ».** Aucune montée de version majeure,
aucun changement de framework ; chaque correction a été suivie d'une reconstruction de la stack et de toute la batterie
de tests (§ 8). Ce qui n'est pas corrigé figure au § 9 avec sa justification.

Mesures prises sur la pile locale (Arch Linux, Docker 29.9.1, Compose 5.6.0, 16 CPU, 29 Go ; WAF publié sur
`127.0.0.1:8088`). La VM PC Hôte (Debian 13, 6 vCPU, 16 Go) n'a pas été modifiée : les changements y arrivent au prochain
`ansible-playbook ansible/deploy.yml`.

## En bref

| Domaine | Avant | Après |
|---|---|---|
| Trivy, images (HIGH + CRITICAL, 19 images) | 1 CRITICAL + 538 HIGH, dont 275 avec correctif publié | 1 CRITICAL + 450 HIGH, dont 187 avec correctif publié ; tous les restants justifiés (§ 9) |
| Images nginx (frontal, loki-proxy) | `nginx-unprivileged:1.29-alpine`, figée en mai (nginx 1.29.8, Alpine 3.23) : 44 HIGH chacune, plus les CVE de nginx lui-même (dont deux débordements de tas du module rewrite, utilisé par le frontal) | `1.30-alpine` (nginx 1.30.6, Alpine 3.24) : 0 |
| `trivy config` (Dockerfiles) / `trivy fs` secrets / dépendances npm | 1 HIGH (DS-0002) / 0 secret suivi par git / 0 | 0 / 0 / 0 |
| En-têtes du front et des API | 3 en-têtes (nosniff, X-Frame-Options, Referrer-Policy), CORS `*` ajouté par le WAF | + CSP stricte, Permissions-Policy, COOP/CORP, `Cache-Control: no-store` sur `/api/`, plus de CORS ; React vérifié sous CSP dans Chromium |
| WAF | PL1 ; 3 points sur 5 consommés par la règle 920350 sur **chaque** requête légitime ; jetons JWT recopiés dans Loki | **PL1 conservé** (PL2 bloque des virements ordinaires) ; 920350 retirée ; journal d'audit sans en-têtes de requête |
| Règle SOC `WafAttackBlocked` | comptait aussi les 403 renvoyés par les API : 6 accès d'un non-admin à `/admin/integrity` en 2 min suffisaient à faire bloquer l'IP (au labo : tout le NAT) | ne compte que les requêtes **interrompues par le WAF** (`is_interrupted`), comme le détecteur, le moteur et Grafana ; prouvé en direct (§ 7.1) |
| Panneaux SOC du frontal | en erreur `JSONParserErr` 15 min après chaque redémarrage du frontal | `| __error__=""`, données affichées juste après un redémarrage (§ 7.2) |
| Conteneurs | postgres en root avec toutes les capabilities, blackbox en root, ollama avec toutes les capabilities, pas de limite mémoire, 9 services sans healthcheck | postgres en uid 70 sans capability, blackbox en nobody, ollama sans capability, limites mémoire mesurées sur les 19 services, healthchecks ajoutés à 4 services, `kill` du proxy Docker limité à SIGHUP |

## 1. Méthode

| Volet | Outil, commande | Preuve |
|---|---|---|
| Vulnérabilités des images | `aquasec/trivy:0.75.0` (image officielle, `sha256:af6acf9a6b85…`), base du 20/10 07:17 UTC, socket Docker monté en lecture seule, cache dans le volume `trivy-cache` ; `trivy image --scanners vuln --severity HIGH,CRITICAL` sur les 19 images de `docker compose --profile ai config --images` | JSON par image, avant et après |
| Configuration, secrets, dépendances | `trivy config` (Dockerfiles ; Trivy n'analyse pas les fichiers Compose), `trivy fs --scanners secret` et `trivy fs --scanners vuln --include-dev-deps` sur une copie des seuls fichiers suivis par git, `npm audit` | idem |
| En-têtes HTTP | `curl -D -` à travers le WAF (8088) et sur chaque port de gestion de 127.0.0.1 | § 4 |
| Applications sous CSP | inspection du build Vite (aucun script ni style en ligne, aucune URI `data:` dans les CSS) puis parcours réel dans Chromium (Playwright) : inscription, connexion, faute de frappe, virements, historique, copie du numéro de compte, déconnexion ; Swagger UI et ReDoc ; dashboard de supervision ; assistant RAG ; Grafana | écouteur `securitypolicyviolation` + console : 0 violation |
| Niveau de paranoïa | WAF en `DetectionOnly`, toutes les règles jusqu'au PL4 évaluées, verdict recalculé par niveau depuis le journal d'audit (`scripts/scenarios/waf_paranoia.py`) ; trafic légitime puis attaques | § 5 |
| Conteneurs | `docker inspect`, `docker top`, `/proc/1/status`, pics `memory.peak` des cgroups, `memory.events` (OOM) | § 6 |
| Non-régression après chaque lot | `docker compose up -d --build --wait`, pytest, Vitest + build des deux fronts, `smoke_test.py`, `observability_check.py`, `export_openapi.py --check` | § 8 |

## 2. Trivy : résultats par image

CRITICAL / HIGH, entre parenthèses ceux pour lesquels un paquet corrigé existe.

| Image | Avant | Après | Commentaire |
|---|---|---|---|
| `resilience-alpha/frontend` | 0 / 44 (44) | **0 / 0** | étape finale passée en `nginx-unprivileged:1.30-alpine` |
| `nginxinc/nginx-unprivileged` (loki-proxy) | 0 / 44 (44) | **0 / 0** | `1.29-alpine` → `1.30-alpine` |
| `resilience-alpha/auth-service`, `payment-api`, `anomaly-detector`, `ops-assistant`, `remediation-engine`, `supervision-dashboard` | 0 / 44 (0) chacune | 0 / 44 (0) chacune | tous dans les paquets Debian 13 de `python:3.12-slim` (util-linux, ncurses, systemd, acl, perl-base) : 43 « affected », 1 « fix_deferred », **aucun correctif publié par Debian** ; dépendances Python : **0** |
| `postgres:17-alpine` | 1 / 24 (25) | 1 / 24 (25) | tous dans `gosu` (Go 1.24.6), aucun dans PostgreSQL ni Alpine ; `gosu` n'est plus exécuté (§ 6) |
| `grafana/grafana:13.2.4` | 0 / 61 (61) | 0 / 61 (61) | bibliothèques Go (kin-openapi, x/net, grpc, stdlib) ; 13.2.4 est la dernière 13.2 |
| `ollama/ollama` | 0 / 48 (48) | 0 / 48 (48) | `latest` figé en `0.40.6` (même empreinte) ; binaire construit avec Go 1.26.0 |
| `prom/node-exporter:v1.12.1` | 0 / 14 (14) | 0 / 14 (14) | Go ; dernière version publiée |
| `prom/alertmanager:v0.34.1` | 0 / 10 (10) | 0 / 10 (10) | Go ; dernière version publiée |
| `prom/prometheus:v3.15.0` | 0 / 8 (8) | 0 / 8 (8) | Go ; dernière version publiée |
| `grafana/alloy:v1.20.1` | 0 / 6 (6) | 0 / 6 (6) | Go + OpenSSL d'Ubuntu ; la v1.21.0 (mineure) date du 19/10 |
| `tecnativa/docker-socket-proxy:v0.5.0` | 0 / 6 (6) | 0 / 6 (6) | OpenSSL et PCRE2 d'Alpine ; dernière version publiée |
| `grafana/loki:3.7.8` | 0 / 4 (4) | 0 / 4 (4) | Go ; dernière 3.7 |
| `prom/blackbox-exporter:v0.29.0` | 0 / 4 (4) | 0 / 4 (4) | Go ; dernière version publiée |
| `owasp/modsecurity-crs:4.25-nginx-alpine-lts` | 0 / 1 (1) | 0 / 1 (1) | `libx11` (inutilisée) ; image reconstruite le 18/10, nginx 1.30.6 |
| **Total** | **1 / 538 (275)** | **1 / 450 (187)** | |

Les CVE Go des images tierces relèvent presque toutes d'un déni de service (HTTP/2, TLS, x509, analyseurs) : leur
correctif exige une nouvelle version de l'éditeur, et aucune n'est encore publiée pour les versions en place, sauf des
mineures toutes récentes (Alloy 1.21.0) écartées avant la démonstration.

Configuration et secrets : `trivy config` ne relevait qu'un DS-0002 (« image user should not be root ») sur le
Dockerfile du frontal, faux positif (l'image `nginx-unprivileged` tourne déjà en uid 101) rendu explicite par
`USER 101` : **0** après. `trivy fs --scanners secret` : **0** dans les fichiers suivis par git ; dans l'arbre de travail,
seule la clé `secrets/jwt_private.pem`, ignorée par git (attendu). Dépendances npm (dev comprises) : **0**
(`npm audit` : 0 aussi). Trivy n'analyse pas les `requirements.txt` à bornes (`>=`) : les paquets Python sont vérifiés
dans les images (31 paquets pour auth-service, aucun HIGH ni CRITICAL).

## 3. Corrections

| Fichier | Changement | Pourquoi |
|---|---|---|
| `services/frontend/Dockerfile`, `docker-compose.yml` (loki-proxy) | `nginxinc/nginx-unprivileged:1.29-alpine` → `1.30-alpine`, `USER 101` explicite | le tag 1.29 n'est plus reconstruit depuis le 11/05 ; la 1.30.0 est la 1.29.8 figée en branche stable (aucun changement), les 1.30.1 à 1.30.6 n'apportent que des correctifs, dont CVE-2026-42945 et CVE-2026-9256 (débordement de tas du module rewrite, que le frontal utilise) et CVE-2026-42533 (`map` à expressions régulières) ; 44 → 0 HIGH par image |
| `docker-compose.yml` (ollama) | `ollama/ollama:latest` → `0.40.6` | même empreinte : aucun changement aujourd'hui, mais un `pull` sur la VM ne change plus le moteur du LLM avant la démo |
| `services/frontend/nginx.conf` | CSP, Permissions-Policy, COOP, CORP, `Cache-Control: no-store` sur `/api/` | § 4 |
| `services/frontend/src/lib/validation.ts` | `z.config({ jitless: true })` | sous CSP sans `unsafe-eval`, la sonde `Function("")` de Zod 4, bien qu'interceptée, levait une violation CSP à chaque chargement (mesurée dans Chromium) ; option prévue par Zod pour ce cas |
| `docker-compose.yml` (waf) | variables `CORS_HEADER_*` vides ; `MODSEC_AUDIT_LOG_PARTS` `ABFHZ` → `AFHZ` | § 4 et § 5 |
| `infra/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` | retrait de la règle 920350 | § 5 |
| `services/ops-assistant/Dockerfile`, `services/ops-assistant/app/main.py`, `services/supervision-dashboard/app/main.py` | `--no-server-header` (assistant), `Permissions-Policy` (les deux) ; une assertion de plus dans chaque test unitaire | § 4 |
| `docker-compose.yml` (grafana) | `GF_SECURITY_CONTENT_SECURITY_POLICY`, `GF_SECURITY_COOKIE_SAMESITE=strict`, `GF_SECURITY_DISABLE_GRAVATAR`, `GF_SNAPSHOTS_EXTERNAL_ENABLED=false`, `GF_PUBLIC_DASHBOARDS_ENABLED=false`, `GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false`, `GF_ANALYTICS_FEEDBACK_LINKS_ENABLED=false` | § 3.2 |
| `docker-compose.yml` (postgres, blackbox, ollama, healthchecks, `mem_limit`) | § 6 | |
| `services/remediation-engine/proxy/haproxy.cfg.template` | `POST /containers/{id}/kill` refusé sauf `signal=HUP` | § 6 |
| `scripts/init_secrets.py` | répertoire `secrets/` en 0700 | § 3.1 |
| `tests/smoke_test.py` | mot de passe des comptes jetables tiré à chaque exécution (`secrets.token_urlsafe`) au lieu d'un littéral | plus aucun mot de passe écrit dans le test de bout en bout |
| `scripts/scenarios/waf_paranoia.py` (nouveau) | outil de mesure du § 5 (bibliothèque standard) | rejouer la mesure |
| `infra/loki/rules/fake/soc.yml`, `services/anomaly-detector/app/features.py`, `services/remediation-engine/app/decisions.py`, `infra/grafana/generate_dashboards.py` (+ `dashboards/soc.json` régénéré) | `WafAttackBlocked`, `waf_blocks_per_min`, l'attribution d'IP du moteur et les deux panneaux de blocage WAF ne comptent que `transaction.is_interrupted="true"` ; `| __error__=""` sur ces requêtes et sur les deux panneaux du frontal | § 7 |
| `tests/unit/test_waf_block.py` | test : les quatre sources et le tableau SOC régénéré filtrent les requêtes interrompues | garde-fou |
| `services/remediation-engine/docs/waf-blocking.md`, `ml/README.md` | description de la règle et de la variable mise à jour | |

### 3.1 Mots de passe et secrets

| Point | Constat | Décision |
|---|---|---|
| Générateur | `secrets.token_urlsafe(24)` (32 caractères, 192 bits) pour les 10 mots de passe, `token_urlsafe(32)` (256 bits) pour le jeton du webhook, RSA 2048 pour les JWT RS256 | conforme |
| Mots de passe des comptes clients | argon2id, paramètres par défaut d'argon2-cffi (RFC 9106 : t=3, m=64 Mio, p=4) | conforme ; coût mémoire mesuré au § 6 |
| Coût bcrypt (Prometheus, Alertmanager, loki-proxy) | 10 | **conservé** : les mots de passe sont aléatoires (192 bits), le coût ne protège que des mots de passe faibles ; nginx recalcule le bcrypt à chaque requête de loki-proxy (coût 12 = 4 fois plus de CPU par requête) ; 10 est le minimum recommandé par l'OWASP |
| Droits des fichiers | `secrets/` en 0755 avec des fichiers en 0644 : lisibles par tout compte de l'hôte | répertoire passé en **0700** par `init_secrets.py` (comme `shared/secrets` sur la VM, `deploy.yml`) ; les fichiers restent en 0644, lisibles par les utilisateurs des conteneurs, qui les reçoivent montés un par un dans `/run/secrets` ; vérifié en recréant tous les conteneurs |
| Mots de passe par défaut | aucun : `POSTGRES_PASSWORD_FILE`, `DB_PASSWORD_FILE`, `JWT_*_KEY_FILE`, `ADMIN_PASSWORD_FILE`, `GF_SECURITY_ADMIN_PASSWORD__FILE`, `*_PASSWORD_FILE`, `WEBHOOK_TOKEN_FILE`, sources Grafana en `$__file{…}` ; aucune valeur de mot de passe ni de jeton dans les variables d'environnement de `docker-compose.yml` | conforme |
| Répertoires ignorés par git | `secrets/*`, `.env`, `.remediation-bridge/`, `.dev-backups/`, `.venv/`, `node_modules/`, `dist/` ; Trivy : 0 secret dans les fichiers suivis | conforme |
| Littéraux dans les tests | seuls des mots de passe de comptes jetables (PostgreSQL de test, comptes des tests unitaires) ; celui du test de bout en bout est désormais tiré au hasard | acceptable |
| Affichage | `init_secrets.py` affiche les mots de passe en fin d'exécution (historique du terminal) ; `deploy.yml` le lance en `no_log` | risque résiduel accepté (opérateur seul) |
| Secrets dans les journaux | le journal d'audit du WAF recopiait l'en-tête `Authorization: Bearer <JWT>` de chaque requête journalisée jusque dans Loki (jetons valides 15 min, rejouables par quiconque lit Loki ou Grafana) | **corrigé** (§ 5.4) |

### 3.2 Interfaces de gestion

Toutes sont publiées sur `127.0.0.1` uniquement ; seul le WAF l'est sur `0.0.0.0`.

| Interface | Authentification vérifiée (sans identifiant → ) | Remarques |
|---|---|---|
| Grafana `:3000` | formulaire, compte admin (`__FILE`) ; inscription et accès anonyme désactivés ; protection contre la force brute active (par défaut) | ajoutés : CSP de Grafana (modèle à nonce), cookie `SameSite=Strict`, ni Gravatar, ni instantanés publiés sur raintank.io, ni tableaux publics, ni installation de plugin, ni liens de retour ; `/api/health` reste public et donne la version (13.2.4) : par conception |
| Prometheus `:9090` | basique bcrypt (`--web.config.file`) → 401, `/metrics` et `/-/healthy` compris | |
| Alertmanager `:9093` | basique bcrypt → 401 | le compte permet de poser des silences : d'où son absence de l'assistant RAG |
| loki-proxy `:3100` | basique (htpasswd bcrypt) → 401 | seule exception ajoutée : `/healthz` (« ok », ne joint pas Loki) pour le healthcheck ; Loki lui-même n'a pas d'authentification et reste sur le réseau interne `obs` |
| assistant RAG `:8090` | basique, comparaison à temps constant → 401 | `/health` public, réduit à l'état |
| supervision `:8091` | basique, temps constant → 401 ; GET seulement | `/health` public |
| API d'état du moteur | aucune, mais aucun port publié (réseaux internes `obs`, `app`, `dmz`), lecture seule ; webhook protégé par jeton porteur | |
| docker-socket-proxy | aucune ; réseau interne `docker-api` partagé avec le seul moteur ; liste blanche (§ 6) | |

## 4. En-têtes HTTP

Relevés par `curl -D -`. Depuis la reconnaissance faciale, le WAF publie aussi l'HTTPS (8443, certificat de l'autorité
locale `secrets/waf_ca.crt`) : la caméra n'est ouverte par le navigateur qu'en contexte sécurisé. **HSTS reste exclu** :
le 8080 sert toujours en HTTP (sondes, tests, postes sans l'autorité), et HSTS ferait passer `http://<hôte>:8080` en
`https://<hôte>:8080`, qui échoue. `Permissions-Policy` autorise désormais `camera=(self)` (origine de la plateforme
seulement), et la CSP `'wasm-unsafe-eval'` : le guidage de la caméra compile un détecteur de visage WebAssembly
(MediaPipe), servi par le front comme son modèle ; `eval` et les scripts en ligne restent interdits. Cookie `Secure` de Grafana : sans objet (interface en HTTP sur 127.0.0.1).

| Réponse | Avant | Après |
|---|---|---|
| SPA (`/`), via le WAF | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Access-Control-Allow-Headers: *` ; pas de `Server` | + `Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `Permissions-Policy` (accéléromètre, caméra, géolocalisation, gyroscope, magnétomètre, micro, paiement, USB : interdits), `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin` ; plus de CORS |
| API (`/api/auth/*`, `/api/payments/*`) | idem SPA | idem + `Cache-Control: no-store` (jetons, soldes, historique) |
| Docs OpenAPI (`/api/*/docs`, `/redoc`) | idem SPA | CSP dédiée : Swagger UI et ReDoc chargent leurs scripts depuis `cdn.jsdelivr.net` avec un script en ligne (`'unsafe-inline'` limité à ces quatre URL), polices Google, logos `fastapi.tiangolo.com` et `cdn.redoc.ly`, workers `blob:` |
| Page 403 du WAF | `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods`, `Access-Control-Max-Age`, `Access-Control-Allow-Headers: *` | plus aucun en-tête CORS (variables `CORS_HEADER_*` vides) ; page HTML statique sans en-tête de sécurité (risque résiduel faible) |
| Grafana | nosniff, `X-Frame-Options: deny`, `X-Xss-Protection` | + CSP à nonce (modèle de Grafana) |
| Prometheus / Alertmanager | nosniff (Prometheus) / `Cache-Control` | inchangé (§ 9) |
| loki-proxy | `Server: nginx` (sans version, `server_tokens off`) | inchangé, nginx 1.30.6 |
| assistant RAG | nosniff, XFO, Referrer-Policy, CSP stricte, **`server: uvicorn`** | + Permissions-Policy, plus d'en-tête `server` |
| supervision | nosniff, XFO, Referrer-Policy, CSP stricte, `no-store` | + Permissions-Policy |

Divulgation de version : aucune sur le parcours client (`SERVER_HEADER` vide au WAF, `server_tokens off` au frontal,
en-tête `Server` d'uvicorn masqué par nginx) ; `server: uvicorn` retiré de l'assistant ; la page 403 du WAF dit « nginx »
sans version.

**Les applications fonctionnent sous la CSP** (Chromium headless, écouteur `securitypolicyviolation`) : front de paiement
(2 inscriptions avec noms accentués et apostrophes, faute de frappe au mot de passe, 8 virements, historique, copie du
numéro de compte, sondage `/health`, déconnexion), Swagger UI et ReDoc des deux API, dashboard de supervision, assistant
RAG, Grafana (« Santé du service » : 62 panneaux, « SOC » : 20) : **0 violation CSP, 0 erreur JavaScript**. La seule
violation rencontrée (sonde `eval` de Zod) est corrigée par `jitless` ; la seule autre, l'image du logo ReDoc, par la
CSP des docs.

## 5. Niveau de paranoïa du WAF

### 5.1 Méthode

Un faux positif du WAF est dangereux ici : six requêtes bloquées en 2 minutes depuis une même IP déclenchent
`WafAttackBlocked`, et le moteur bloque alors l'IP ; au labo, **tous les postes partagent l'IP NAT 172.16.255.252**, donc
un faux positif peut couper le jury. On mesure donc sans rien bloquer : WAF recréé en `MODSEC_RULE_ENGINE=DetectionOnly`
avec `PARANOIA`, `BLOCKING_PARANOIA` et `DETECTION_PARANOIA` à 4 (surcharge Compose temporaire, § 10), puis verdict de
chaque requête recalculé à chaque niveau depuis son journal d'audit (somme des points des règles de niveau ≤ N, seuil 5).
Le mode détection donne un majorant : une requête bloquée n'arrête pas la suite du parcours, toutes les étapes sont donc
évaluées.

### 5.2 Trafic légitime : faux positifs

Requêtes vues par le frontal (sondes blackbox comprises, elles tournent en continu) ; 1 735 requêtes en tout.

| Trafic | Requêtes | Bloquées PL1 | PL2 | PL3 | PL4 |
|---|---|---|---|---|---|
| `tests/smoke_test.py` (28 vérifications) | 69 | 0 | 0 | 69 | 69 |
| transaction témoin du moteur (depuis la dmz) | 9 | 0 | 0 | 3 | 5 |
| front réel, usage courant (2 inscriptions « Éloïse D'Arcy-Lefèvre », « Jean-Noël O'Connor », mots de passe à caractères spéciaux, faute de frappe, 4 virements, historique, copie, déconnexion) | 41 | 0 | **1** | 8 | 10 |
| front réel, saisies limites mais légitimes (4 virements de plus : guillemets, `--`, `;`, `:`, `+`, `=`) | 53 | 0 | **2** | 8 | 14 |
| docs OpenAPI (Swagger UI, ReDoc) | 12 | 0 | 0 | 0 | 0 |
| `ml/generate_normal.py`, 5 min (1 063 actions) | 1 573 | 0 | 0 | 1 353 | 1 353 |
| **Total, fenêtre complète** | **1 735** | **0** | **3** | **1 441** | **1 451** |

- **PL2** : 942440 « SQL Comment Sequence Detected » (CRITICAL, 5 points à elle seule) sur le libellé de virement
  **« Loyer #3 / octobre »** (usage courant, rejoué deux fois), et 942440 + 932200 « RCE Bypass Technique » sur
  « Part 1/2 -- vacances d'été ».
- **PL3** : 920300 (en-tête `Accept` absent : tous les clients scriptés, transaction témoin du moteur comprise), 920272
  (tout caractère non ASCII : « Éloïse », « Témoin », « Utilisateur Démo », tiret cadratin), 942460 (suite de caractères
  spéciaux dans un mot de passe ou dans « (50 %) »).
- **PL4** : en plus 920273 et 942432 (un `-` et un `@` dans une adresse électronique suffisent).
- Au PL1, la règle **920350** « Host header is a numeric IP address » (WARNING, 3 points) se déclenchait sur 1 363 des
  1 543 transactions de trafic normal : toute requête venue du réseau, jury compris, puisque le PC Hôte n'a pas de nom DNS.

### 5.3 Attaques : détection

| Attaque | Requêtes | Bloquées PL1 | PL2 | PL3 | PL4 |
|---|---|---|---|---|---|
| `attack.py injections` (SQLi/XSS de la démonstration, 30 s à 25/min) | 13 | **13** | 13 | 13 | 13 |
| `attack.py brute-force` (30 s à 25/min) | 13 | 0 | 0 | 13 | 13 |
| jeu élargi `waf_paranoia.py payloads` (16 SQLi, 10 XSS, 6 RCE, 4 traversées, 5 divers, 6 corps JSON) | 47 | **42** | 44 | 47 | 47 |
| idem, sans la règle 920350 | 47 | **42** | 44 | 45 | 47 |

- La force brute n'est pas l'affaire du CRS : elle est détectée par la règle SOC `AuthBruteForce` (et par le détecteur
  ML) ; au PL3 elle n'est « bloquée » que par 920300, la règle qui bloque aussi les clients légitimes.
- Manquées au PL1 : `admin'#` et `{{7*7}}` (prises au PL2), `<math><mtext>`, `;id`, `....//` (prises au PL3).
- Retirer 920350 ne change rien au PL1 ni au PL2.

### 5.4 Décision

- **Le PL1 est conservé.** Le PL2 n'apporte que 2 charges sur 47, mais bloque un libellé de virement ordinaire
  (« Loyer #3 ») : avec l'IP NAT partagée du labo, quelques faux positifs du jury suffiraient à faire bloquer tout le labo.
  On pourrait exclure `ARGS:json.label` des règles 942440 et 932200, mais deux jours avant le gel, sur un échantillon de
  saisies forcément incomplet (les règles PL2 visent justement le texte libre : noms, libellés, mots de passe), le risque
  l'emporte ; la protection contre l'injection SQL reste assurée par les requêtes paramétrées (psycopg). Le PL3 est
  inutilisable (accents, en-tête `Accept`).
- **Règle 920350 retirée** (exclusion ciblée, justifiée dans le fichier) : elle consommait 3 des 5 points du seuil sur
  chaque requête légitime venue du réseau, si bien qu'une seule autre règle de niveau NOTICE suffisait à bloquer un
  client. Mesuré : aucune perte de détection (13/13, 42/47).
- **Journal d'audit sans la partie B** (en-têtes de requête) : elle recopiait `Authorization: Bearer <JWT>` dans Loki,
  et, avec 920350, pour chaque requête légitime. Méthode, URI, `client_ip`, code de réponse et règles restent (parties A,
  F, H) : c'est tout ce que lisent `WafAttackBlocked`, le détecteur, le moteur et Grafana (vérifié par une requête LogQL
  et par `observability_check.py`).
- Vérification au PL1 bloquant, configuration finale : front (usage courant et saisies limites), docs, transaction témoin
  et 90 s de `generate_normal.py` : **0 requête interrompue par le WAF** ; le journal d'audit ne garde plus que les
  attaques et les réponses 4xx/5xx (1 ligne pour ce parcours, contre 1 543 en 5 min auparavant).
- Pour monter au PL2 après la démonstration : `WAF_PARANOIA=2` dans `.env`, exclusions `ARGS:json.label` (942440,
  932200) dans `infra/waf/`, puis rejouer le § 10 avec des saisies réelles d'utilisateurs.

## 6. Conteneurs

| Service | Utilisateur du processus | read_only | cap_drop | no-new-priv | Healthcheck | Mémoire (pic mesuré → limite) | Port publié |
|---|---|---|---|---|---|---|---|
| waf | nginx (101) | non (§ 9) | ALL | oui | oui | 98 Mio → 512m | **0.0.0.0**:8088 |
| frontend | nginx (101) | oui | ALL | oui | oui | 26 Mio → 256m | — |
| auth-service | appuser (10001) | oui | ALL | oui | oui | 2,5 Gio (60 connexions simultanées) → 3g | — |
| payment-api | appuser | oui | ALL | oui | oui | 73 Mio → 512m | — |
| postgres | **postgres (70)**, au lieu de root puis gosu | non (§ 9) | **ALL** (aucune avant) | oui | oui | 91 Mio → 1g | — |
| prometheus | nobody | oui | ALL | oui | non (§ 9) | 373 Mio → 1g | 127.0.0.1:9090 |
| alertmanager | nobody | oui | ALL | oui | non (§ 9) | 52 Mio → 256m | 127.0.0.1:9093 |
| loki | 10001 | oui | ALL | oui | non (§ 9) | 293 Mio → 1g | — |
| loki-proxy | nginx (101) | oui | ALL | oui | **ajouté** | 24 Mio → 128m | 127.0.0.1:3100 |
| alloy | root (§ 9) | oui | ALL | oui | non (§ 9) | 475 Mio → 1g | — |
| blackbox | **nobody**, au lieu de root | oui | ALL | oui | **ajouté** | 40 Mio → 256m | — |
| node-exporter | nobody | oui | ALL | oui | **ajouté** | 27 Mio → 128m | — |
| grafana | grafana (472) | oui | ALL | oui | **ajouté** | 1,2 Gio → 2g | 127.0.0.1:3000 |
| ollama (profil `ai`) | root (§ 9) | non (§ 9) | **ALL** (aucune avant) | oui | non | 2,9 Gio (llama3.2:3b + nomic-embed-text) → 6g | — |
| ops-assistant | appuser | oui | ALL | oui | oui | 117 Mio → 1g | 127.0.0.1:8090 |
| anomaly-detector | appuser | oui | ALL | oui | oui | 61 Mio → 512m | — |
| remediation-engine | appuser | oui | ALL | oui | oui | 72 Mio → 512m | — |
| docker-socket-proxy | root (§ 9) | oui | ALL | oui | oui | 42 Mio → 256m | — |
| supervision-dashboard | appuser | oui | ALL | oui | oui | 62 Mio → 512m | 127.0.0.1:8091 |

- **postgres** : `user: "70:70"` et `cap_drop: [ALL]` ; capacités effectives du PID 1 : 0. L'entrypoint ne passe plus par
  root ni par `gosu` (seul porteur du CRITICAL de l'image, désormais jamais exécuté). Essayé aussi sur un volume neuf
  (conteneur jetable, supprimé) : `initdb` et `db/init` passent (bases `authdb`, `paydb`). Sauvegarde, restauration et
  pont de remédiation utilisaient déjà `exec -u postgres`.
- **blackbox** : `user: "65534:65534"` ; seules des sondes HTTP sont configurées (l'ICMP était de toute façon impossible
  sans `CAP_NET_RAW`).
- **ollama** : `cap_drop: [ALL]` ; plongements et génération vérifiés depuis l'assistant.
- **Healthchecks ajoutés** : grafana (`/api/health`), blackbox (`/-/healthy`), node-exporter (`/`), loki-proxy
  (`/healthz`) ; `docker compose up --wait` les attend.
- **docker-socket-proxy** : liste blanche essayée depuis le moteur. Autorisés : `GET /containers/json` et
  `/containers/{id}/json` (200), `restart` (204), `start` (304), `kill?signal=HUP` (204). Refusés (403) : `kill` sans
  signal, `signal=KILL`, `TERM`, `9`, `stop`, `create`, `exec`, `DELETE`, `/images`, `/info`, `/version`. Le refus
  des autres signaux est nouveau : seul le rechargement du WAF utilise `kill`, et un moteur compromis ne peut plus
  arrêter un conteneur par ce biais. Le socket est monté `:ro`, ce qui n'empêche pas d'écrire dans l'API (un `connect()`
  n'est pas une écriture de fichier) : la protection, c'est la liste blanche et le réseau interne.
- **Limites mémoire** : 2 à 10 fois le pic mesuré sous la charge de la démonstration (smoke test, transaction témoin,
  parcours du front, `generate_normal.py`, réponse du LLM, Grafana ouvert). Cas particulier mesuré : argon2id prend
  64 Mio par hachage dans le pool de 40 threads d'anyio, soit **2,5 Gio** pour 60 connexions simultanées (40 traitées à
  la fois) ; 40 vérifications parallèles sous `--memory 3g` passent (pic 2 498 Mio). Après application : **0 OOM**
  (`memory.events`) sur les 19 conteneurs sous la même charge. Pas de limite CPU : un étranglement ralentirait la reprise,
  et le LLM est déjà borné par `LLM_NUM_THREAD=4`. Pas de `pids_limit` (Grafana monte à 176 tâches, Ollama lance des
  processus de calcul) : à mesurer avant de l'ajouter.
- Ports : seul le WAF est publié hors de 127.0.0.1 (`FRONT_BIND`).

## 7. Suites corrigées et observations

### 7.1 `WafAttackBlocked` : seules les requêtes interrompues par le WAF

**Constat.** Le journal d'audit contient aussi les réponses 4xx des API (`SecAuditLogRelevantStatus`), dont leurs 403
(un utilisateur non admin sur `/api/payments/admin/integrity`). La règle SOC comptait tous les `http_code=403` : six en
2 minutes déclenchaient `WafAttackBlocked`, et le moteur bloquait l'IP ; au labo, l'IP NAT de tous les postes. Sur les
lignes réelles du journal, les blocages du WAF portent `"is_interrupted": true` et les 403 des API `false` (sur 60 min :
10 blocages du WAF, 8 refus des API).

**Correction.** Même filtre aux quatre endroits qui comptent les blocages du WAF : règle SOC, variable
`waf_blocks_per_min` du détecteur, requête d'attribution d'IP du moteur (`offender_query`), deux panneaux Grafana :

```
… | json client_ip="transaction.client_ip", code="transaction.response.http_code", interrupted="transaction.is_interrupted"
  | __error__="" | code="403" | interrupted="true"
```

`__error__=""` évite en plus qu'une ligne tronquée (non JSON) fasse échouer l'évaluation de la règle. Un test unitaire
(`tests/unit/test_waf_block.py`) vérifie que les quatre sources et le tableau régénéré gardent ce filtre.

**Preuves en direct** (règle rechargée par le ruler Loki, détecteur et moteur reconstruits) :

| Essai | Ancienne expression | Nouvelle expression | Alerte |
|---|---|---|---|
| utilisatrice inscrite, non admin : 12 appels à `/api/payments/admin/integrity` en 30 s (12 × 403 des API) | 12 pour 172.25.0.1 (> 5 : aurait déclenché) | aucune série | **aucune** (ruler Loki et Alertmanager relevés pendant 45 s) |
| `attack.py injections` depuis un conteneur jetable du réseau edge (« second poste »), 30 s à 25/min | — | 13 pour 172.25.0.3 | **`WafAttackBlocked`** déclenchée, IP bloquée 300 s par le moteur (`inc-20261020-123035-fc6254`), puis `AnomalyDetected` sur le frontal, variable dominante `waf_blocks_per_min` (score 0,991) : « déjà bloquée », vérification seule |

**Détecteur : aligné, sans ré-entraînement.** La variable a été recalculée dans Loki (rétention 7 jours) aux 269 instants
`frontend` des jeux d'entraînement et de test : l'ancienne requête reproduit le CSV à l'identique (269/269), la nouvelle
donne les mêmes valeurs dans **toutes les fenêtres d'attaque** et ne diffère qu'en **18 instants normaux** (1 → 0 : les 403
du smoke test lancé pendant la collecte). Le modèle n'utilise de cette variable que sa médiane (0) et son échelle
(plancher 1, l'écart absolu médian étant nul) : inchangées. Le sens de la variable (« blocages WAF/min ») est donc
conservé, il est même rendu exact ; le modèle `rz-2026-10-19-v3` reste en place, ses métadonnées gardent la requête
d'origine (trace de l'entraînement).

`tests/observability_check.py` ne dépendait pas de l'ancienne expression (il cherche la ligne d'audit de sa propre
injection) : inchangé.

### 7.2 Panneaux SOC du frontal

« Codes HTTP servis par le frontal » et « Top 10 des IP sources » appliquaient `| json` à `{service="frontend"}`, qui
contient aussi les lignes texte de démarrage de nginx (stderr). Juste après `docker compose restart frontend`, mesuré :
l'ancienne requête répond `400 pipeline error: 'JSONParserErr'` ; avec `| __error__=""`, Grafana (`/api/ds/query` sur le
tableau provisionné) renvoie 6 séries (codes) et 4 séries (IP), les deux panneaux de blocage WAF aussi, et le parcours
Chromium du tableau SOC n'a plus aucune erreur console (avant : 400 et `jsonparsererr`).

### 7.3 Autres observations (non corrigées)

- **Charge de connexions** : 240 connexions valides, 60 en parallèle, déclenchent `AnomalyDetected` (`latency_p95`) et le
  moteur redémarre auth-service, ce qui ne règle pas une surcharge. À garder en tête pour la démo (ne pas lancer de
  test de charge pendant le passage).
- **Dépendances Python à bornes** (`>=`) : une reconstruction sans cache sur la VM peut installer des versions plus
  récentes que celles testées. À figer (`pip freeze` des images testées en contraintes) si la VM doit être reconstruite
  de zéro avant vendredi.

## 8. Preuves de non-régression

Après chaque lot (images et en-têtes ; conteneurs, Grafana, proxy, secrets ; WAF ; limites mémoire), stack reconstruite
(`docker compose --profile ai up -d --build --wait`, les 19 conteneurs `healthy` ou `running` pour ceux sans
healthcheck), puis :

| Vérification | Résultat final |
|---|---|
| `.venv/bin/python -m pytest -q` | 394 passed |
| `npm test && npm run build` (`services/frontend`) | 139 tests, build OK |
| `npm test && npm run build` (`services/supervision-dashboard`) | 19 tests, build OK |
| `python tests/smoke_test.py http://127.0.0.1:8088` | 28/28 |
| `RA_FRONT_URL=http://127.0.0.1:8088 python tests/observability_check.py` | 23/23 |
| `.venv/bin/python scripts/export_openapi.py --check` | à jour |
| parcours Chromium (front, docs, supervision, assistant, Grafana) | 0 violation CSP, 0 erreur console sur Grafana |
| transaction témoin du moteur, réponse du LLM | OK |

État laissé : aucune IP bloquée, aucun incident ouvert, aucune alerte active, aucun silence actif, registre intègre
(`/internal/integrity` 200), aucun conteneur de test.

Effets de bord de la revue, pour l'historique des incidents du moteur :

| Heure (UTC) | Fait | Conséquence |
|---|---|---|
| 11:33:47–11:38:47 et 11:38:58–11:47:34 | silences Alertmanager sur **toutes** les alertes pendant les recréations et la mesure du WAF (trop larges) | l'arrêt de payment-api survenu à 11:37:43 n'a été remédié qu'à 11:38:52, et l'incident `inc-20261020-113852-640f7b` est resté ouvert jusqu'à 11:48:27 (transaction témoin tombée pendant la recréation du WAF, notifications `resolved` retenues) |
| 11:46–11:47 | force brute de `attack.py` depuis l'hôte (passerelle edge, exclue du blocage) | `AuthBruteForce` et `AnomalyDetected` escaladés (« réseau exclu »), puis `RemediationFailed` jusqu'à 11:58 |
| 11:54 | 240 connexions simultanées (mesure mémoire d'argon2) | `AnomalyDetected` (`latency_p95`), auth-service redémarré par le moteur, rétabli |
| 11:56:29–11:57:23 | silence limité à `service=~"postgres|auth-service|payment-api|frontend|waf|auth|payments"` pendant la recréation pour les limites mémoire | levé dès la fin (54 s) |
| 12:29 | 12 refus 403 des API pour une utilisatrice non admin (preuve du § 7.1) | aucune alerte |
| 12:30–12:35 | injections depuis un conteneur jetable du réseau edge (preuve du § 7.1) | `WafAttackBlocked` et `AnomalyDetected`, 172.25.0.3 bloquée 300 s puis levée automatiquement au TTL |
| 12:31 | `docker compose restart frontend` (preuve du § 7.2) | aucune alerte (redémarrage de 2 s) |

Leçon, reprise au § 10 : mesurer en `DetectionOnly`, limiter un silence aux services recréés et le lever aussitôt.

## 9. Risques résiduels

| Risque | Justification |
|---|---|
| 44 HIGH Debian dans les 6 images Python (`python:3.12-slim`) | **aucun correctif publié** par Debian ; outils système (util-linux `mount`/`login`, ncurses, perl) jamais exécutés par les services ; processus non root, sans capability, `no-new-privileges` (aucun binaire setuid exploitable), système de fichiers en lecture seule |
| 1 CRITICAL + 24 HIGH de `gosu` (postgres) | **non atteignable** : PostgreSQL tourne directement en uid 70, `gosu` n'est plus lancé |
| CVE Go de Grafana, Prometheus, Alertmanager, Loki, Alloy, node-exporter, blackbox, Ollama | **pas de version corrigée publiée** pour ces lignes (sauf Alloy 1.21.0, mineure du 19/10 : **trop risquée** avant la démo) ; essentiellement des dénis de service HTTP/2, TLS, x509 : interfaces sur 127.0.0.1 derrière une authentification, services internes sans TLS ni port publié |
| OpenSSL et PCRE2 de docker-socket-proxy v0.5.0 | **pas de version publiée** ; reconstruire l'image (`apk upgrade`) ferait maintenir une image dérivée du composant le plus sensible : **trop risqué** avant la démo ; joignable du seul moteur, motifs PCRE2 fixes |
| `libx11` du WAF | **non atteignable** (aucun usage X11) ; l'image `-lts` est reconstruite chaque semaine |
| PL1 seulement (42/47 charges du jeu élargi) | PL2 : faux positifs mesurés sur des virements ordinaires, IP NAT partagée (§ 5.4) |
| Mot de passe recopié dans l'audit si un mot de passe déclenche une règle | au PL1 seulement pour un mot de passe en forme d'attaque (requête alors bloquée) ; à traiter (exclusion de `ARGS:json.password` des journaux) avant tout passage au PL2 |
| Jeton JWT (15 min) en `sessionStorage`, lisible par un script de la page | la CSP stricte n'autorise que les scripts de la même origine (aucun script tiers ni en ligne) ; à revoir si une dépendance externe était ajoutée |
| WAF et postgres sans `read_only` | l'entrypoint du WAF génère sa configuration au démarrage (modèles, CRS, certificat) et le garde-fou de liste réécrit un fichier rendu ; postgres écrit son socket et son verrou hors du volume : gain faible depuis qu'il n'est plus root, risque de régression réel |
| Alloy en root (sans capability) | lit les journaux Docker (`0640 root`) ; passer en uid non root avec le groupe 0 imposerait de recréer son volume d'état (positions perdues, journaux réingérés) |
| Ollama en root, sans `read_only` | modèles dans `/root/.ollama` (volume à root) ; profil `ai` seulement, réseau `ai` sans port publié |
| docker-socket-proxy en root | doit ouvrir le socket Docker (`root:docker`, gid propre à chaque hôte) |
| Pas de healthcheck Prometheus, Alertmanager, Loki, Alloy | Loki et Alloy n'ont ni shell ni client HTTP dans l'image ; Prometheus et Alertmanager exigent l'identifiant même sur `/-/healthy` : le passer en argument de `wget` l'exposerait dans la liste des processus de l'hôte ; les quatre sont surveillés par Prometheus (`up`) |
| Prometheus et Alertmanager sans `X-Frame-Options` ni CSP | interfaces sur 127.0.0.1 derrière une authentification ; possible par `http_server_config.headers` du fichier web (`init_secrets.py`), à faire après la démo |
| Affichage des mots de passe par `init_secrets.py` | voulu pour l'opérateur ; `no_log` dans Ansible |
| RSA 2048 pour les JWT | suffisant jusqu'en 2030 (ANSSI) |
| Reconnaissance faciale : défi de pose contournable par une vidéo ou un masque | le défi (de face puis un seul côté tiré au hasard à la connexion, 2 consignes possibles ; les deux côtés dans un ordre aléatoire à l'enregistrement) et la parallaxe du nez arrêtent une photo tenue immobile et une photo peu inclinée ; mesuré sur une photo réelle déformée en perspective, une **forte inclinaison peut passer** (le repère du nez de YuNet se décale sur une image déformée) ; une vidéo rejouée ou un masque passent. Pas de modèle anti-usurpation passif (type MiniFASNet). Le visage reste un **second** facteur : le mot de passe est exigé avant, 5 essais par étape, refus journalisés et captures gardées pour le SOC |
| Reconnaissance faciale : seuils non calibrés sur de vraies webcams | similarité SFace 0,363 (valeur d'OpenCV), seuils de pose et de parallaxe tirés d'un modèle 3D synthétique ; réglables par variables d'environnement, journal `face_liveness` en DEBUG pour les ajuster |
| Données biométriques dans les sauvegardes et restaurations de `authdb` | chiffrées (AES-256-GCM, clé hors base dans `secrets/`) ; une restauration peut toutefois faire réapparaître un visage supprimé entre-temps (droit à l'effacement) : à traiter par une purge après restauration |
| Clé `face_encryption_key` régénérée par `init_secrets.py --force` | les empreintes enregistrées deviennent illisibles : la connexion par visage répond `face_reference_unreadable` et l'utilisateur réinitialise (ou supprime) son visage depuis Paramètres → Sécurité ; à restaurer avec les autres secrets (SOPS) |

## 10. Rejouer la revue

Depuis la racine du dépôt, pile démarrée (`.env` : `FRONT_PORT=8088`).

```bash
# Trivy officiel en conteneur (socket Docker en lecture seule, cache dans un volume, dépôt en lecture seule)
docker volume create trivy-cache
trivy() { docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro -v trivy-cache:/root/.cache/ \
  -v "$PWD":/src:ro aquasec/trivy:0.75.0 "$@"; }
for img in $(docker compose --profile ai config --images | sort -u); do
  trivy image -q --scanners vuln --severity HIGH,CRITICAL "$img"
done
trivy config -q --skip-dirs '**/node_modules' /src    # Dockerfiles (Compose n'est pas analysé par Trivy)
trivy fs -q --scanners secret --skip-dirs '**/node_modules' --skip-dirs .venv /src   # attendu : secrets/jwt_private.pem seul
trivy fs -q --scanners vuln --include-dev-deps --skip-dirs '**/node_modules' /src    # package-lock.json

# En-têtes
for u in http://127.0.0.1:8088/ http://127.0.0.1:8088/api/auth/health http://127.0.0.1:8088/api/auth/docs \
         http://127.0.0.1:3000/login http://127.0.0.1:9090/ http://127.0.0.1:9093/ http://127.0.0.1:3100/ready \
         http://127.0.0.1:8090/ http://127.0.0.1:8091/; do echo "== $u"; curl -s -o /dev/null -D - "$u"; done

# Proxy Docker : liste blanche (depuis le moteur, seul client du réseau docker-api) ; attendu : « HTTP Error 403: Forbidden »
docker compose exec remediation-engine python -c "import urllib.request as u; \
  print(u.urlopen(u.Request('http://docker-socket-proxy:2375/version')).status)"
```

Niveau de paranoïa (rien n'est bloqué pendant la mesure, mais le WAF est recréé : la pile doit être au repos) :

```bash
cat > /tmp/waf-mesure.yml <<'EOF'
services:
  waf:
    environment:
      MODSEC_RULE_ENGINE: DetectionOnly
      PARANOIA: "4"
      BLOCKING_PARANOIA: "4"
      DETECTION_PARANOIA: "4"
EOF
docker compose -f docker-compose.yml -f /tmp/waf-mesure.yml up -d --wait waf
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python tests/smoke_test.py http://127.0.0.1:8088
docker compose exec remediation-engine python -c "from app.witness import Witness; print(Witness().run()['steps'][-1])"
python ml/generate_normal.py --base http://127.0.0.1:8088 --duration 300
# … puis un parcours réel du front dans un navigateur (inscription, virements avec des libellés variés)
docker logs --since "$T0" resilience-alpha-waf-1 2>&1 | python scripts/scenarios/waf_paranoia.py analyze
T1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python scripts/scenarios/waf_paranoia.py payloads --target http://127.0.0.1:8088
docker logs --since "$T1" resilience-alpha-waf-1 2>&1 | python scripts/scenarios/waf_paranoia.py verdicts
docker compose up -d --wait waf                         # retour à la configuration normale (PL1, blocage)
RA_FRONT_URL=http://127.0.0.1:8088 python tests/observability_check.py   # 23/23
```

`attack.py` lancé depuis l'hôte passe par la passerelle edge, exclue du blocage : ses alertes atteignent quand même le
moteur, qui escalade. Si un silence Alertmanager est nécessaire pendant une recréation, le limiter aux services recréés
(`service=~"…"`), le garder court et le supprimer aussitôt (`DELETE /api/v2/silence/<id>`).

Règle `WafAttackBlocked` (§ 7.1) : comparer les deux expressions dans Loki (`/loki/api/v1/query` via loki-proxy) après
des 403 d'API, puis la déclencher par une vraie attaque depuis le réseau edge (l'IP du conteneur est bloquée pendant
`WAF_BLOCK_TTL_SECONDS`, puis levée seule) :

```bash
# 403 des API : un compte non admin appelle GET /api/payments/admin/integrity une douzaine de fois → aucune alerte
docker run --rm --network resilience-alpha_edge -v "$PWD/scripts/scenarios:/s:ro" python:3.12-slim \
  python -I /s/attack.py injections --target http://waf:8080 --duration 30 --rate 25    # → WafAttackBlocked, blocage
docker compose restart frontend     # puis tableau SOC : « Codes HTTP » et « Top 10 IP » affichent des données (§ 7.2)
```

Conteneurs et mémoire :

```bash
docker compose --profile ai ps
for c in $(docker compose --profile ai ps -q); do
  id=$(docker inspect -f '{{.Id}}' "$c"); f=/sys/fs/cgroup/system.slice/docker-$id.scope
  echo "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}} user={{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}} mem={{.HostConfig.Memory}}' "$c") \
pic=$(( $(cat $f/memory.peak) / 1048576 ))Mio oom=$(grep oom_kill $f/memory.events | cut -d' ' -f2)"
done
```

Puis la batterie du § 8.
