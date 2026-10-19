# ops-assistant — assistant RAG pour les opérateurs (pilier IA/DATA)

Assistant local qui aide l'opérateur confronté à un incident à **comprendre ce qui se passe et à retrouver la bonne
procédure** dans la documentation de l'équipe (runbooks, architecture, contrats d'intégration, PCA/PRA). Construit avec
**LangChain** et un **LLM local servi par Ollama** (≤ 8 milliards de paramètres). Chaque réponse **cite ses sources**
(fichier + section) et l'assistant répond « je ne sais pas » quand la documentation ne couvre pas la question.

> L'assistant **n'exécute aucune action** et n'a aucun accès privilégié : il ne remplace pas le moteur de remédiation
> (`services/remediation-engine/`), qui reste le seul composant autorisé à agir sur la plateforme.

## Démarrage

Sur le PC Hôte (VM Debian 13 du Proxmox, 6 vCPU, 16 Go, sans GPU), l'assistant fait partie de la stack ; le LLM tourne
dans le conteneur `ollama` (profil `ai`) ou sur le PC de délestage IA :

```bash
ansible-playbook -i ansible/inventory.ini ansible/deploy.yml           # mode du LLM : pc_hote_ai_mode (group_vars)
ssh -N -L 8090:127.0.0.1:8090 resilience@172.16.147.10                 # depuis le poste de l'opérateur
# puis http://127.0.0.1:8090 : identifiant admin, mot de passe dans secrets/ops_assistant_password
#   (sur la VM : sudo cat /opt/resilience-alpha/shared/secrets/ops_assistant_password), ou :
curl -s http://127.0.0.1:8090/health                                   # sans identifiant : état seul, toujours 200
curl -s -u "admin:$PASS" http://127.0.0.1:8090/health                  # avec : détail (Ollama, index)
curl -s -u "admin:$PASS" -X POST http://127.0.0.1:8090/ask -H 'Content-Type: application/json' \
     -d '{"question": "Que faire quand LedgerIntegrityBroken se déclenche ?"}'
```

Hors Ansible (poste de développement) : `python scripts/init_secrets.py`, puis
`COMPOSE_PROFILES=ai docker compose up -d --build` et, une fois, `docker compose exec ollama ollama pull llama3.2:3b`
et `docker compose exec ollama ollama pull nomic-embed-text` (modèles stockés dans le volume `ollama-data`).

Sans LLM joignable (profil `ai` non activé, modèle absent, PC IA éteint), l'assistant démarre quand même et reste
**healthy** : `/health` répond 200 avec `"status": "degraded"`, `"ready": false` et la cause (`checks.ollama`,
`checks.index`) ; `/ask` répond 503 en listant les documents à consulter ; l'index est reconstruit automatiquement
(nouvel essai toutes les 15 s) dès qu'Ollama répond, puis le LLM est préchargé. Un LLM absent ne fait donc jamais
échouer `docker compose up --wait` (utilisé par `ansible/deploy.yml`).

**Déploiement Ansible** : `pc_hote_ai_mode` (`ansible/group_vars/pc_hote.yml`) choisit où tourne le LLM et
`deploy.yml` l'écrit à chaque déploiement dans le `.env` de Compose (`/opt/resilience-alpha/shared/.env`) :

| `pc_hote_ai_mode` | `.env` écrit | Effet |
|---|---|---|
| `container` (défaut) | `COMPOSE_PROFILES=ai`, `OLLAMA_BASE_URL=http://ollama:11434` | le conteneur `ollama` démarre avec la stack ; après `up --wait`, `deploy.yml` tire les modèles **absents** du volume `ollama-data` (une seule fois, ~2,3 Go). Sans Internet, simple avertissement : le déploiement continue, l'assistant reste dégradé et se rétablit seul dès que les modèles sont là |
| `offload` | `OLLAMA_BASE_URL=<pc_hote_ai_offload_url>` | LLM sur le PC de délestage IA (modèles à tirer sur ce PC) |
| `off` | aucun profil | pas de LLM : assistant dégradé, `/ask` en 503 |

Le téléchargement n'est pas un service Compose « one-shot » : `docker compose up --wait` échoue dès qu'un conteneur se
termine, même avec le code 0 (vérifié avec Compose 5.6) ; c'est donc une étape idempotente de `deploy.yml`
(`ollama list`, puis `ollama pull` seulement si le modèle manque).

### Où tourne le LLM (`OLLAMA_BASE_URL`)

| Option | `OLLAMA_BASE_URL` | Quand la choisir |
|---|---|---|
| **Conteneur `ollama`** (défaut) | `http://ollama:11434` | Sur la VM PC Hôte : profil `ai`, non publié, joint par le réseau `ai`. CPU uniquement (pas de GPU sur la VM) ; `OLLAMA_NUM_PARALLEL=1` (un seul contexte réservé) est fixé dans le compose. |
| **PC de délestage IA** (3e PC) | `http://<ip-du-pc-ia>:11434` | Le LLM ne prend ni CPU ni RAM à la VM pendant la démo, et peut profiter d'un GPU (`mistral` devient alors aussi rapide que le 3B, voir les mesures). Sur ce PC : `OLLAMA_HOST=0.0.0.0:11434`, `OLLAMA_NUM_PARALLEL=1` et **pare-feu limité à l'IP de la VM** (172.16.147.10) : l'API Ollama n'a aucune authentification. |
| **Ollama natif de l'hôte** | `http://host.docker.internal:11434` | **Développement uniquement**, sous Docker Desktop (joint l'Ollama local). Inutilisable sur la VM : le pare-feu nftables de l'hôte (entrée refusée sauf SSH et WAF) bloque un conteneur qui vise l'hôte, et un Ollama Linux n'écoute par défaut que sur 127.0.0.1. `extra_hosts: host-gateway` reste dans le compose pour les postes Linux de développement. |

Les autres variables (`OPS_ASSISTANT_LLM_NUM_THREAD`, `OPS_ASSISTANT_PORT`…) gardent leurs valeurs par défaut de
`docker-compose.yml`, adaptées à la VM. `OPS_ASSISTANT_LLM_NUM_THREAD=4` (défaut) laisse 2 des 6 vCPU à la stack
pendant qu'une réponse est générée.

### Développement local (sans Docker)

```bash
python -m pip install -r services/ops-assistant/requirements.txt
cd services/ops-assistant && OPS_ASSISTANT_PASSWORD_FILE=../../secrets/ops_assistant_password \
    PYTHONPATH=../common:. python -m uvicorn app.main:app --port 8090
```

Par défaut le corpus est lu à la racine du dépôt et Ollama sur `http://127.0.0.1:11434` (`LLM_MODEL`, `LLM_NUM_THREAD`,
`LLM_NUM_GPU` pour changer de modèle ou forcer le CPU). Sans mot de passe configuré, tout est refusé sauf `/health`.

## Contrat d'intégration

| Élément | Détail |
|---|---|
| Authentification | **Basic** `admin` / `secrets/ops_assistant_password` (généré par `scripts/init_secrets.py`, monté en secret Docker) sur tout sauf `/health` : page, `/static`, `/ask`, `/metrics`, `/docs`. 401 + `WWW-Authenticate` sans identifiant ; un mauvais mot de passe est journalisé (`event_type=auth_failure`, IP source) |
| `POST /ask` | `{"question": "…" (3 à 500 caractères), "include_alerts": true}` → `answer`, `refused`, `cited`, `sources[]` (`id`, `source`, `section`, `score`, `cited`, `excerpt`), `alerts[]`, `alerts_error`, `model`, `timings_ms` |
| Erreurs | `{code, detail}` : 422 question invalide, 411/413 corps absent ou > 4 Ko, 503 `index_unavailable` / `llm_unavailable` (avec la liste des documents à lire) / `assistant_busy`, 504 `llm_timeout` |
| `GET /health` | **toujours 200** tant que le service répond (healthcheck Docker, sans identifiant) ; `status` vaut `ok` et `ready` `true` si Ollama répond, que les deux modèles y sont installés et que l'index est prêt, sinon `degraded` / `false`. Sans identifiant, rien d'autre ; avec, `checks.ollama` (adresse, modèles), `checks.index` (état, essais, dernière erreur, documents indexés) |
| `GET /metrics` | `http_requests_total`, `http_request_duration_seconds` (communs), `ops_assistant_questions_total{result}` (answered/refused/error/timeout/busy/unavailable), `ops_assistant_stage_duration_seconds{stage}` (indexing/retrieval/generation), `ops_assistant_index_ready`, `ops_assistant_index_chunks`, `ops_assistant_ollama_up` |
| `GET /` | page de consultation (HTML + JS servis par le service, CSP stricte, aucun appel externe) |
| Journaux | JSON sur stdout (→ Loki), `event_type=assistant_question` avec la question (300 caractères max), le modèle, les fichiers cités et les durées : traçabilité de l'usage |
| LLM | `OLLAMA_BASE_URL`, `LLM_MODEL`, `EMBED_MODEL` (voir `.env.example`, variables `OPS_ASSISTANT_*`) |
| Corpus | `docs/**/*.md` + README d'architecture, montés **en lecture seule** sous `/corpus` |
| Réseaux | `ai` seulement (Ollama conteneurisé ; ce réseau n'étant pas interne, il suffit à publier `127.0.0.1:8090`, joint par tunnel SSH) ; **aucun** accès au socket Docker, à la base, aux autres secrets, à la chaîne d'observation ni au moteur de remédiation |

Prometheus ne scrape pas l'assistant : `/metrics` exige le même identifiant, et les deux services ne partagent aucun
réseau. Pour le brancher : un réseau commun (par exemple un réseau interne dédié aux deux), le secret
`ops_assistant_password` monté dans Prometheus et, dans `infra/prometheus/prometheus.yml` :

```yaml
  - job_name: ops-assistant
    basic_auth: { username: admin, password_file: /run/secrets/ops_assistant_password }
    static_configs: [{ targets: ["ops-assistant:8000"], labels: { service: ops-assistant } }]
```

## Fonctionnement de la chaîne RAG

```
docs/**/*.md + README ─▶ MarkdownHeaderTextSplitter (#, ##, ###) ─▶ RecursiveCharacterTextSplitter (1000 car., recouvrement 150)
                         chaque fragment garde {source: fichier, section: « Titre > Section »} et commence par ce chemin de titres
        ─▶ nomic-embed-text (préfixe « search_document: ») ─▶ InMemoryVectorStore (RAM, reconstruit à chaque démarrage)

question ─▶ nomic-embed-text (« search_query: ») ─▶ 4 extraits les plus proches (cosinus ≥ 0,5)
         (+ 2 extraits sur les alertes actives d'Alertmanager, lues en GET)
         ─▶ prompt : règles + <extrait id="n" fichier="…" section="…"> … </extrait> + <alertes> … </alertes>
         ─▶ ChatOllama (température 0,1, num_ctx 4096, num_predict 400)
         ─▶ réponse avec renvois [n] ─▶ sources citées (fichier + section) renvoyées à l'opérateur
```

Choix et justifications :

- **Corpus** : `docs/**/*.md` (runbooks, gouvernance), le README racine (architecture, points d'intégration,
  comportements de résilience vérifiés) et les README des composants et d'Ansible (contrats, procédures de reprise).
  Exclus : `docs/context/` (sujet et grille d'évaluation, sans valeur pour un opérateur et source de réponses
  hors sujet), `docs/TODO.md` (suivi de projet, vite périmé) et la documentation de l'assistant lui-même (ses résultats
  d'évaluation biaiseraient la recherche). Les README sont montés un par un : le reste du code n'est pas exposé.
  Le corpus est configurable (`CORPUS_INCLUDE`, `CORPUS_EXCLUDE`) ; un fichier qui sort de la racine (lien symbolique)
  ou dépasse 512 Ko est ignoré.
- **Découpage par titres** : une section Markdown (« Par alerte », « Comportements de résilience ») est une unité de
  sens, et son titre sert à la fois à la recherche et à la citation.
- **Index en mémoire** (`InMemoryVectorStore` de `langchain-core`) plutôt que FAISS/Chroma : pour quelques dizaines de
  fragments, une recherche exacte prend quelques dizaines de ms (vectorisation de la question comprise : 45 ms en CPU)
  et l'index se construit en ~1 s avec GPU, ~27 s en CPU sur 4 threads (par lots de 8) ; rien n'est écrit sur disque
  (compatible `read_only: true`). L'intégration FAISS de LangChain vit dans `langchain-community`, désormais marqué
  « en fin de vie » (avertissement à l'import) ; Chroma ajoute ~200 Mo de dépendances et un stockage persistant. Si le
  corpus dépasse quelques milliers de fragments, `InMemoryVectorStore` se remplace par FAISS sans changer le reste.
- **Préfixes de tâche nomic** (`search_document:` / `search_query:`, l'usage prévu du modèle) : sur le corpus actuel, ils
  améliorent le rang du bon extrait (MRR 0,79 → 0,83) mais pas le succès top-4 (90 % contre 95 % sans : une question
  de plus manquée) ; sur le corpus précédent, plus petit, ils donnaient 100 % contre 93 %. Gain modeste, conservé.
- **Refus** : les scores de similarité des questions hors corpus (jusqu'à 0,71) recouvrent ceux des vraies questions
  (dès 0,65) : un seuil seul ne suffit pas. Le seuil (0,5) n'écarte que l'évidence ; le refus est surtout obtenu par le
  prompt, dont la formulation a été choisie sur le jeu d'évaluation : avec la première version, `llama3.2:3b` comme
  `mistral` inventaient une procédure de déploiement Kubernetes absente du corpus ; avec la version retenue, les trois
  questions hors corpus sont refusées par tous les modèles testés, à chaque exécution.
- **Données ≠ instructions** : extraits et alertes sont placés entre balises, les balises qui apparaîtraient dans un
  document sont neutralisées, et le prompt demande d'ignorer toute consigne qu'ils contiendraient.

## Choix du modèle (mesures)

Évaluation : `python services/ops-assistant/eval/run_eval.py --models llama3.2:3b,mistral:latest [--num-gpu 0] [--num-thread 4]`
sur [`eval/questions.json`](eval/questions.json) — 25 questions : 20 sur les procédures, l'architecture, les alertes,
l'intégrité, la restauration et l'analyse de risques, 1 sur une lacune connue du corpus (coût d'indisponibilité),
3 hors corpus et 1 demande d'action. Résultats complets et réponses relues dans [`eval/results/`](eval/results/).

Mesures du 19/10/2026 sur un poste de développement **avec GPU** (Ryzen 7 5800H, RTX 3070 Mobile 8 Go ; corpus de
10 documents, 55 fragments ; k = 4) — [`eval/results/rapport-gpu.md`](eval/results/rapport-gpu.md) :

| Modèle | Citent une source attendue | Refus hors corpus | Prétend agir | Latence moy. / max (s) | Jetons/s | Mémoire (Mo) |
|---|---|---|---|---|---|---|
| `llama3.2:1b` | 50 % | 3/3 | non | 1,1 / 2,5 | 165 | 3 552 |
| `llama3.2:3b` | 75 % | 3/3 | **oui (q19)** | 1,3 / 3,3 | 95 | 5 365 |
| `mistral` (7B) | 95 % | 3/3 | non | 1,9 / 3,9 | 50 | 5 779 |
| `deepseek-r1:7b` | 45 % | 3/3 | non | 10,0 / 16,3 | 38 | 6 960 |

Relecture humaine des 20 réponses documentées ([`eval/results/relecture.md`](eval/results/relecture.md)) :
`mistral` **15 justes, 3 partielles, 2 fausses** ; `llama3.2:3b` **10 justes, 4 partielles, 6 fausses**, et une
réponse où il prétend lancer `docker restart`. `llama3.2:1b` (citations trop rares) et `deepseek-r1:7b` (raisonnement
long : 5 à 8 fois plus lent, réponses moins sourcées) sont écartés.

Mesures en **CPU seul, 4 threads** (proxy de la VM : `run_eval.py --models llama3.2:3b --num-gpu 0 --num-thread 4`,
même poste, GPU désactivé requête par requête, 4 threads comme `OPS_ASSISTANT_LLM_NUM_THREAD` ; corpus de 65 fragments,
charge machine 4 à 5,5 pendant la mesure car la stack tournait) —
[`eval/results/rapport-cpu-4threads.md`](eval/results/rapport-cpu-4threads.md) :

| `llama3.2:3b`, CPU 4 threads | Mesure |
|---|---|
| Latence par réponse (moyenne / p95 / max) | **56,5 s / 70,1 s / 91,6 s** (minimum 42 s ; un refus prend aussi 43 à 61 s) |
| dont lecture du prompt (~1 650 jetons) / génération | 42,0 s / 14,4 s en moyenne — la lecture du contexte domine |
| Vitesse de génération | 5,8 jetons/s (contre 95 avec GPU) |
| Chargement à froid (1re question après démarrage) | 70,4 s — d'où le préchargement automatique du modèle |
| Construction de l'index (65 fragments, par lots de 8) | 33 s |
| Mémoire du modèle chargé | 3,8 Go (4 contextes réservés par l'Ollama de mesure ; `OLLAMA_NUM_PARALLEL=1` dans le conteneur `ollama`) |
| Qualité | 90 % citent une source, 75 % une source attendue, 3/3 refus hors corpus, et de nouveau la réponse « je vais … `docker restart` » à q19 |

Deux contrôles directs (même configuration, appel chronométré de l'extérieur) donnent 64,4 s et 60,8 s, identiques
aux durées relevées par l'évaluation. La campagne complète (25 questions) a duré 51 min de bout en bout : `mistral` en
CPU n'a donc **pas été mesuré** (seuil fixé : 15 min pour la campagne du 3B). Ordre de grandeur attendu, non mesuré :
environ deux fois plus lent que le 3B (2,2 fois plus de paramètres), soit 2 min par réponse.

**Sur la VM**, compter **au moins** ces durées : ses 6 vCPU (Proxmox) sont a priori moins rapides que les cœurs du
Ryzen 7 5800H de mesure et partagés avec toute la stack. Levier principal : la lecture du prompt, proportionnelle au
contexte (`RETRIEVAL_K=3` ou `CHUNK_SIZE` plus petit la réduiraient, au prix de la recherche — non mesuré).

**Choix** :
- **`llama3.2:3b` par défaut sur la VM** (6 vCPU, sans GPU) : seul modèle mesuré dont la latence CPU reste de l'ordre
  de la minute ; 3,8 Go de RAM au plus, compatibles avec les 16 Go de la VM (la stack en occupe ~1,4 Go). Sa justesse
  plus faible (10/20 en relecture, une action prétendue) impose de vérifier les sources citées.
- **`mistral` dès qu'un GPU est disponible** (PC de délestage IA, `pc_hote_ai_mode: offload`) : nettement plus juste
  (15/20), jamais d'action prétendue, ~2 s par réponse avec GPU.

## Sécurité

- **Aucun outil, aucune action** : le LLM ne produit que du texte, aucune réponse n'est interprétée ni exécutée ; il n'y
  a pas d'appel de fonctions (« tools »). Une injection de consignes (dans une question ou un document) peut au pire
  produire une réponse trompeuse, jamais une action — d'où l'obligation de citer la source, que l'opérateur vérifie.
- **Moindre privilège** : conteneur `read_only`, `tmpfs /tmp`, `cap_drop: ALL`, `no-new-privileges`, utilisateur 10001 ;
  corpus monté `:ro` ; **un seul secret monté, son propre mot de passe** (aucun autre secret : le LLM ne peut pas en
  divulguer, et ce mot de passe n'est jamais placé dans un prompt) ; ni socket Docker, ni réseaux `app`/`data`/`obs`/`mgmt`.
- **Alertes en lecture seule, désactivées** : le code sait lire `GET /api/v2/alerts` et ne transmet au LLM que le nom, la
  gravité, le domaine, le service, le résumé et l'heure (10 alertes au plus, 200 caractères par champ). Mais Alertmanager
  exige désormais le compte `admin`, qui permet aussi de poser des silences et donc de masquer une alerte :
  l'assistant ne reçoit pas ce secret, `OPS_ASSISTANT_ALERTMANAGER_URL` est vide et l'assistant n'est plus sur le
  réseau `mgmt` (Alertmanager est injoignable). À rebrancher sur une API d'état en lecture seule (moteur de
  remédiation, dashboard de supervision), sur un réseau partagé avec elle seule.
- **Entrées bornées** : question ≤ 500 caractères, corps ≤ 4 Ko (413 sinon), une génération à la fois (503 « occupé »
  au-delà de 20 s d'attente), réponse ≤ 400 jetons, premier jeton attendu 180 s au plus et réponse complète 240 s
  (504 au-delà : chargement à froid d'un 7B en CPU), 32 connexions simultanées au plus.
- **Exposition** : publié uniquement sur `127.0.0.1:8090` de la VM (`MGMT_BIND`), comme les autres interfaces de
  gestion, et joint par tunnel SSH (`ssh -N -L 8090:127.0.0.1:8090 resilience@172.16.147.10`) ; **authentification
  basique** comme Grafana, Prometheus, Alertmanager et Loki (`admin` / `secrets/ops_assistant_password`, comparaison à
  temps constant), sauf `/health` réduit à l'état (ni adresse d'Ollama, ni documents, ni erreurs) ; en-têtes
  `nosniff`, `X-Frame-Options: DENY`, CSP stricte sur la page.
- **LLM conteneurisé non publié** : le conteneur `ollama` n'a aucun port publié, seul le réseau `ai` le joint. Sur le
  PC de délestage IA, l'API Ollama (sans authentification) doit être filtrée par pare-feu sur l'IP de la VM.
- **Journaux** : volontairement pas `event_type=dependency_failure` quand Ollama tombe (`llm_unavailable` à la place) :
  la règle SOC `DependencyFailures` déclencherait sinon une alerte critique de disponibilité vers la remédiation.
- **Risques résiduels** : le réseau `ai` n'est pas `internal` (il sert à publier le port et au `ollama pull`), donc une
  sortie Internet reste possible depuis l'assistant (le code n'en fait aucune, le traçage LangSmith est désactivé) ;
  le mot de passe Basic circule en clair entre le navigateur et le service, ce qui n'est acceptable que dans le tunnel
  SSH ; aucune limitation du nombre d'essais (les échecs sont journalisés pour le SOC). En contexte industriel : TLS,
  comptes nominatifs (SSO), sortie Internet coupée une fois les modèles installés.

## Limites

- **La justesse dépend du modèle et du corpus** : en relecture, `llama3.2:3b` donne 6 réponses fausses sur 20 (dont
  une requête Loki inventée mais citée) et `mistral` 2 sur 20 (`eval/results/relecture.md`). Les sources citées
  doivent être vérifiées : la page les affiche pour cela.
- **Corpus encore incomplet** : le runbook ne décrit que quatre alertes (réponses souvent « à définir »), le PCA/PRA
  et l'analyse NIS2/DORA sont des plans. Sur ces sujets l'assistant répond « je ne sais pas » ; les deux erreurs
  communes aux modèles (q06, q14) viennent d'informations présentes seulement en liste ou ambiguës dans le corpus.
- **Recherche** : 4 extraits par question ; une information isolée dans une liste (requête Loki du runbook) peut ne
  pas remonter. Une recherche hybride (mots-clés + vecteurs) ou des runbooks rédigés par alerte l'amélioreraient.
- **Latence en CPU seul** : ~1 min par réponse mesurée sur 4 threads (56,5 s en moyenne, 92 s au pire), davantage sur
  la VM ; chaque réponse occupe 4 vCPU et une seule question est traitée à la fois.
- Jeu d'évaluation réduit (25 questions, une exécution par configuration, sortie non déterministe) : les taux sont
  indicatifs ; l'indicateur « termes clés » est grossier, d'où la relecture humaine.
- L'index n'est reconstruit qu'au démarrage : après une mise à jour des documents, `docker compose restart ops-assistant`.
  Les README étant montés fichier par fichier, un éditeur qui remplace le fichier (nouvel inode) n'est vu qu'après ce
  redémarrage.
- Réponses en français uniquement ; pas de mémoire de conversation (chaque question est indépendante).
- Pas de contexte d'incident en direct par défaut : la lecture des alertes est désactivée (voir Sécurité) et l'assistant
  ne lit ni métriques ni journaux (cela exigerait le réseau `obs`, réservé à la chaîne d'observation et de remédiation).

## Section pour le dossier (données, préparation, modèle, résultats, limites)

- **Données (corpus)** : documentation de l'équipe — `docs/**/*.md` (runbooks, EBIOS RM, PCA/PRA, NIS2/DORA), README
  racine (architecture, points d'intégration) et README des composants et d'Ansible ; 10 documents, 55 fragments.
  Exclus : sujet et grille d'évaluation (`docs/context/`), suivi de projet (`docs/TODO.md`), documentation de
  l'assistant lui-même.
- **Préparation** : découpage par titres Markdown puis par taille (1 000 caractères, recouvrement 150) ; chaque
  fragment garde son fichier et son chemin de titres, réutilisés pour la citation ; embeddings `nomic-embed-text` avec
  préfixes de tâche, index vectoriel en mémoire reconstruit au démarrage.
- **Modèle** : chaîne LangChain + Ollama — 4 extraits les plus proches, prompt qui impose de citer `[n]`, de répondre
  « je ne sais pas » hors corpus et de ne jamais prétendre agir ; LLM local ≤ 8 milliards de paramètres
  (`llama3.2:3b` sur la VM, `mistral` 7B avec GPU).
- **Résultats** : recherche — bon extrait dans les 4 premiers pour 90 % des questions (MRR 0,83) ; génération (GPU) —
  `mistral` 15/20 réponses justes, 95 % citent une source attendue ; `llama3.2:3b` 10/20 ; 3/3 refus hors corpus pour
  tous les modèles ; latence 1 à 2 s avec GPU ; en CPU seul sur 4 threads (proxy de la VM), `llama3.2:3b` met
  56,5 s en moyenne (70 s au 95e centile), dont 42 s de lecture du contexte.
- **Limites** : un petit modèle peut attacher une citation à une information inventée (relecture obligatoire des
  sources) ; corpus encore mince (runbook limité à quelques alertes) ; recherche purement vectorielle qui manque une
  information isolée dans une liste ; environ une minute par réponse en CPU, sans doute plus sur la VM ; pas de
  contexte d'incident en direct (lecture des alertes désactivée faute d'accès en lecture seule à Alertmanager) ;
  authentification basique à compte unique, joignable seulement par tunnel SSH.
