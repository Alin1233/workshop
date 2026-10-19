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
COMPOSE_PROFILES=ai docker compose up -d --build                       # stack + ollama (ou --profile ai)
docker compose exec ollama ollama pull llama3.2:3b                     # une fois : modèles dans le volume ollama-data
docker compose exec ollama ollama pull nomic-embed-text
ssh -N -L 8090:127.0.0.1:8090 resilience@172.16.147.10                 # depuis le poste de l'opérateur
# puis http://127.0.0.1:8090 (page de consultation), ou :
curl -s http://127.0.0.1:8090/health                                   # toujours 200 ; "status": "ok" ou "degraded"
curl -s -X POST http://127.0.0.1:8090/ask -H 'Content-Type: application/json' \
     -d '{"question": "Que faire quand LedgerIntegrityBroken se déclenche ?"}'
```

Sans LLM joignable (profil `ai` non activé, modèle absent, PC IA éteint), l'assistant démarre quand même et reste
**healthy** : `/health` répond 200 avec `"status": "degraded"`, `"ready": false` et la cause (`checks.ollama`,
`checks.index`) ; `/ask` répond 503 en listant les documents à consulter ; l'index est reconstruit automatiquement
(nouvel essai toutes les 15 s) dès qu'Ollama répond, puis le LLM est préchargé. Un LLM absent ne fait donc jamais
échouer `docker compose up --wait` (utilisé par `ansible/deploy.yml`).

> `ansible/deploy.yml` n'active pas encore le profil `ai` : déployé tel quel, l'assistant tourne en mode dégradé.
> Pour l'activer, lancer Compose avec `COMPOSE_PROFILES=ai` (environnement de la tâche « Construire et démarrer la
> stack ») et tirer les deux modèles une fois dans le conteneur `ollama` (le réseau `ai` a une sortie Internet).

### Où tourne le LLM (`OLLAMA_BASE_URL`)

| Option | `OLLAMA_BASE_URL` | Quand la choisir |
|---|---|---|
| **Conteneur `ollama`** (défaut) | `http://ollama:11434` | Sur la VM PC Hôte : profil `ai`, non publié, joint par le réseau `ai`. CPU uniquement (pas de GPU sur la VM) ; `OLLAMA_NUM_PARALLEL=1` (un seul contexte réservé) est fixé dans le compose. |
| **PC de délestage IA** (3e PC) | `http://<ip-du-pc-ia>:11434` | Le LLM ne prend ni CPU ni RAM à la VM pendant la démo, et peut profiter d'un GPU (`mistral` devient alors aussi rapide que le 3B, voir les mesures). Sur ce PC : `OLLAMA_HOST=0.0.0.0:11434`, `OLLAMA_NUM_PARALLEL=1` et **pare-feu limité à l'IP de la VM** (172.16.147.10) : l'API Ollama n'a aucune authentification. |
| **Ollama natif de l'hôte** | `http://host.docker.internal:11434` | **Développement uniquement**, sous Docker Desktop (joint l'Ollama local). Inutilisable sur la VM : le pare-feu nftables de l'hôte (entrée refusée sauf SSH et WAF) bloque un conteneur qui vise l'hôte, et un Ollama Linux n'écoute par défaut que sur 127.0.0.1. `extra_hosts: host-gateway` reste dans le compose pour les postes Linux de développement. |

Les variables (`OLLAMA_BASE_URL`, `OPS_ASSISTANT_LLM_MODEL`, `OPS_ASSISTANT_LLM_NUM_THREAD`…) ont des valeurs par défaut
dans `docker-compose.yml` adaptées à la VM : le déploiement Ansible ne copie pas de `.env` (seul le commit est déployé).
`OPS_ASSISTANT_LLM_NUM_THREAD=4` (défaut) laisse 2 des 6 vCPU à la stack pendant qu'une réponse est générée.

### Développement local (sans Docker)

```bash
python -m pip install -r services/ops-assistant/requirements.txt
cd services/ops-assistant && PYTHONPATH=../common:. python -m uvicorn app.main:app --port 8090
```

Par défaut le corpus est lu à la racine du dépôt et Ollama sur `http://127.0.0.1:11434` (`LLM_MODEL`, `LLM_NUM_THREAD`,
`LLM_NUM_GPU` pour changer de modèle ou forcer le CPU).

## Contrat d'intégration

| Élément | Détail |
|---|---|
| `POST /ask` | `{"question": "…" (3 à 500 caractères), "include_alerts": true}` → `answer`, `refused`, `cited`, `sources[]` (`id`, `source`, `section`, `score`, `cited`, `excerpt`), `alerts[]`, `alerts_error`, `model`, `timings_ms` |
| Erreurs | `{code, detail}` : 422 question invalide, 411/413 corps absent ou > 4 Ko, 503 `index_unavailable` / `llm_unavailable` (avec la liste des documents à lire) / `assistant_busy`, 504 `llm_timeout` |
| `GET /health` | **toujours 200** tant que le service répond (healthcheck Docker) ; `status` vaut `ok` et `ready` `true` si Ollama répond, que les deux modèles y sont installés et que l'index est prêt, sinon `degraded` / `false` avec `checks.ollama`, `checks.index` (état, essais, dernière erreur, documents indexés), `checks.alertmanager` |
| `GET /metrics` | `http_requests_total`, `http_request_duration_seconds` (communs), `ops_assistant_questions_total{result}` (answered/refused/error/timeout/busy/unavailable), `ops_assistant_stage_duration_seconds{stage}` (indexing/retrieval/generation), `ops_assistant_index_ready`, `ops_assistant_index_chunks`, `ops_assistant_ollama_up` |
| `GET /` | page de consultation (HTML + JS servis par le service, CSP stricte, aucun appel externe) |
| Journaux | JSON sur stdout (→ Loki), `event_type=assistant_question` avec la question (300 caractères max), le modèle, les fichiers cités et les durées : traçabilité de l'usage |
| LLM | `OLLAMA_BASE_URL`, `LLM_MODEL`, `EMBED_MODEL` (voir `.env.example`, variables `OPS_ASSISTANT_*`) |
| Corpus | `docs/**/*.md` + README d'architecture, montés **en lecture seule** sous `/corpus` |
| Réseaux | `ai` (Ollama conteneurisé) + `mgmt` (publication sur `127.0.0.1:8090`, joint par tunnel SSH ; lecture d'Alertmanager) ; **aucun** accès au socket Docker, à la base, aux secrets ni au moteur de remédiation |

Prometheus ne scrape pas encore l'assistant (fichier partagé `infra/prometheus/prometheus.yml`). Les deux services
partagent le réseau `mgmt`, il suffit d'ajouter :

```yaml
  - job_name: ops-assistant
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

**Choix** :
- **`mistral` dès qu'un GPU est disponible** (PC de délestage IA) : nettement plus juste, jamais d'action prétendue,
  latence de l'ordre de 2 s.
- **`llama3.2:3b` par défaut sur la VM** (6 vCPU, sans GPU) : en CPU, la vitesse de génération baisse à peu près en
  proportion du nombre de paramètres, donc `mistral` y serait environ deux fois plus lent que le 3B. C'est une
  **estimation** : la campagne CPU sur 4 threads, représentative de la VM, n'a pas été menée
  (`run_eval.py --num-gpu 0 --num-thread 4`, à lancer avant la démo). La justesse plus faible du 3B impose de vérifier
  les sources citées.

## Sécurité

- **Aucun outil, aucune action** : le LLM ne produit que du texte, aucune réponse n'est interprétée ni exécutée ; il n'y
  a pas d'appel de fonctions (« tools »). Une injection de consignes (dans une question ou un document) peut au pire
  produire une réponse trompeuse, jamais une action — d'où l'obligation de citer la source, que l'opérateur vérifie.
- **Moindre privilège** : conteneur `read_only`, `tmpfs /tmp`, `cap_drop: ALL`, `no-new-privileges`, utilisateur 10001 ;
  corpus monté `:ro` ; **aucun secret monté** (l'assistant ne peut donc pas en divulguer) ; ni socket Docker, ni réseaux
  `app`/`data`/`obs`.
- **Alertes en lecture seule, désactivées par défaut** : le code sait lire `GET /api/v2/alerts` (réseau `mgmt`, pas besoin
  d'`obs`) et ne transmet au LLM que le nom, la gravité, le domaine, le service, le résumé et l'heure (10 alertes au plus,
  200 caractères par champ). Mais Alertmanager exige désormais le compte `admin`, qui permet aussi de poser des silences
  et donc de masquer une alerte : l'assistant ne reçoit pas ce secret et `OPS_ASSISTANT_ALERTMANAGER_URL` est vide.
  À rebrancher sur une API d'état en lecture seule compatible (moteur de remédiation, dashboard de supervision).
- **Entrées bornées** : question ≤ 500 caractères, corps ≤ 4 Ko (413 sinon), une génération à la fois (503 « occupé »
  au-delà de 20 s d'attente), réponse ≤ 400 jetons, premier jeton attendu 180 s au plus et réponse complète 240 s
  (504 au-delà : chargement à froid d'un 7B en CPU), 32 connexions simultanées au plus.
- **Exposition** : publié uniquement sur `127.0.0.1:8090` de la VM (`MGMT_BIND`), comme les autres interfaces de
  gestion, et joint par tunnel SSH (`ssh -N -L 8090:127.0.0.1:8090 resilience@172.16.147.10`) ; pas
  d'authentification applicative ; en-têtes `nosniff`, `X-Frame-Options: DENY`, CSP stricte sur la page.
- **LLM conteneurisé non publié** : le conteneur `ollama` n'a aucun port publié, seul le réseau `ai` le joint. Sur le
  PC de délestage IA, l'API Ollama (sans authentification) doit être filtrée par pare-feu sur l'IP de la VM.
- **Journaux** : volontairement pas `event_type=dependency_failure` quand Ollama tombe (`llm_unavailable` à la place) :
  la règle SOC `DependencyFailures` déclencherait sinon une alerte critique de disponibilité vers la remédiation.
- **Risques résiduels** : le réseau `mgmt` est partagé avec Prometheus, Loki, Grafana et Alertmanager — un assistant
  compromis pourrait joindre leurs API (dont la création de silences d'Alertmanager) ; `ai` et `mgmt` ne sont pas
  `internal`, donc une sortie Internet reste possible (le code n'en fait aucune, le traçage LangSmith est désactivé).
  En contexte industriel : proxy en lecture seule devant Alertmanager, réseau dédié, authentification de l'interface.

## Limites

- **La justesse dépend du modèle et du corpus** : en relecture, `llama3.2:3b` donne 6 réponses fausses sur 20 (dont
  une requête Loki inventée mais citée) et `mistral` 2 sur 20 (`eval/results/relecture.md`). Les sources citées
  doivent être vérifiées : la page les affiche pour cela.
- **Corpus encore incomplet** : le runbook ne décrit que quatre alertes (réponses souvent « à définir »), le PCA/PRA
  et l'analyse NIS2/DORA sont des plans. Sur ces sujets l'assistant répond « je ne sais pas » ; les deux erreurs
  communes aux modèles (q06, q14) viennent d'informations présentes seulement en liste ou ambiguës dans le corpus.
- **Recherche** : 4 extraits par question ; une information isolée dans une liste (requête Loki du runbook) peut ne
  pas remonter. Une recherche hybride (mots-clés + vecteurs) ou des runbooks rédigés par alerte l'amélioreraient.
- **Latence en CPU seul** : sur la VM (6 vCPU, sans GPU), chaque réponse prend plusieurs dizaines de secondes et
  occupe 4 vCPU (voir les mesures) ; une seule question est traitée à la fois.
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
  tous les modèles ; latence 1 à 2 s avec GPU, non mesurée en CPU.
- **Limites** : un petit modèle peut attacher une citation à une information inventée (relecture obligatoire des
  sources) ; corpus encore mince (runbook limité à quelques alertes) ; recherche purement vectorielle qui manque une
  information isolée dans une liste ; latence CPU sur la VM non mesurée ; pas de contexte d'incident en direct
  (lecture des alertes désactivée faute d'accès en lecture seule à Alertmanager) ; aucune authentification de
  l'interface (accès par tunnel SSH uniquement).
