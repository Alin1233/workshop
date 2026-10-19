# ops-assistant — assistant RAG pour les opérateurs (pilier IA/DATA) — À DÉVELOPPER

Ollama + LangChain, modèle local ≤ 8 milliards de paramètres, recherche documentaire sur `docs/` (procédures, architecture, PCA/PRA).

## Contrat d'intégration

| Élément | Détail |
|---|---|
| LLM | `OLLAMA_BASE_URL` : Ollama du PC Hôte (`http://host.docker.internal:11434`), du PC de délestage IA (`http://<ip>:11434`), ou conteneur `ollama` (`docker compose --profile ai up -d`, `http://ollama:11434`) |
| Corpus | `docs/**/*.md` monté en lecture seule |
| Réseaux | `ai` (+ `mgmt` pour publier l'interface sur 127.0.0.1) ; **aucun** accès au socket Docker, à la base ou au moteur de remédiation |

## À faire
- [ ] Choisir le modèle (ex. `llama3.1:8b`, `qwen2.5:7b`, `mistral:7b`) et l'embedding (`nomic-embed-text`), justifier vs matériel
- [ ] Indexation (découpage, embeddings, base vectorielle locale : Chroma/FAISS) et chaîne RAG avec citations des sources
- [ ] Interface minimale (API + page ou intégration au dashboard de supervision)
- [ ] Optionnel : lecture seule de l'état (alertes Alertmanager) pour contextualiser — jamais d'action. Alertmanager exige
  `admin` / `alertmanager_password`, qui permet aussi de poser des silences : préférer passer par une API d'état en lecture seule.
- [ ] Jeu de questions de test et évaluation des réponses
