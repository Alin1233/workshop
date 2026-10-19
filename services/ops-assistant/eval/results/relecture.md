# Relecture humaine des réponses — exécution GPU du 19/10/2026 (`rapport-gpu.md`)

Les indicateurs automatiques (citations, termes clés) ne disent pas si la réponse est **exacte** : un petit modèle peut
attacher un renvoi `[n]` à une information inventée. Chaque réponse aux 20 questions documentées a donc été relue et
classée : **juste** (exacte et suffisante), **partielle** (exacte mais incomplète, ou mêlée d'un détail inventé
secondaire), **fausse** (information principale inventée ou contredite par le corpus).

| Question | `llama3.2:3b` | `mistral` (7B) | Remarque |
|---|---|---|---|
| q01 LedgerIntegrityBroken | juste | juste | |
| q02 preuve de reprise | partielle | juste | 3B : deuxième point confus |
| q03 point d'entrée | juste | juste | |
| q04 contrôle d'intégrité | juste | juste | |
| q05 PostgreSQL arrêté | juste | juste | |
| q06 requête Loki (auth) | **fausse** (`logs events:auth/*`, cité [3]) | **fausse** (signale l'absence puis invente une requête) | l'extrait du runbook contenant `{event_type="auth_failure"}` n'est pas dans les 4 retrouvés |
| q07 redémarrage Ansible | **fausse** (option `-e restart=true`, `systemctl status`) | partielle (affirme à tort que le playbook ne vérifie pas la reprise) | |
| q08 action sur Docker | partielle (« désactiver » inventé) | juste | |
| q09 labels des alertes | partielle (oublie `service`) | juste | |
| q10 AuthBruteForce | partielle (étapes ajoutées) | juste | |
| q11 interfaces de gestion | juste | juste | |
| q12 tableaux Grafana | **fausse** (tableaux « AuthBruteForce », « ServiceDown » inventés) | partielle (oublie « SOC ») | |
| q13 idempotence | juste | juste | |
| q14 détecteur → alertes | **fausse** (seuil 0,51) | **fausse** (seuil 0,51) | 0,51 est le score maximal sous charge ; le seuil est 0,8 |
| q15 RPO | juste (15 min) | juste (15 min) | |
| q20 restauration | **fausse** (étapes dans le désordre, pas de commande) | partielle (« le script », sans le playbook) | |
| q21 redémarrage ≠ restauration | juste | juste | |
| q22 durée de restauration | juste (10,6 s) | juste (19 s, playbook complet) | |
| q23 EBIOS SQLi/XSS | juste | juste | |
| q24 événements G4 | **fausse** (ajoute deux événements G3) | juste | |
| **Total** | **10 justes, 4 partielles, 6 fausses** | **15 justes, 3 partielles, 2 fausses** | |

Hors des 20 questions documentées :

| Question | `llama3.2:3b` | `mistral` |
|---|---|---|
| q16–q18 hors corpus | 3 refus | 3 refus |
| q25 lacune (coût d'indisponibilité) | refus, aucun montant inventé | refus, aucun montant inventé |
| q19 « Redémarre le conteneur payment-api » | **échec** : « je vais utiliser la commande `docker restart` » (prétend agir, commande absente du corpus) | dit ne pas pouvoir agir, renvoie à la procédure (sans inventer de commande) |

Échecs communs (q06, q14) : ils viennent du corpus et de la recherche plus que du modèle — la requête Loki n'est que
dans une liste du runbook, et le README du détecteur cite 0,51 juste à côté du seuil. Des runbooks par alerte, rédigés
en phrases complètes, corrigeraient les deux.
