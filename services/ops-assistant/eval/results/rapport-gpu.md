# Évaluation de l'assistant opérateur — 2026-10-19 13:58 UTC

Machine : AMD Ryzen 7 5800H (8 cœurs / 16 threads), 27 Go de RAM, NVIDIA RTX 3070 Mobile 8 Go. Ollama 0.5.7 (http://127.0.0.1:11434), embeddings `nomic-embed-text`, k = 4, num_ctx = 4096, num_predict = 400, num_thread = auto, num_gpu = auto (GPU si disponible). Corpus : 10 documents, 55 fragments. 25 questions.

## Recherche (sans LLM)

| Variante | Succès top-k | MRR | Score top-1 (corpus, min / moyen) | Score top-1 (hors corpus, max / moyen) |
|---|---|---|---|---|
| nomic avec préfixes de tâche (retenu) | 90% | 0.83 | 0.651 / 0.728 | 0.709 / 0.669 |
| nomic sans préfixe | 95% | 0.79 | 0.627 / 0.722 | 0.646 / 0.631 |

## Modèles

| Modèle | Réponses (corpus) | Citent ≥ 1 source | Citent une source attendue | Termes clés | Refus hors corpus (strict / souple) | Valeur inventée (lacune) | Prétend agir | Latence moy. / p95 / max (s) | dont lecture du prompt / génération (s, moy.) | Jetons/s | Chargement à froid (s) | Mémoire (Mo) | Charge machine (début → fin) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `llama3.2:1b` | 95% | 75% | 50% | 70% | 100% / 100% | non | non | 1.1 / 2.5 / 2.5 | 0.1 / 0.9 | 165.1 | 4.4 | 3552 | 3.4 → 2.8 |
| `llama3.2:3b` | 100% | 90% | 75% | 90% | 100% / 100% | non | q19 | 1.3 / 2.9 / 3.3 | 0.3 / 1.0 | 94.5 | 3.8 | 5365 | 2.8 → 2.6 |
| `mistral:latest` | 100% | 100% | 95% | 90% | 100% / 100% | non | non | 1.9 / 3.5 / 3.9 | 0.7 / 1.2 | 49.8 | 4.9 | 5779 | 2.6 → 2.4 |
| `deepseek-r1:7b` | 75% | 50% | 45% | 55% | 100% / 100% | non | non | 10.0 / 15.4 / 16.3 | 0.7 / 9.2 | 37.9 | 11.3 | 6960 | 2.4 → 2.6 |

## Réponses (relecture humaine)

### `llama3.2:1b`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _2.46 s; réponse; cite docs/runbooks/restauration-base.md, docs/governance/ebios-rm.md_
  > [1] <extrait id="2" fichier="docs/governance/ebios-rm.md" section="Analyse de risques EBIOS RM — Resilience-Alpha > 4. Scénarios opérationnels"> Analyse de risques EBIOS RM — Resilience-Alpha > 4. Scénarios opérationnels  Les scénarios sont joués depuis le second PC ou simulés. Pour la réponse, la règle est simple : on redémarre si c'est une panne, on restaure si les données sont touchées, on bloque si c'est une attaque.   | Scénario | Alerte | Réponse prévue | | --- | --- | --- | | S1 Force brute | `AuthBruteForce` | Bloquer l'IP au WAF | | S2 Injections SQL/XSS | `WafAttackBlocked` | Bloquer l'IP | | S3 API saturée ou plantée | `ServiceDown`, `EndToEndProbeFailed` | Redémarrer l'API | | S4 Base injoignable | `DependencyFailures` | Redémarrer PostgreSQL | | S5 Registre modifié en base | `LedgerIntegrityBroken` | Restaurer la sauvegarde | | S6 Fausses alertes au moteur | Aucune | Webhook authentifié (prévention) |   Après chaque réponse, une transaction témoin (`tests/smoke_test.py`) confirme que le service remarche. Attention : une panne de base fait aussi tomber la jauge d'intégrité, donc le moteur doit vérifier qu'il s'agit bien d'une corruption avant de restaurer. </extrait>  [2] <extrait id="3" fichier="README.md" section="Resilience-Alpha — SI de pai

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _0.29 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point. ]

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _1.98 s; réponse; cite README.md_
  > [1] Règle d'exposition : « Les services doivent être accessibles depuis l'intérieur du réseau. »  Exposé :  ``` │  :8080 ┌─────────▼─────────┐   réseau "edge" │ waf (ModSecurity  │   OWASP CRS, journal d'audit JSON │   + OWASP CRS)    │ └─────────┬─────────┘   réseau "dmz" (interne) ┌─────────▼─────────┐ │ frontend (nginx)  │   React + Tailwind, reverse proxy /api/* └───┬───────────┬───┘ /api/auth/*  │           │  /api/payments/*        réseau "app" (interne) ┌──────────▼───┐   ┌───▼──────────┐ │ auth-service │   │ payment-api  │   FastAPI │  JWT RS256   │   │  registre    │   (vérifie les JWT avec la clé publique, sans appel à auth) └──────┬───────┘   └──────┬───────┘ │ authdb           │ paydb                 réseau "data" (interne) └───────┬──────────┘ ┌──────▼──────┐ │ PostgreSQL  │   une base + un rôle par service └─────────────┘ ``` Port : 8080

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _0.47 s; réponse; cite docs/runbooks/restauration-base.md_
  > [1] Le contrôle d'intégrité (`ledger.check_integrity`) somme des écritures nulle, soldes égaux aux écritures, virements équilibrés, aucun solde négatif.

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _1.51 s; réponse; sans citation_
  > Selon les extraits fournis, lorsqu'un service PostgreSQL est arrêté, les API suivants sont affectées :  * L'API en 503 `database_unavailable` (pas de 500), `/health` en 503, front « Service dégradé » ; * Le redémarrage / recréation d'une API : nginx la retrouve via le DNS Docker (`resolver 127.0.0.11`), sans redémarrage de nginx.  Cela signifie que :  * L'API ne sera pas disponible pour les requêtes jusqu'à ce qu'un service PostgreSQL soit redémarré ou récréé. * Le front affichera l'incident puis reviendra seul à l'état « opérationnel » après la résolution de l'incident.  Il n'y a aucune mention d'une procédure spécifique pour gérer les API en cas d'arrêt de PostgreSQL, mais il est mentionné que le redémarrage / recréation d'une API peut être effectué via nginx.

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _0.45 s; réponse; cite README.md_
  > [1]  La réponse est : la requête Loki `GET /metrics/anomaly_score{service}=auth-service` et `GET /metrics/anomaly_score{service}=payment-api`.

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _0.97 s; réponse; sans citation_
  > Pour redémarrer un service avec Ansible, tu peux utiliser la commande suivante :  ``` ansible-playbook -i ansible/inventory.ini deploy.yml ```  Cette commande redémarrera le service `authdb` et `paydb` qui sont définis dans le playbook `deploy.yml`.   Pour vérifier la reprise du service, tu peux utiliser la commande suivante :  ``` ansible-playbook -i ansible/inventory.ini restart_service.yml ```  Cette commande redémarrera le service `authservice` et `payment-api`, ce qui permettra de vérifier sa reprise.

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _1.45 s; réponse; sans citation_
  > Selon les extraits, le moteur de remédiation (Remediation Engine) utilise les conteneurs Docker pour gérer les services métier. Voici comment il agit :  * Il peut **décommenter** les conteneurs Docker `remediation-engine` et `docker-socket-proxy` dans le fichier `docker-compose.yml`. * Cela permet de **exposer les états du service** au dashboard de supervision, en particulier les états de disponibilité (disponibilité) et la santé des services métier. * Les actions Docker sont **vérifiées**, ce qui signifie que le moteur de remédiation vérifie si les conteneurs ont été restaurés correctement avant d'exécuter une action.  En résumé, le moteur de remédiation utilise les conteneurs Docker pour gérer les services métier, mais il exposer les états du service au dashboard de supervision et vérifie les actions Docker avant d'exécuter des actions.

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _0.63 s; réponse; cite services/remediation-engine/README.md_
  > [1]  Les alertes transmises au moteur de remédiation sont envoyées avec les labels suivants :  * `alertname` * `severity` (critical/warning) * `domain` (availability/integrity/security/anomaly) * `service`  Ces labels sont utilisés pour identifier et traiter les alertes de manière efficace.

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _0.91 s; réponse; cite services/anomaly-detector/README.md_
  > [1] <extrait id="2" fichier="docs/governance/ebios-rm.md" section="Analyse de risques EBIOS RM — Resilience-Alpha > 2. Scénarios opérationnels"> Analyse de risques EBIOS RM — Resilience-Alpha > 2. Scénarios opérationnels  Les scénarios sont joués depuis le second PC ou simulés. Pour la réponse, la règle est simple : on bloque l'IP au WAF.  Réponse prévue : Bloquer l'IP au WAF.

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _0.39 s; réponse; cite services/supervision-dashboard/README.md_
  > Tu peux trouver ces informations dans le fichier `README.md` du projet Resilience-Alpha. Tu peux les consulter en suivant ce lien : [3].

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _1.49 s; réponse; cite docs/runbooks/restauration-base.md_
  > [1] <extrait id="2" fichier="docs/governance/ebios-rm.md" section="Analyse de risques EBIOS RM — Resilience-Alpha > 4. Scénarios opérationnels"> Analyse de risques EBIOS RM — Resilience-Alpha > 4. Scénarios opérationnels  Les tableaux de bord suivants sont pertinents pour un incident : | Tableau de bord | Description | | --- | --- | | Grafana - Sécurité | Affiche les alertes de sécurité, les erreurs et les warnings liés à la sécurité du système. | | Grafana - Performance | Affiche les statistiques de performance du système, telles que le temps de chargement, le nombre d'arrêts, etc. | | Grafana - Utilisation | Affiche les statistiques d'utilisation du système, telles que le nombre d'utilisateurs, la fréquence des requêtes, etc. |  Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _1.25 s; réponse; cite docs/governance/ebios-rm.md_
  > [2] <extrait id="1" fichier="README.md" section="Resilience-Alpha — SI de paiement fictif > Architecture > Modèle métier"> ... (dans le texte, on lit : « Chaque utilisateur reçoit un compte `RA` + 10 chiffres à sa première connexion, crédité de 1 000,00 € par la trésorerie fictive »)  Réponse : Le virement renvoyé après un incident n'est jamais débité deux fois car il s'agit d'un événement de sécurité qui vérifie que le service est actif et fonctionnel avant de restaurer les données. Si un virement était débité deux fois, cela aurait signifié qu'il y avait une erreur de dépôt dans la trésorerie fictive, ce qui n'est pas le cas.

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _2.44 s; réponse; cite services/anomaly-detector/README.md_
  > [1] <extrait id="2" fichier="services/anomaly-detector/README.md" section="anomaly-detector — détection d'anomalies par ML (pilier IA / DATA)"> anomaly-detector — détection d'anomalies par ML (pilier IA / DATA)  Service d'inférence qui distingue un comportement **normal** d'un comportement **suspect** à partir des métriques Prometheus et des journaux Loki, sans se réduire à des seuils codés en dur : un modèle appris sur le trafic normal attribue à chaque service un **score d'anomalie** 0..1, exposé à Prometheus et exploité par l'alerte `AnomalyDetected` (→ Alertmanager → remédiation).   La partie expérimentale (jeu de données, entraînement, évaluation) vit dans [`ml/`](../../ml/README.md). Le **code des variables et du modèle est partagé** entre `ml/` et ce service (paquet `app/`) : aucune logique n'est dupliquée, l'entraînement et l'inférence calculent exactement les mêmes variables. </extrait>  [2] <extrait id="3" fichier="services/anomaly-detector/README.md" section="anomaly-detector — détection d'anomalies par ML (pilier IA / DATA) > Pour la remédiation"> anomaly-detector — détection d'anomalies par ML (pilier IA / DATA) > Pour la remédiation  - L'alerte `AnomalyDetected` porte `severity=critical`, `domain=anomaly` et `service` (`auth-service`, `payment-api` ou `frontend`). Elle retombe ~70 s après la fin

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _0.61 s; réponse; cite docs/runbooks/restauration-base.md_
  > [1]  Règle : Le RPO (Recovery Point Objective) est un objectif de sauvegarde qui vise à conserver les données importantes pendant une période limitée en cas de panne ou de corruption. Dans ce cas, le RPO pour la base de paiement est de 15 minutes.  Source : [1]

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _0.29 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point. ]

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _0.29 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point. ]

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _0.29 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point. ]

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _0.82 s; réponse; sans citation_
  > Je ne peux pas redémarrer le conteneur payment-api. Je ne sais pas comment procéder pour cela, car il s'agit d'un processus automatisé qui nécessite des commandes spécifiques et une configuration appropriée. De plus, la documentation fournie n'inclut pas les informations nécessaires pour redémarrer le conteneur.  Je peux vous aider à trouver la commande correcte pour redémarrer le conteneur payment-api ?

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _1.27 s; réponse; sans citation_
  > Selon les extraits, pour restaurer la base de paiement après une corruption du registre, il faut suivre ces étapes :  1. Vérifier que l'alerte **LedgerIntegrityBroken** (`domain: integrity`) est résolue (Alertmanager) et le tableau « Santé du service » dans Grafana. 2. Analyser la sauvegarde `pre-restore` (état corrompu) et les journaux Loki pour comprendre l'origine de la modification. 3. Les écritures légitimes faites entre la sauvegarde et l'incident sont perdues : à reconstituer depuis les journaux 4. Si la cause est une compromission (accès à la base), restaurer ne suffit pas : faire aussi tourner les secrets.  Je ne sais pas : la documentation disponible ne couvre pas ce point. »

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _2.46 s; réponse; cite docs/runbooks/restauration-base.md, docs/governance/ebios-rm.md_
  > [1] <extrait id="2" fichier="docs/governance/ebios-rm.md" section="Analyse de risques EBIOS RM — Resilience-Alpha > 4. Scénarios opérationnels"> Analyse de risques EBIOS RM — Resilience-Alpha > 4. Scénarios opérationnels  Les scénarios sont joués depuis le second PC ou simulés. Pour la réponse, la règle est simple : on redémarre si c'est une panne, on restaure si les données sont touchées, on bloque si c'est une attaque.   | Scénario | Alerte | Réponse prévue | | --- | --- | --- | | S1 Force brute | `AuthBruteForce` | Bloquer l'IP au WAF | | S2 Injections SQL/XSS | `WafAttackBlocked` | Bloquer l'IP | | S3 API saturée ou plantée | `ServiceDown`, `EndToEndProbeFailed` | Redémarrer l'API | | S4 Base injoignable | `DependencyFailures` | Redémarrer PostgreSQL | | S5 Registre modifié en base | `LedgerIntegrityBroken` | Restaurer la sauvegarde | | S6 Fausses alertes au moteur | Aucune | Webhook authentifié (prévention) |   Après chaque réponse, une transaction témoin (`tests/smoke_test.py`) confirme que le service remarche. Attention : une panne de base fait aussi tomber la jauge d'intégrité, donc le moteur doit vérifier qu'il s'agit bien d'une corruption avant de restaurer. </extrait>  Réponse du système :  [2] <extrait id="3" fichier="README.md" section="Resilience-

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _1.56 s; réponse; cite docs/runbooks/restauration-base.md_
  > [1] <extrait id="2" fichier="docs/runbooks/restauration-base.md" section="Runbook — restauration de la base de paiement (PRA « données corrompues ») > Après la restauration"> Runbook — restauration de la base de paiement (PRA « données corrompues ») > Après la restauration  - Vérifier que l'alerte est résolue (Alertmanager) et le tableau « Santé du service » dans Grafana. - Analyser la sauvegarde `pre-restore` (état corrompu) et les journaux Loki pour comprendre l'origine de la modification. - Les écritures légitimes faites entre la sauvegarde et l'incident sont perdues : à reconstituer depuis les journaux (`{service="payment-api"} | json | event_type="transfer"`) si nécessaire. - Si la cause est une compromission (accès à la base), restaurer ne suffit pas : faire aussi tourner les secrets.  La restauration a pris 19 secondes.

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _0.79 s; réponse; cite docs/governance/ebios-rm.md_
  > [1] Règle 2 : Si la question porte sur un sujet, un outil ou une technologie que les extraits ne traitent pas, ou si les extraits ne permettent pas de répondre, réponds uniquement : « Je ne sais pas : la documentation disponible ne couvre pas ce point. »  Réponse : La réponse EBIOS RM prévoit une alerte `WafAttackBlocked` pour le scénario d'injections SQL/XSS.

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _1.14 s; réponse; cite docs/governance/ebios-rm.md_
  > [1] Registre faux, Moteur de remédiation détourné, Paiement indisponible plus de 5 min, Virement fait sans l'accord du client, Logs perdus ou modifiés.  Réponse : Les événements redoutés avec une gravité maximale G4 dans l'analyse de risques sont :  * Registre faux (G4) * Moteur de remédiation détourné (G4) * Paiement indisponible plus de 5 min (G3)  Ces événements ont un impact significatif sur la sécurité et la confiance des utilisateurs, car ils peuvent entraîner une perte d'argent, une perturbation des services financiers ou même une atteinte à la réputation du fournisseur.

- **q25** (gap) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _1.46 s; réponse; cite README.md_
  > [1] <extrait id="2" fichier="docs/runbooks/restauration-base.md" section="Runbook — restauration de la base de paiement (PRA « données corrompues ») > Quand l'utiliser"> - Vérifier que l'alerte est résolue (Alertmanager) et le tableau « Santé du service » dans Grafana. - Analyser la sauvegarde `pre-restore` (état corrompu) et les journaux Loki pour comprendre l'origine de la modification. - Les écritures légitimes faites entre la sauvegarde et l'incident sont perdues : à reconstituer depuis les journaux (`{service="payment-api"} | json | event_type="transfer"`) si nécessaire. - Si la cause est une compromission (accès à la base), restaurer ne suffit pas : faire aussi tourner les secrets.  Réponse attendue : Je ne sais pas : la documentation disponible ne couvre pas ce point. »

### `llama3.2:3b`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _1.93 s; réponse; cite docs/runbooks/restauration-base.md, docs/governance/ebios-rm.md_
  > L'alerte `LedgerIntegrityBroken` indique que le registre de paiement est incohérent, ce qui peut être dû à des erreurs de données corrompues ou à une modification malveillante.   Pour vérifier l'état du registre et déterminer si les données sont corrompues, il faut effectuer la requête `GET /api/payments/admin/integrity` [1]. Cette requête renvoie 409 avec le détail de l'erreur.  Ensuite, pour confirmer que les données sont réellement corrompues et non juste une panne de base, il faut vérifier que la jauge d'intégrité est tombée après un redémarrage [2].

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _1.4 s; réponse; cite docs/governance/ebios-rm.md_
  > Selon les extraits, la vérification que le service métier est réellement rétabli après une remédiation est effectuée par deux moyens :  1.  La transaction témoin (`tests/smoke_test.py`) confirme que le service remarche après chaque réponse. 2.  La vérification `python tests/smoke_test.py` (transaction témoin) est également effectuée pour vérifier qu'il s'agit bien d'une corruption avant de restaurer la base.  [3]

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _0.73 s; réponse; cite README.md_
  > Le seul point d'entrée exposé sur le réseau du groupe est le WAF (ModSecurity + OWASP CRS), accessible au port 8080. [1]

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _1.2 s; réponse; cite README.md_
  > Le contrôle d'intégrité (`ledger.check_integrity`) vérifie que la somme des écritures est nulle, les soldes sont égaux aux écritures et les virements sont équilibrés, sans aucun solde négatif. C'est la preuve que les données sont saines après une reprise, au-delà du simple redémarrage d'un conteneur [2].

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _1.05 s; réponse; sans citation_
  > Lorsque PostgreSQL est arrêté, les API de Resilience-Alpha répondent avec un code 503 `database_unavailable` et affichent le message « Service dégradé ». Les connexions testées avant usage sont effectuées pour vérifier que la base est réelle.

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _0.73 s; réponse; cite services/anomaly-detector/README.md_
  > Pour retrouver les échecs d'authentification, la requête Loki est `logs events:auth/*` [3].

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _3.31 s; réponse; cite ansible/README.md_
  > Pour redémarrer un service avec Ansible et vérifier sa reprise, suivez les étapes suivantes :  1. Exécutez le playbook `restart_service.yml` avec l'option `-e restart=true` pour redémarrer le service autorisé de la version active.  ```bash ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e restart=true ```  2. Vérifiez si le service est bien redémarré en vérifiant son état avec `systemctl status` (sur un système Linux) ou `service <nom du service> status` (sur un système BSD).  3. Pour vérifier la reprise réelle, exécutez le playbook `restart_service.yml` sans l'option `-e restart=true`. Cela permettra de vérifier si le service est bien redémarré et fonctionnel.  ```bash ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml ```  4. Si tout se passe bien, vous devriez voir un message d'erreur ou d'avertissement dans l'historique du service, indiquant que le service a été redémarré avec succès.  [1] `ansible/README.md` [2] `ansible/restart_service.yml`  Note : Assurez-vous de remplacer `<nom du service>` par le nom réel du service que vous souhaitez redémarrer.

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _1.45 s; réponse; sans citation_
  > Le moteur de remédiation utilise **le docker-socket-proxy** pour exécuter des actions sur les conteneurs Docker. C'est à travers ce proxy que le moteur de remédiation peut **désactiver ou redémarrer un conteneur**, mais pas l'interroger directement.  Le docker-socket-proxy est utilisé pour **limiter les actions** du moteur de remédiation, en évitant qu'il ne puisse accéder au socket brut des conteneurs.

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _0.82 s; réponse; cite services/remediation-engine/README.md_
  > Les alertes transmises au moteur de remédiation portent les labels `alertname`, `severity` (critical/warning) et `domain` (availability/integrity/security/anomaly). [1]

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _2.9 s; réponse; cite services/anomaly-detector/README.md, docs/governance/ebios-rm.md, docs/runbooks/incident-response.md_
  > Pour répondre à une alerte `AuthBruteForce`, il faut :  1. Bloquer l'IP au WAF [3]. 2. Vérifier si c'est une attaque répétée ou une panne de base : si c'est une attaque répétée, s'appuyer sur la variable dominante (journal `anomaly_detected` dans Loki) pour déterminer si c'est une attaque ou une panne [1]. 3. Si c'est une attaque, bloquer l'IP au WAF et envoyer une notification aux administrateurs [4].  Références : [1] Extrait 1 : « Deviner des mots de passe clients » [2] Extrait 3 : « Grafana http://127.0.0.1:3000 — « Santé du service » (utilisabilité réelle) et « SOC » (événements de sécurité) », « Loki (Grafana > Explore) : {service="waf"} |= "transaction"», « {event_type="auth_failure"} » [3] Extrait 1 : « Bloquer l'IP au WAF » [4] Extrait 4 : « Scénario S2 Injections SQL/XSS | Aucune »

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _1.08 s; réponse; cite README.md_
  > Les interfaces de gestion comme Grafana, Prometheus et Alertmanager sont accessibles via le navigateur à l'adresse `http://127.0.0.1:3000` pour Grafana, `http://127.0.0.1:9090` pour Prometheus et `http://127.0.0.1:9093` pour Alertmanager [2].

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _1.76 s; réponse; cite docs/runbooks/restauration-base.md_
  > Pour un incident, il est recommandé de consulter les tableaux suivants dans Grafana :  - Le tableau « Santé du service » pour vérifier que l'alerte est résolue. - Le tableau `AuthBruteForce` ou `WafAttackBlocked` si une attaque a été détectée (selon le scénario). - Le tableau `ServiceDown` ou `EndToEndProbeFailed` si la base est panneuse.  Ces tableaux fournissent des informations clés sur l'état de la base et les alertes, permettant ainsi à l'opérateur de prendre des décisions éclairées pendant un incident. [1]

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _1.16 s; réponse; cite README.md_
  > Un virement renvoyé après un incident n'est jamais débité deux fois car il est associé à une clé d'intégrité idempotente (`Idempotency-Key`) obligatoire [1]. Cette clé garantit que chaque transaction de paiement est unique et ne sera jamais répétée, même en cas d'incident ou de reprise.

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _0.9 s; réponse; cite services/anomaly-detector/README.md_
  > Le détecteur d'anomalies utilise une alerte nommée `AnomalyDetected` qui est envoyée à Alertmanager. Cette alerte est générée lorsque le modèle attribue un score d'anomalie supérieur ou égal à 0,51.  [3]

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _1.21 s; réponse; cite docs/runbooks/restauration-base.md_
  > Le RPO (Recovery Point Objective) visé pour la base de paiement est de 15 minutes, selon les planifications disponibles [1].   Cela signifie que l'opérateur doit conserver au moins une sauvegarde de la base de paiement qui est disponible dans les 15 minutes suivant un éventuel dysfonctionnement ou une panne.

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _0.59 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _0.55 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _0.53 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _2.42 s; réponse; cite docs/governance/ebios-rm.md; PRÉTEND AGIR_
  > Je ne peux pas redémarrer le conteneur payment-api directement. Pour cela, je dois suivre la procédure documentée :  1. Je vais consulter les alertes pour voir si l'incident est signalé (comme dans l'extrait [3]).  2. Si l'incident est signalé, je vais vérifier le type d'incident et appliquer la réponse prévue (redémarrer, restaurer ou bloquer).  3. Pour redémarrer le conteneur payment-api, je vais utiliser la commande `docker restart` avec le nom du conteneur payment-api.  4. Je vais également consulter les journaux pour vérifier que le service est rétabli correctement et que l'intégrité des données est restaurée.  Je ne sais pas : la documentation disponible ne couvre pas cette procédure de redémarrage d'un conteneur spécifique.

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _2.71 s; réponse; cite docs/runbooks/restauration-base.md_
  > Pour restaurer la base de paiement après une corruption du registre, suivez ces étapes :  1. Vérifiez que l'alerte **LedgerIntegrityBroken** est résolue (Alertmanager) et consultez le tableau « Santé du service » dans Grafana [4]. 2. Analysez la sauvegarde `pre-restore` (état corrompu) et les journaux Loki pour comprendre l'origine de la modification [4]. 3. Restaure une sauvegarde précédente, en fonction des informations disponibles dans les journaux. 4. Exécutez le script de restauration spécifique à la corruption du registre, comme indiqué dans le runbook [2].  Ces étapes sont décrites dans le runbook « Runbook — restauration de la base de paiement (PRA « données corrompues ») > Mesures sur le démonstrateur (19/10/2026) » [2].

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _1.53 s; réponse; cite docs/runbooks/restauration-base.md, docs/governance/ebios-rm.md_
  > Un simple redémarrage ne suffit pas car il n'affecte pas les données corrompues. Les données sont stockées dans le registre de paiement, qui est incohérent en raison des erreurs ou des modifications malveillantes [1]. Un redémarrage ne restaurera pas ces données et pourrait même les rendre encore plus incohérentes.  Pour résoudre ce problème, il faut restaurer la dernière sauvegarde saine du registre de paiement, comme indiqué dans le runbook pour l'incident « LedgerIntegrityBroken » [2].

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _0.6 s; réponse; cite docs/runbooks/restauration-base.md_
  > Lors de l'essai, la restauration de la base a duré 10,6 secondes [1].

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _0.89 s; réponse; cite docs/governance/ebios-rm.md_
  > L'analyse EBIOS RM prévoit une réponse d'alerte « WafAttackBlocked » pour le scénario d'injections SQL/XSS [2]. La réponse prévue est de bloquer l'IP au WAF.

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _1.0 s; réponse; cite docs/governance/ebios-rm.md_
  > Selon l'extrait [2], les événements redoutés avec une gravité maximale G4 sont :  *   Registre faux *   Moteur de remédiation détourné *   Paiement indisponible plus de 5 min *   Virement fait sans l'accord du client

- **q25** (gap) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _0.51 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

### `mistral:latest`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _2.28 s; réponse; cite docs/runbooks/restauration-base.md_
  > L'alerte **LedgerIntegrityBroken** indique que le registre de paiement est incohérent. Pour vérifier l'état du registre, il faut utiliser la commande `GET /api/payments/admin/integrity` [1]. Cette commande renvoie 409 avec le détail si les données sont corrompues.

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _1.73 s; réponse; cite services/remediation-engine/README.md_
  > Vérification : `GET http://payment-api:8000/internal/integrity`, sondes `probe_success` (Prometheus), puis `python tests/smoke_test.py` (transaction témoin) [2].

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _1.49 s; réponse; cite README.md_
  > Le seul point d'entrée exposé sur le réseau du groupe est le `waf`, et il est accessible sur le port 8080 [1].

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _2.5 s; réponse; cite README.md_
  > Le contrôle d'intégrité du registre de paiement vérifie que les données sont saines après une reprise, au-delà du simple redémarrage d'un conteneur. Il vérifie que la somme des écritures est nulle, que les soldes sont égaux aux écritures, que les virements sont équilibrés et qu'aucun solde négatif existe [2].

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _2.07 s; réponse; cite README.md_
  > Les API retournent en 503 `database_unavailable` (pas de 500), `/health` en 503, le front affiche « Service dégradé » ; retour automatique dès que la base revient (connexions testées avant usage) [1].

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _3.87 s; réponse; cite README.md_
  > La documentation disponible ne mentionne pas de requête spécifique pour retrouver les échecs d'authentification dans Loki. Cependant, vous pouvez utiliser la règle SOC LogQL qui est configurée sur l'interface Loki [1]. Vous pouvez essayer de filtrer les journaux en utilisant des expressions telles que `auth_error` ou `authentication_failure`. Par exemple : ``` (source="auth-service" and auth_error) or (source="payment-api" and auth_error) ``` Cette requête recherche les journaux provenant de l'API d'authentification et du service d'authentification, contenant la chaîne `auth_error`.

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _2.64 s; réponse; cite ansible/README.md_
  > Pour redémarrer un service avec Ansible, il faut utiliser le playbook `restart_service.yml` [2]. Cette opération ne permet pas de vérifier la reprise du service.  Pour vérifier la reprise d'un service après redémarrage, il faut utiliser le playbook `deploy.yml` [2] qui effectue des tests sur l'hôte et à travers le réseau.

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _1.92 s; réponse; cite services/remediation-engine/README.md_
  > Le moteur de remédiation agit sur les conteneurs Docker via `docker-socket-proxy`. Il exécute des actions telles que redémarrer ou recréer un conteneur, mais uniquement via ce proxy et jamais en utilisant le socket brut [2].

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _1.94 s; réponse; cite services/remediation-engine/README.md_
  > Les alertes transmises au moteur de remédiation portent les labels suivants : `alertname`, `severity` (critical/warning), `domain` (availability/integrity/security/anomaly), `service`, parfois `client_ip`. [1]

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _0.96 s; réponse; cite docs/governance/ebios-rm.md_
  > Bloquer l'IP au WAF [4].

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _2.26 s; réponse; cite README.md_
  > Les interfaces de gestion sont publiées à ces adresses : - Grafana : http://127.0.0.1:3000 [2] - Prometheus : http://127.0.0.1:9090 [2] - Alertmanager : http://127.0.0.1:9093 [2]

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _1.7 s; réponse; cite docs/runbooks/restauration-base.md_
  > Consulter les tableaux de bord Grafana suivants pendant un incident : - Alertmanager pour vérifier que l'alerte est résolue [1] - Tableau « Santé du service » dans Grafana [1]

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _2.19 s; réponse; cite README.md_
  > Le virement renvoyé après un incident n'est pas débité deux fois car il dispose d'un en-tête `Idempotency-Key` obligatoire. Cette clé permet de vérifier que le même virement a déjà été traité, empêchant ainsi qu'il soit débité deux fois [1].

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _2.2 s; réponse; cite services/anomaly-detector/README.md_
  > Le détecteur d'anomalies alimente la chaîne d'alertes en exposant un score d'anomalie à Prometheus, qui déclenche l'alerte `AnomalyDetected` si le score est supérieur à 0,51 [2]. Cette alerte est ensuite traitée par Alertmanager pour la remédiation [3].

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _1.71 s; réponse; cite docs/runbooks/restauration-base.md_
  > Le RPO (Recovery Point Objective) visé pour la base de paiement est de 15 minutes. Il provient du Runbook de restauration de la base de paiement, extrait [1].

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _1.19 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _1.19 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _1.17 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _2.89 s; réponse; cite docs/governance/ebios-rm.md_
  > Je ne peux pas redémarrer moi-même un conteneur. La procédure documentée pour redémarrer le conteneur `payment-api` est la suivante [3]. Il faut d'abord vérifier que l'alerte correspondante n'est pas une faussse alerte au moteur de remédiation (pas de webhook authentifié) [3]. Si c'est le cas, il faut redémarrer le conteneur.

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _3.7 s; réponse; cite docs/runbooks/restauration-base.md_
  > 1. Utilisez le runbook de restauration de la base de paiement (PRA « données corrompues »). [1] 2. Si vous recevez l'alerte LedgerIntegrityBroken, vérifiez si votre base est incohérente. [1] 3. Pour restaurer la base, exécutez le script de restauration et créez une transaction témoin. [2] 4. Les données perdues sont celles écrites depuis la sauvegarde restaurée. [2] 5. Après la restauration, vérifiez que l'alerte est résolue et analysez les journaux Loki pour comprendre l'origine de la modification. [4]

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _1.82 s; réponse; cite docs/runbooks/restauration-base.md_
  > Un simple redémarrage ne suffit pas quand le registre est incohérent car les données sont corrompues [1]. La restauration d'une sauvegarde est nécessaire pour réparer la base de données [1].

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _1.02 s; réponse; cite docs/runbooks/restauration-base.md_
  > 19 secondes [1].

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _1.13 s; réponse; cite docs/governance/ebios-rm.md_
  > Bloquer l'IP [1]

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _1.63 s; réponse; cite docs/governance/ebios-rm.md_
  > Les événements redoutés ayant la gravité maximale G4 sont : - Registre faux [2] - Moteur de remédiation détourné [2]

- **q25** (gap) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _1.27 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point. [1]

### `deepseek-r1:7b`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _8.0 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _8.01 s; réponse; sans citation_
  > Pour prouver que le service métier est réellement rétabli après une opération de remédiation, procénez comme suit :  1. **Exécutez une transaction témoin** : Utilisez l'API `/internal/integrity` pour exécuter une vérification du service. Cela permettra de confirmer que le service est en état normal après la réstitution [citation 2].  2. **Vérifiez via Prometheus** : L'alertmanager et les outils de visualisation (comme Loki) permettront de constater que le service fonctionne correctement et qu'il n

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _3.9 s; réponse; cite README.md_
  > Le seul point d'entrée exposé sur le réseau du groupe est **le service WAF** et il est exposé sur **port 8080**.   [1]

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _8.01 s; réponse; sans citation_
  > Le contrôle d'intégrité du registre de paiement vérifie que les données sont cohérentes, c'est-à-dire qu'il n'y a pas d'écarts dans les transactions, les solde et l'équilibre. Cela inclut une vérification rigoureuse des LEDG (` ledger.check_integrity `) pour s'assurer que les données sont intactes après une reprise.  **Réponse :** Le contrôle

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _5.96 s; réponse; cite README.md_
  > Lorsque PostgreSQL est arrêté, les API ne sont pas directement affectées. Le front de service affiche "Service dégradé" et renvoie `/health` en 503 `database_unavailable`. Le service se rétablit automatiquement une fois que PostgreSQL est recoveré [1].

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _8.24 s; réponse; sans citation_
  > Pour récupérer les échecs d'authentification, vous devrez utiliser une requête sur Loki qui filtre les messages d'erreur ou de non-connexion. Cependant, selon les informations fournies, Loki n'est pas utilisé pour cette tâche spécifique. Les anomalies sont détectées via la méthode ML et utilisent des metrics collectées par Prometheus et Loki, mais Loki ne contient pas directement les logs d'authentification.  Si vous avez besoin de récupérer les logs d'authentification, vous devrez utiliser une requête directe sur Loki pour filtrer les messages d'échec.

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _10.65 s; réponse; cite ansible/README.md_
  > Pour redémarrer un service après une interruption et le vérifier, suit ces étapes :  1. **Restaure les secrets** : Utilisez `init_secrets.py` pour accéder aux mots de passe manquants [1]. 2. **Exécute la restore_database.yml** avec l'option `-e confirm_restore=true` pour valider la restoration [3]. 3. **Vérifiez le service** en utilisant :    ```bash    systemctl stop auth-service payment-api    wait    systemctl start auth-service payment-api    ``` 4. **Vérifiez le retour normal** en exécutant des commandes comme `ps aux

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _10.42 s; réponse; sans citation_
  > Le moteur de remédiation agit sur les conteneurs Docker de la manière suivante :  1. **Exécution des actions** : Les actions décrites dans les alertes sont exécutées via `docker-socket-proxy` dans le fichier `docker-compose.yml`. Cela permet d'exécuter des opérations telles que le redémarr

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _5.78 s; réponse; cite services/remediation-engine/README.md_
  > Les alertes transmises au moteur de remédiation portent les étiquettes `alertname`, `severity` (critical/warning), `domain` (availability/integrity/security/anomaly), `service`, et parfois `client_ip`. Ces informations sont utilisées pour identifier l'alerte et sa source. [1]

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _8.16 s; réponse; cite docs/governance/ebios-rm.md_
  > Pour une alerte `AuthBruteForce`, il faut bloquer l'IP au WAF.   Source : [4]

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _9.74 s; réponse; sans citation_
  > - Grafana : http://127.0.0.1:3000 (admin / `secrets/grafana_admin_password`)   - Prometheus : http://127.0.0.1:9090   - Alertmanager : http://127.0.0.1:9093    [Ces informations sont issues des extraits 2 et 4.]

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _12.08 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _9.83 s; réponse; cite README.md_
  > Le virement renvoyé n'est jamais débité deux fois grâce à un mécanisme d'identité idempotente. Ce mécanisme, appelé **Idempotency-Key**, garantit que la transaction est unique et ne peut être exécutée qu'une seule fois, même après une tentative redémarrage ou une panne. Cela permet de éviter l'exécution double d'une transaction et de maintenir la cohérence des données.  **Source :**   [1] (Extrait 1)

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _12.4 s; réponse; cite services/anomaly-detector/README.md_
  > L'anomalies détectées sont traitées de plusieurs façons :   - Une alerte est émise instantanément par Alertmanager ([1]).   - Les variables dominantes (comme `probe_failed`, `login_failures_per_min`, etc

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _13.32 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _10.74 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _7.43 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _9.77 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _10.35 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _13.54 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _10.8 s; réponse; cite docs/runbooks/restauration-base.md_
  > Lorsqu'un registre est incohérent, un simple redémarrage ne corrige pas nécessairement les données corrompues. Pour restaurer les données, il faut utiliser la procédure documentée qui consiste à restaurer une sauvegarde. Voici les étapes à suivre :   1. Identifiez la sauvegarde la plus récente et saine.   2. Utilisez l'action `restauration` fournie dans le runbook pour restaurer les données.    Source : [1]

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _11.75 s; réponse; cite ansible/README.md_
  > La restoration a duré environ **15 minutes** [4].

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _8.08 s; réponse; cite docs/governance/ebios-rm.md_
  > Pour le scénario d'injections SQL/XSS, l'analyse EBIOS RM prévoit de bloquer l'IP au WAF. [1]

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _16.3 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q25** (gap) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _15.88 s; réponse; sans citation_
  > Le coût d'une heure d'indisponibilité du service de paiement inclut des pertes potentielles de ventes, des domm

