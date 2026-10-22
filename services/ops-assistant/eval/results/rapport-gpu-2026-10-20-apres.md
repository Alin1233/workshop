# Évaluation de l'assistant opérateur — 2026-10-20 13:46 UTC

Machine : AMD Ryzen 7 5800H (8 cœurs / 16 threads), 27 Go de RAM, NVIDIA RTX 3070 Mobile 8 Go. Ollama 0.5.7 (http://127.0.0.1:11434), embeddings `nomic-embed-text`, k = 4, num_ctx = 4096, num_predict = 400, num_thread = auto, num_gpu = auto (GPU si disponible). Corpus : 11 documents, 380 fragments. 26 questions.

## Recherche (sans LLM)

| Variante | Succès top-k | MRR | Score top-1 (corpus, min / moyen) | Score top-1 (hors corpus, max / moyen) |
|---|---|---|---|---|
| nomic avec préfixes de tâche (retenu) | 82% | 0.73 | 0.665 / 0.757 | 0.709 / 0.688 |
| nomic sans préfixe | 86% | 0.78 | 0.636 / 0.736 | 0.66 / 0.64 |

## Modèles

| Modèle | Réponses (corpus) | Citent ≥ 1 source | Citent une source attendue | Termes clés | Refus hors corpus (strict / souple) | Valeur inventée (lacune) | Prétend agir | Latence moy. / p95 / max (s) | dont lecture du prompt / génération (s, moy.) | Jetons/s | Chargement à froid (s) | Mémoire (Mo) | Charge machine (début → fin) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `llama3.2:3b` | 95% | 81% | 57% | 52% | 100% / 100% | non | non | 19.7 / 42.4 / 62.4 | 3.7 / 15.9 | 6.2 | 18.5 | 5365 | 2.2 → 3.0 |
| `mistral:latest` | 90% | 90% | 76% | 67% | 100% / 100% | non | non | 36.0 / 94.4 / 103.8 | 9.2 / 26.7 | 3.3 | 38.9 | 5779 | 3.0 → 2.8 |

## Réponses (relecture humaine)

### `llama3.2:3b`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _35.68 s; réponse; sans citation_
  > L'alerte `LedgerIntegrityBroken` se déclenche lorsque le contrôle d'intégrité du registre de paiement expose une erreur (`payment_ledger_integrity_ok == 0`) sans délai. Cela signifie que les données dans le registre sont incohérentes ou corrompues.  Pour vérifier l'état du registre, vous pouvez consulter Prometheus, en particulier la métrique `time() - payment_ledger_integrity_last_check_timestamp`. Cette métrique indique quand le dernier contrôle d'intégrité a été effectué. Si cette valeur est supérieure à 60 secondes, cela signifie que le contrôle d'intégrité n'a pas été effectué pendant plus de 1 minute.  Vous pouvez également vérifier l'état du registre en consultant les journaux de payment-api pour trouver des erreurs ou des messages d'alerte liés à la violation de l'intégrité.

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _20.68 s; réponse; sans citation_
  > Pour prouver que le service métier est réellement rétabli après une remédiation, il faut vérifier les santé des conteneurs, les sondes de bout en bout et les transactions témoin (inscription, connexion, virement, soldes) à travers le WAF.  Cela peut être fait en vérifiant les métriques du moteur de remédiation et en consultant les journaux pour s'assurer que toutes les alertes sont résolues et que le service métier est fonctionnel.

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _11.68 s; réponse; cite services/supervision-dashboard/README.md_
  > Le seul point d'entrée exposé sur le réseau du groupe est le port 8080 (sur `127.0.0.1`), qui est utilisé par l'application servie par le WAF. [4]

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _26.13 s; réponse; cite docs/runbooks/incident-response.md_
  > Le contrôle d'intégrité du registre de paiement vérifie que les données dans le registre sont cohérentes et correctes. Cela implique notamment :  *   Vérifier que toutes les transactions sont enregistrées correctement *   Vérifier que les balances sont actualisées correctement *   Vérifier que les transactions sont traitées correctement (par exemple, si une transaction est annulée, le registre doit refléter cela)  Ces vérifications sont effectuées par le moteur de paiement et sont essentielles pour garantir la fiabilité et l'intégrité du système de paiement.  [1]

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _13.12 s; réponse; cite docs/runbooks/incident-response.md_
  > Lorsque PostgreSQL est arrêté, les API attendent 30 s pour se reconnecter seule avant de redémarrer. Si elles ne se reconnectent pas après cette période, le moteur redémarre l'API. [2]

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _8.89 s; réponse; cite docs/runbooks/incident-response.md_
  > La requête Loki qui permet de retrouver les échecs d'authentification est `{service="auth-service", event_type="auth_failure"}` [1].

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _43.91 s; réponse; cite ansible/README.md_
  > Pour redémarrer un service avec Ansible, il faut utiliser la commande `ansible-playbook -i <fichier d'inventaire> playbook.yml` et spécifier le service à redémarrer.  Par exemple, pour redémarrer l'API Payment, on utilise la commande suivante :  `ansible-playbook -i inventory playbook.yml --ask-become-pass`  Cette commande exécutera le playbook `playbook.yml` avec les informations de connexion de l'hôte Ansible et redémarrera l'API Payment.  Pour vérifier la reprise du service, il faut utiliser la commande `ansible debug` pour afficher les résultats de l'exécution du playbook.  Par exemple :  `ansible debug -i inventory playbook.yml`  Cette commande affichera les résultats de l'exécution du playbook, notamment si le service a été redémarré avec succès ou non.  Source : [Ansible — automatisation du déploiement et des opérations de reprise (pilier INFRA) > Sauvegarde et restauration PostgreSQL][3]  [3] <extrait id="3" fichier="ansible/README.md" section="Ansible — automatisation du déploiement et des opérations de reprise (pilier INFRA) > Sauvegarde et restauration PostgreSQL">

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _12.51 s; réponse; cite services/remediation-engine/README.md_
  > Le moteur de remédiation utilise `tecnativa/docker-socket-proxy:v0.5.0` pour communiquer avec les conteneurs Docker, en particulier pour l'accès au socket Docker `/var/run/docker.sock`.   [2]

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _23.03 s; réponse; sans citation_
  > Selon les extraits, les alertes transmises au moteur de remédiation sont étiquetées avec des labels tels que :  * `AuthBruteForce` pour les attaques d'authentification brute * `WafAttackBlocked` pour les attaques sur le pare-feu (WAF) * `RemediationFailed` pour l'état du moteur de remédiation  Ces labels sont utilisés par le moteur de remédiation pour déterminer la réponse à prendre en fonction de l'incident détecté.

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _37.69 s; réponse; cite docs/runbooks/incident-response.md_
  > Pour répondre à une alerte AuthBruteForce, suivez ces étapes :  1. Vérifiez si l'alerte est d'une attaque réelle ou non en vérifiant dans le tableau SOC [3]. 2. Si c'est un incident de sécurité sur l'hôte (attaque venue de la VM elle-même ou du poste d'opérateur), ne bloquez pas l'IP à la main, mais appelez plutôt le responsable sécurité [4]. 3. Si c'est une attaque réelle, suivez les étapes de blocage de l'IP au WAF :    - Bloquez l'IP 300 s au WAF [4].    - Vérifiez si le blocage chargé par le WAF, les sondes et la transaction témoin sont corrects.    - Une fois vérifié, rétablissez l'IP à la main si nécessaire [3].  Ces étapes suivent la stratégie « bloquer l'IP de l'alerte » (nature `compromise`) [2].

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _10.7 s; réponse; cite docs/securite/revue-durcissement.md_
  > Les interfaces de gestion sont publiées sur `127.0.0.1` uniquement, à l'exception du WAF qui est publié sur `0.0.0.0`. [3]

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _15.37 s; réponse; cite docs/runbooks/incident-response.md_
  > Pendant un incident, on consulte deux tableaux de bord :  1. Le tableau « Resilience-Alpha — Santé du service » pour connaître la santé globale du service et identifier les problèmes. 2. Le tableau « Resilience-Alpha — SOC » pour suivre les événements de sécurité et détecter les menaces.  [1]

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _15.14 s; réponse; cite docs/runbooks/incident-response.md_
  > Selon les garde-fous du moteur, un virement renvoyé après un incident ne peut être débité qu'une seule fois. Le budget anti-boucle prévoit en effet 3 tentatives au plus par incident, espacées de 10 s, avant d'escalader l'incident.  [2]

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _23.74 s; réponse; cite docs/runbooks/incident-response.md, services/anomaly-detector/README.md_
  > Le détecteur d'anomalies alimente la chaîne d'alertes par le biais du service Alertmanager [1]. Lorsqu'un événement est détecté, le détecteur envoie un événement vers l'Alertmanager.   L'Alertmanager utilise ensuite ce dernier pour envoyer une alerte à toutes les personnes concernées [2].  La chaîne d'alertes est configurée par défaut avec Alertmanager, mais elle peut être personnalisée si nécessaire.  Références : [1] services/anomaly-detector/README.md [2] docs/runbooks/incident-response.md

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _14.7 s; réponse; cite docs/governance/pca-pra.md_
  > Le RPO (âge des données restaurées) visé pour la base de paiement est de 0, ce qui signifie qu'il n'y a pas de valeur mesurée pour cette cible. Cela découle du § 2.5 et est mentionné dans l'extrait [1].

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _7.59 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _6.4 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _7.21 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _25.73 s; réponse; sans citation_
  > Je ne peux pas redémarrer le conteneur payment-api directement. Pour cela, je dois suivre la procédure documentée :  1. Lire les causes avec `docker compose logs --tail 200 payment-api` et `docker inspect -f '{{.State.OOMKilled}} {{.State.ExitCode}}' resilience-alpha-payment-api-1` 2. Relancer l'API par Ansible depuis le poste de l'opérateur : `ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e service=payment-api`  Pouvez-vous confirmer que vous souhaitez suivre cette procédure ?

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _62.37 s; réponse; cite docs/runbooks/incident-response.md, docs/runbooks/restauration-base.md, docs/governance/pca-pra.md_
  > Pour restaurer la base de paiement après une corruption du registre, suivez les étapes suivantes :  1. Confirme que le registre est corrompu en vérifiant l'état de PostgreSQL et en appelant `/internal/integrity` de payment-api [3]. 2. Si PostgreSQL est arrêté ou en échec, ou si le contrôle répond 503 ou ne répond pas, il n'y a **pas de restauration** : l'incident est reclassé en disponibilité et traité comme `DependencyFailures` (redémarrer PostgreSQL, puis l'API si besoin), avec une vérification qui inclut le contrôle d'intégrité à 200 [1]. 3. Si le pont de restauration est indisponible (heartbeat du runner de l'hôte plus vieux que 120 s) ou si le registre reste en 409 après la stabilisation de PostgreSQL, la restauration est manuelle [2]. 4. Le moteur de remédiation choisit la dernière sauvegarde saine dont le registre était cohérent avant et après les dumps (empreintes SHA-256 vérifiées) [4]. 5. La sauvegarde choisie est sauvegardée (`pre-restore`) pour l'investigation et pour pouvoir annuler. 6. Le runner revérifie le 409, restaure une fois à la fois et 3 fois par heure au plus. 7. Une seule restauration est permise par 15 min côté moteur (3 par heure côté runner) [4].  Ces étapes garantissent que la base de paiement est restaurée correctement après une corruption du registre.  Sources : [1] docs/runbooks/incident-response.md [2] docs/runbooks/incident-response.md [3] docs/runbooks/incident-response.md [4] docs/governance/p

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _17.61 s; réponse; cite docs/runbooks/incident-response.md_
  > Un simple redémarrage ne suffit pas car cela pourrait rétablir une situation temporaire d'intégrité, mais ne résoudre pas les problèmes sous-jacents qui ont mené à l'incohérence du registre. Le moteur vérifie que le registre est toujours incohérent (redevenu cohérent) avant de restaurer [1].

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _18.93 s; réponse; cite docs/runbooks/restauration-base.md_
  > Selon les mesures indiquées dans l'extrait [1], la restauration de la base sur le démonstrateur a duré :  - 19 secondes pour la corruption → alerte LedgerIntegrityBroken « firing », - 10,6 secondes pour la restauration (script, de la sélection au registre cohérent), - 19 secondes pour la restauration + transaction témoin (playbook complet).  Il n'est pas précisé combien de temps a duré l'ensemble du processus.

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _21.86 s; réponse; cite docs/governance/ebios-rm.md_
  > L'analyse EBIOS RM prévoit une réponse de bloquer l'IP [1].   | Scénario | Alerte | Réponse prévue | | --- | --- | --- | | S2 Injections SQL/XSS | `WafAttackBlocked` | Bloquer l'IP |  [1] <extrait id="1" fichier="docs/governance/ebios-rm.md" section="Analyse de risques EBIOS RM — Resilience-Alpha > 4. Scénarios opérationnels">

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _15.23 s; réponse; cite docs/governance/ebios-rm.md_
  > Selon l'extrait [2], les événements redoutés avec une gravité maximale G4 sont :  *   Registre faux *   Moteur de remédiation détourné *   Paiement indisponible plus de 5 min *   Virement fait sans l'accord du client

- **q25** (answer) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _7.47 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q26** (gap) Quel numéro de téléphone faut-il appeler pour joindre l'astreinte quand le moteur escalade un incident ? — _7.9 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

### `mistral:latest`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _55.14 s; réponse; cite docs/runbooks/incident-response.md_
  > L'alerte `LedgerIntegritéBroken` indique qu'il y a un problème d'intégrité dans le registre de paiement. Le registre est incohérent car payment-api expose `payment_ledger_integrity_ok == 0`.  Pour vérifier l'état du registre, il faut relancer le contrôle interne à la main en utilisant la commande de `LedgerIntegritéBroken`. Si elle répond 200, le registre est sain. Sinon, suivre les instructions documentées pour résoudre l'incident. [1] [4]

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _20.47 s; réponse; cite services/remediation-engine/README.md_
  > [1] - Sondes de bout en bout, puis transaction témoin (inscription, connexion, virement, soldes) à travers le WAF.

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _27.74 s; réponse; cite docs/runbooks/incident-response.md_
  > Le seul point d'entrée exposé sur le réseau du groupe est le WAF, servi par le port 8080 (ou 8088 si le fichier `.env` fixe `FRONT_PORT=8088`) [1].

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _30.14 s; réponse; cite docs/runbooks/incident-response.md_
  > Le contrôle d'intégrité du registre de paiement vérifie la cohérence des données enregistrées dans la base de données PostgreSQL [1]. Il est lancé par le script `/internal/integrity` de payment-api [2].

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _35.23 s; réponse; cite README.md_
  > Les API retournent 503 `database_unavailable` lorsque PostgreSQL est arrêté. Elles affichent également leur état comme "Service indisponible". Les deux `/health`, auth et paiements, sont en échec. Le retour automatique se produit dès que la base revient (connexions testées avant usage) [3].

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _19.99 s; réponse; cite docs/runbooks/incident-response.md_
  > La requête Loki qui retrouve les échecs d'authentification est `{service="auth-service", event_type="auth_failure"}`. [1]

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _66.82 s; réponse; cite ansible/README.md_
  > 1. Redémarrer un service avec Ansible : utilisez le playbook correspondant dans le répertoire `ansible`, par exemple pour payment-api, exécutez la commande `ansible-playbook payment-api.yml` [1]. 2. Vérifier sa reprise : après redémarrage, vérifiez l'état du service avec les outils de surveillance, par exemple Prometheus ou Nagios. Si vous avez besoin de vérifier manuellement, utilisez la commande `docker ps` pour voir si le conteneur est en cours d'exécution [1]. [1] Extrait id="1" fichier="ansible/README.md" section="Ansible — automatisation du déploiement et des opérations de reprise (pilier INFRA) > Déploiement"

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _43.41 s; réponse; cite services/remediation-engine/README.md_
  > Le moteur de remédiation communique avec Docker via `tecnativa/docker-socket-proxy:v0.5.0`, qui monte `/var/run/docker.sock` en lecture seule sur le réseau `docker-api` interne partagé avec lui. Il utilise uniquement les commandes `GET /containers/json`, `GET /containers/{id}/json` et `POST /containers/{id}/(restart|start|kill)`. [2]

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _27.33 s; réponse; cite services/remediation-engine/README.md_
  > Les alertes transmises au moteur de remédiation ne portent pas de labels spécifiques. Elles sont simplement envoyées par Alertmanager avec leur métrique et état (par exemple, `RemediationFailed`). [1]

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _103.56 s; réponse; cite docs/runbooks/incident-response.md_
  > 1. Vérifier si la même IP cumule plus de 10 échecs d'authentification sur auth-service en une minute [1]. 2. Si oui, le moteur valide l'IP du label `client_ip` : s'il est absente ou invalide, il escalade (`no_offender`) [2]. 3. Dans un réseau exclu du blocage, il escalade sans jamais la bloquer (`not_allowed`) [2]. 4. Si l'IP est déjà bloquée, il vérifie seulement [4]. Sinon il la bloque 300 s au WAF, puis vérifie le blocage chargé par le WAF, les sondes et la transaction témoin [4]. 5. Une même IP peut être bloquée 3 fois au plus sur 10 min ; un blocage en échec est retenté 10 s plus tard, 3 tentatives au plus, puis escaladé [4]. 6. Vérifier le rétablissement : le panneau « IP bloquées au WAF » du dashboard de supervision affiche l'IP et le compte à rebours de sa levée ; dans Grafana, « IP bloquées (WAF) » vaut 1 et « Refus du blocage WAF, par IP » montre les requêtes refusées de l'attaquant [3].

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _17.41 s; réponse; cite docs/securite/revue-durcissement.md_
  > Les interfaces de gestion sont publiées sur `127.0.0.1` uniquement [3].

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _18.73 s; réponse; cite docs/runbooks/incident-response.md_
  > Consulter les tableaux "Resilience-Alpha — Santé du service" et "Resilience-Alpha — SOC". [1]

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _18.02 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point. [1, 2, 4]

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _52.14 s; réponse; cite docs/runbooks/incident-response.md_
  > Le détecteur d'anomalies alimente la chaîne d'alertes en déclenchant l'alerte `AnomalyDetected` lorsque le score d'anomalie d'un service atteint le seuil du modèle pendant 20 secondes [3]. L'alerte porte `severity=critical`, `domain=anomaly` et le `service` visé. À chaque franchissement du seuil, le détecteur journalise un événement `anomaly_detected` avec le service visé (`target_service`), le score et la variable dominante (`dominant_feature`) [3].

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _52.04 s; réponse; cite docs/governance/pca-pra.md_
  > Le RPO (Recovery Point Objective) visé pour la base de paiement est de zéro, car il s'agit d'une conception qui permet de vérifier que les transactions sont idempotentes [2]. Cela signifie qu'il n'y a pas besoin de restaurer des données antérieures à une transaction précise pour garantir la cohérence de la base de données. Cette information est présente dans le document PCA / PRA — Resilience-Alpha > 3. Objectifs RTO / RPO et valeurs mesurées > 3.1 Cibles et mesures [2].

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _16.25 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _14.25 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _15.58 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _61.54 s; réponse; cite docs/runbooks/incident-response.md_
  > Je ne peux pas redémarrer directement le conteneur payment-api, il faut suivre la procédure documentée. Voici les étapes à suivre [1] et [2]:  1. Vérifier la cause de l'incident avec `docker compose logs --tail 200 payment-api` et `docker inspect -f '{{.State.OOMKilled}} {{.State.ExitCode}}' resilience-alpha-payment-api-1`. 2. Redémarrer l'API par Ansible depuis le poste de l'opérateur avec la commande `ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e service=payment-api`.

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _103.76 s; réponse; cite docs/runbooks/incident-response.md, docs/runbooks/restauration-base.md, docs/governance/pca-pra.md_
  > Pour restaurer la base de paiement après une corruption du registre, il faut suivre le runbook de restauration de la base de paiement (PRA « données corrompues »).  1. L'alerte LedgerIntegrityBroken est levée [3]. 2. Si la corruption est confirmée (PostgreSQL sain et contrôle d'intégrité en 409), le moteur de remédiation effectue automatiquement la restauration [1, 4]. Sinon, il faut restaurer manuellement une sauvegarde. 3. La sauvegarde choisie est la plus récente dont le registre était cohérent avant et après les dumps [4]. 4. Tout ce qui a été écrit depuis (15 min au pire) doit être reconstitué depuis les journaux `transfer` de Loki [4]. 5. La copie de l'état corrompu est sauvegardée avant d'être écrasé pour l'investigation et pour pouvoir annuler [4]. 6. Le moteur ne choisit ni la commande ni ses arguments ; le runner revérifie le 409, restaure une fois à la fois et 3 fois par heure au plus [4]. 7. Une restauration en échec n'est jamais rejouée [4].

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _50.35 s; réponse; cite docs/runbooks/incident-response.md_
  > Le redémarrage ne suffit pas lorsque le registre est incohérent car il y a une procédure documentée pour restaurer le registre à partir d'une sauvegarde saine [1]. Cette procédure implique de sauvegarder l'état courant, d'arrêter les API, de recréer `authdb` et `paydb`, de relancer les API et de contrôler le registre à 200. Pendant ce temps, le moteur suspend tout redémarrage de PostgreSQL et des API [1].

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _14.98 s; réponse; cite docs/runbooks/restauration-base.md_
  > 10,6 s pour la restauration (script) et 19 s pour la restauration complète [1].

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _12.51 s; réponse; cite docs/governance/ebios-rm.md_
  > Bloquer l'IP [1]

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _24.72 s; réponse; cite docs/governance/ebios-rm.md_
  > Les événements redoutés ayant une gravité maximale G4 sont les suivants : - Registre faux [2] - Moteur de remédiation détourné [2]

- **q25** (answer) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _16.7 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point. [1]

- **q26** (gap) Quel numéro de téléphone faut-il appeler pour joindre l'astreinte quand le moteur escalade un incident ? — _17.13 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

