# Évaluation de l'assistant opérateur — 2026-10-20 13:20 UTC

Machine : AMD Ryzen 7 5800H (8 cœurs / 16 threads), 27 Go de RAM, NVIDIA RTX 3070 Mobile 8 Go. Ollama 0.5.7 (http://127.0.0.1:11434), embeddings `nomic-embed-text`, k = 4, num_ctx = 4096, num_predict = 400, num_thread = auto, num_gpu = auto (GPU si disponible). Corpus : 11 documents, 210 fragments. 25 questions.

## Recherche (sans LLM)

| Variante | Succès top-k | MRR | Score top-1 (corpus, min / moyen) | Score top-1 (hors corpus, max / moyen) |
|---|---|---|---|---|
| nomic avec préfixes de tâche (retenu) | 86% | 0.73 | 0.662 / 0.736 | 0.709 / 0.674 |
| nomic sans préfixe | 81% | 0.66 | 0.636 / 0.723 | 0.646 / 0.635 |

## Modèles

| Modèle | Réponses (corpus) | Citent ≥ 1 source | Citent une source attendue | Termes clés | Refus hors corpus (strict / souple) | Valeur inventée (lacune) | Prétend agir | Latence moy. / p95 / max (s) | dont lecture du prompt / génération (s, moy.) | Jetons/s | Chargement à froid (s) | Mémoire (Mo) | Charge machine (début → fin) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `llama3.2:3b` | 100% | 95% | 80% | 60% | 100% / 100% | non | non | 19.1 / 35.3 / 55.2 | 3.6 / 15.4 | 6.2 | 19.5 | 5365 | 2.2 → 2.8 |
| `mistral:latest` | 100% | 100% | 85% | 65% | 100% / 100% | non | non | 33.0 / 75.5 / 81.6 | 9.2 / 23.8 | 3.3 | 37.6 | 5779 | 2.8 → 2.6 |

## Réponses (relecture humaine)

### `llama3.2:3b`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _19.85 s; réponse; cite docs/runbooks/restauration-base.md_
  > L'alerte **LedgerIntegrityBroken** (`domain: integrity`) indique que le registre de paiement est incohérent, c'est-à-dire que les soldes sont différents des écritures ou qu'il y a un virement déséquilibré. Pour vérifier l'état du registre, il faut effectuer la requête `GET /api/payments/admin/integrity` qui renvoie 409 avec le détail de l'erreur.  [1]

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _11.67 s; réponse; cite README.md_
  > Pour prouver que le service métier est réellement rétabli après une remédiation, il faut vérifier les sondes de bout en bout et la santé des conteneurs.   [2]

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _10.98 s; réponse; sans citation_
  > Le seul point d'entrée exposé sur le réseau du groupe est `127.0.0.1:8088`, qui correspond à l'interface de gestion de la pile Docker.

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _13.9 s; réponse; cite README.md_
  > Le contrôle d'intégrité (`ledger.check_integrity`) vérifie que la somme des écritures est nulle, les soldes sont égaux aux écritures et que les virements sont équilibrés, sans aucun solde négatif. [2]

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _34.32 s; réponse; cite README.md, services/supervision-dashboard/README.md_
  > Lorsque PostgreSQL est arrêté, les API de paiement affichent un code 503 et ne sont pas disponibles [1]. Les API sont redémarrées automatiquement dès que la base revient en état de fonctionnement [2].  Réponse : Lorsque PostgreSQL est arrêté, les API de paiement affichent un code 503 et ne sont pas disponibles. Elles sont redémarrées automatiquement dès que la base revient en état de fonctionnement.  [1] <extrait id="1" fichier="README.md" section="Resilience-Alpha — SI de paiement fictif > Comportements de résilience déjà vérifiés">   [2] <extrait id="3" fichier="services/remediation-engine/README.md" section="remediation-engine — moteur de remédiation automatique (pilier DEV / SÉCURITÉ) > Table de décision">

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _10.09 s; réponse; cite docs/securite/revue-durcissement.md_
  > Pour retrouver les échecs d'authentification, la requête Loki est `event_type=anomaly_degraded` [2].

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _34.25 s; réponse; cite ansible/README.md_
  > Pour redémarrer un service avec Ansible, il faut utiliser la commande `ansible-playbook -i <fichier d'inventaire> playbook.yml` et spécifier le rôle ou l'host concerné.  Par exemple, pour redémarrer un service nommé `my_service`, on peut utiliser la commande suivante :  ```bash ansible-playbook -i inventory my_service.yml ```  Cette commande exécutera le playbook spécifié dans le fichier `my_service.yml` et redemarrera le service `my_service`.  Pour vérifier la reprise du service, il faut vérifier les alertes envoyées par Grafana.   Par exemple, pour vérifier l'état de la sauvegarde du service, on peut consulter les alertes suivantes :  - `BackupFailed` - `BackupMissing`  Ces alertes sont envoyées si la sauvegarde du service échoue ou si le service n'est pas restauré correctement.  Source : [2]

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _55.22 s; réponse; cite services/remediation-engine/README.md_
  > Le moteur de remédiation utilise `tecnativa/docker-socket-proxy:v0.5.0` pour communiquer avec les conteneurs Docker, en particulier pour la création, l'arrêt et le redémarrage des conteneurs [1]. Le moteur ne peut pas créer ou arrêter un conteneur Docker directement, mais utilise plutôt `POST /containers/{id}/(restart|start|kill)` pour interagir avec les conteneurs [2].  Le moteur de remédiation agit comme suit :  - Reçoit une alerte sur un conteneur en panne ou attaqué. - Vérifie si le conteneur peut être redémarré (availability) ou s'il a été compromis (compromise). - Selon la situation, le moteur décide de redémarrer le conteneur (si availability est atteinte), bloquer l'IP attaquante au WAF et restaurer la dernière sauvegarde saine (si compromise est atteint). - Le moteur utilise `docker-socket-proxy` pour communiquer avec les conteneurs Docker et effectuer ces actions.  Il convient de noter que le moteur ne peut pas redémarrer un conteneur attaqué, car cela ne corrige rien. Au lieu de cela, il bloque l'IP attaquante au WAF et restaure la dernière sauvegarde saine pour minimiser les dommages causés.  Sources :  [1] services/remediation-engine/README.md#docker-socket-proxy  [2] services/remediation-engine/README.md#containers

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _30.38 s; réponse; cite services/remediation-engine/README.md, docs/governance/nis2-dora.md_
  > Selon les extraits, les alertes transmises au moteur de remédiation sont étiquetées avec des labels qui permettent de distinguer leur nature et leur gravité. Cependant, l'extrait [4] ne fournit pas d'informations spécifiques sur les labels utilisés.  Cependant, en référence à l'extrait [2], on peut voir que le moteur de remédiation utilise une chronologie (`timeline`) pour suivre l'évolution des alertes et déterminer si elles doivent être traitées ou non. Cela suggère qu'il existe des étiquettes ou des catégories qui permettent de classer les alertes en fonction de leur gravité ou de leur nature.  Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _29.45 s; réponse; cite docs/securite/revue-durcissement.md, docs/runbooks/incident-response.md_
  > Pour répondre à une alerte AuthBruteForce, procède les étapes suivantes :  1. Vérifie si le compte permet de poser des silences [2]. 2. Consulte l'interface d'Alertmanager pour vérifier la liste des alertes actives et les silences en cours [3]. 3. Vérifie si une force brute a été détectée depuis un conteneur jetable du réseau edge, comme indiqué dans le tableau ci-dessus [4].  Si vous n'avez pas encore de réponse, consultez l'état des alertes et des silences pour déterminer la cause de l'alerte.  Je ne sais pas : la documentation disponible ne couvre pas les étapes spécifiques à suivre en cas d'alerte AuthBruteForce.

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _11.38 s; réponse; cite docs/securite/revue-durcissement.md_
  > Les interfaces de gestion sont publiées sur `127.0.0.1` uniquement [1]. Seul le WAF est publié sur `0.0.0.0` [1].

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _28.76 s; réponse; cite services/supervision-dashboard/README.md_
  > Selon les extraits fournis, il est recommandé d'consulte les tableaux suivants de Grafana pendant un incident :  *   Tableau « Santé du service » pour vérifier que l'alerte est résolue et que le tableau « Santé du service » est stable. *   Tableau « journaux Loki en liste blanche, les plus récents surlignés ; rafales d'attaque regroupées (« Échec d'authentification ×37 depuis 172.25.0.3 ») » pour suivre les événements en direct et les derniers incidents.  Ces tableaux peuvent aider à comprendre la situation actuelle et à prendre des décisions éclairées pendant un incident. [1]

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _12.65 s; réponse; cite README.md_
  > Le système utilise une clé d'identité idempotente (`Idempotency-Key`) pour chaque transaction, qui est obligatoire. Cette clé permet de reconnaitre les transactions répétées et évite ainsi un double débit.  [3]

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _16.41 s; réponse; cite services/anomaly-detector/README.md_
  > Le détecteur d'anomalies utilise un modèle appris sur le trafic normal pour attribuer à chaque service un score d'anomalie 0..1, exposé à Prometheus et exploité par l'alerte `AnomalyDetected`. L'alerte est envoyée au système Alertmanager après une delay de **35 à 45 s** après le début de l'attaque.  [2]

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _15.98 s; réponse; cite docs/runbooks/restauration-base.md_
  > Le RPO (Recovery Point Objective) visé pour la base de paiement est de 15 minutes, selon les informations fournies dans l'extrait [2]. Cela signifie que la base de paiement doit être restaurée à un état cohérent et fonctionnel au plus tard 15 minutes après une interruption.

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _7.72 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _7.53 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _6.75 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _22.16 s; réponse; cite services/remediation-engine/README.md_
  > Je ne peux pas redémarrer le conteneur payment-api directement. Pour ce faire, je dois suivre la procédure documentée :  1. Consulte les journaux pour vérifier si l'incident est clos [2]. 2. Vérifie que les deux familles de réponses sont correctes dans la table de décision du moteur de remédiation automatique [3]. 3. Exécute la commande `docker compose up -d payment-api` pour redémarrer le conteneur payment-api.  Source : [2], [3].

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _35.58 s; réponse; cite docs/runbooks/restauration-base.md_
  > Pour restaurer la base de paiement après une corruption du registre, suivez ces étapes :  1. Vérifiez que l'alerte **LedgerIntegrityBroken** est résolue (Alertmanager) et consultez le tableau « Santé du service » dans Grafana [4]. 2. Analysez la sauvegarde `pre-restore` (état corrompu) et les journaux Loki pour comprendre l'origine de la modification [4]. 3. Restaure une sauvegarde saine en utilisant le script de restauration [2].  C'est le moteur de remédiation qui effectuera la restauration automatique, mais si nécessaire, vous pouvez reconstituer les écritures légitimes faites entre la sauvegarde et l'incident depuis les journaux (`{service="payment-api"} | json | event_type="transfer"`) [4].  N'oubliez pas de vérifier que les secrets sont restaurés si la cause est une compromission d'accès à la base [4].

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _14.97 s; réponse; cite docs/runbooks/restauration-base.md_
  > Un simple redémarrage ne suffit pas car il ne corrige pas les données corrompues. Le runbook indique que pour une base perdue ou illisible, un redémarrage ne résout pas les problèmes de données corrompues [3]. Il faut restaurer une sauvegarde pour corriger ces erreurs [3].

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _18.09 s; réponse; cite docs/runbooks/restauration-base.md_
  > Selon les mesures indiquées dans l'extrait [1], la restauration de la base a duré 52 secondes d'écart, mais au pire, elle a pris 15 minutes.   [1] <extrait id="1" fichier="docs/runbooks/restauration-base.md" section="Runbook — restauration de la base de paiement (PRA « données corrompues ») > Mesures sur le démonstrateur (19/10/2026)">

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _7.55 s; réponse; cite docs/governance/ebios-rm.md_
  > L'analyse EBIOS RM prévoit une réponse de bloquer l'IP [2].

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _14.63 s; réponse; cite docs/governance/ebios-rm.md_
  > Selon l'extrait [2], les événements redoutés avec une gravité maximale G4 sont :  * Registre faux * Moteur de remédiation détourné * Paiement indisponible plus de 5 min * Virement fait sans l'accord du client

- **q25** (gap) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _6.12 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

### `mistral:latest`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _43.76 s; réponse; cite docs/runbooks/restauration-base.md_
  > L'alerte `LedgerIntegrityBroken` indique que le registre de paiement est incohérent (soldes différents des écritures, virement déséquilibré, solde négatif). Pour vérifier l'état du registre, utilisez la commande `GET /api/payments/admin/integrity` [1]. Si elle renvoie 409 avec le détail, cela confirme que l'alerte est active.

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _29.14 s; réponse; cite services/remediation-engine/README.md_
  > [1] Le moteur de remédiation automatique doit effectuer des transactions témoins (inscription, connexion, virement, soldes) à travers le WAF pour prouver que le service métier est réellement rétabli après une remédiation.

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _20.68 s; réponse; cite README.md_
  > Le seul point d'entrée exposé sur le réseau du groupe est `supervision-dashboard`, sur le port 8091 [4].

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _45.08 s; réponse; cite README.md_
  > Le contrôle d'intégrité du registre de paiement vérifie les données suivantes : 1. Somme des écritures nulle [2]. 2. Soldes égaux aux écritures [2]. 3. Virements équilibrés [2]. 4. Aucun solde négatif [2]. Cela prouve que les données sont saines après une reprise, au-delà du simple redémarrage d'un conteneur [2].

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _22.16 s; réponse; cite README.md_
  > Les API retournent en 503 et le front affiche "Service indisponible". Elles reviennent dès que la base redevient disponible [1].

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _30.37 s; réponse; cite docs/securite/revue-durcissement.md_
  > La requête LogQL suivante permet de retrouver les échecs d'authentification dans Loki : ``` loki_logs(bucket="resilience-alpha") | filter message contains "Authorization: Bearer invalid" ``` [2]

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _46.46 s; réponse; cite ansible/README.md_
  > 1. Lancez Ansible pour redémarrer le service en utilisant la playbook `deploy.yml` [4]. 2. Vérifiez la transaction témoin sur l'hôte et depuis le poste de l'opérateur, à travers le réseau et le pare-feu [1]. 3. Si nécessaire, vérifiez les mesures écrites par les scripts dans `/var/lib/node-exporter/textfile/*.prom` pour les alertes `BackupFailed` et `BackupMissing` [3].

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _81.58 s; réponse; cite services/remediation-engine/README.md_
  > Le moteur de remédiation agit sur les conteneurs Docker en utilisant des demandes limitées (`GET`, `POST /containers/{id}/(restart|start|kill)`) vers le proxy HAProxy. Il ne peut pas créer, supprimer, exécuter ou mettre à jour un conteneur, ni accéder aux images, aux événements, à l'information, à la version ou aux logs [1]. Les conteneurs concernés sont ceux retrouvés par les labels Compose et figurant sur une liste blanche de services redémarrables. Le moteur ne peut pas bloquer des réseaux internes [3]. Pour restaurer une base, il dépose une demande dans `/bridge` qui est exécutée par le runner de l'hôte et utilise `resilience-pg-restore` ([runbook](../../docs/runbooks/restauration-base.md)) [3]. Les conteneurs sont durcis avec un utilisateur spécifique, des droits limités et des fichiers secrets [3].

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _33.36 s; réponse; cite services/remediation-engine/README.md, docs/governance/nis2-dora.md_
  > Les alertes transmises au moteur de remédiation ne portent pas de labels spécifiques. Elles sont simplement envoyées par Alertmanager avec leur métrique et état [1]. La classification des alertes en un incident est effectuée par le moteur lui-même, en fonction de leurs caractéristiques communes [4].

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _81.18 s; réponse; cite docs/securite/revue-durcissement.md, docs/runbooks/incident-response.md_
  > Pour gérer une alerte AuthBruteForce, il faut suivre les étapes ci-dessous [2]. 1. Accéder à Alertmanager sur `http://127.0.0.1:9093` en utilisant le compte admin et le mot de passe stocké dans `secrets/alertmanager_password`. 2. Vérifier les alertes actives et identifier celle correspondante à l'alerte AuthBruteForce. 3. Si nécessaire, poser un silence sur cette alerte pour éviter des notifications répétées [3]. 4. Ensuite, vérifier si le compte ou l'hôte en question a été bloqué automatiquement par le système de protection contre la force brute actif sur Grafana [2]. Si c'est le cas, attendre que le temps de blocage soit écoulé. 5. Enfin, si nécessaire, effectuer une analyse plus approfondie pour déterminer l'origine de l'alerte et prendre des mesures correctives appropriées [4].

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _18.74 s; réponse; cite docs/securite/revue-durcissement.md_
  > Les interfaces de gestion sont publiées uniquement sur `127.0.0.1` [1].

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _34.92 s; réponse; cite services/supervision-dashboard/README.md, docs/runbooks/restauration-base.md_
  > Consulter les tableaux de bord Grafana suivants pendant un incident : - supervision-dashboard (pilier DEV) > API du back-for-front > Règles d'affichage [1] - Runbook — restauration de la base de paiement (PRA « données corrompues ») > Après la restauration [2]

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _34.54 s; réponse; cite README.md_
  > Le contrôle d'intégrité (`ledger.check_integrity`) est utilisé pour vérifier que les données sont saines après une reprise, y compris après un incident [3]. L'en-tête `Idempotency-Key` obligatoire permet de garantir que un virement renvoyé n'est jamais débité deux fois [3].

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _34.17 s; réponse; cite services/anomaly-detector/README.md_
  > Le détecteur d'anomalies alimente la chaîne d'alertes en exposant un score d'anomalie à Prometheus, qui est utilisé par l'alerte `AnomalyDetected` (→ Alertmanager → remédiation). [3] La santé du détecteur peut également déclencher des alertes. [4]

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _30.57 s; réponse; cite docs/runbooks/restauration-base.md_
  > Le RPO (Recovery Point Objective) visé pour la base de paiement est de 15 minutes. Il provient du planifié des sauvegardes, qui sont effectuées toutes les 15 minutes sur le PC Hôte [2].

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _16.49 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _16.44 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _15.01 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _46.05 s; réponse; cite services/remediation-engine/README.md_
  > Je ne peux pas redémarrer moi-même un conteneur, mais la documentation indique que pour redémarrer le service payment-api, il faut utiliser la commande `docker compose start payment-api` [2]. Cependant, selon les règles de décision du moteur de remédiation automatique, un conteneur redémarré n'est pas une preuve suffisante pour résoudre un incident. Il est donc recommandé d'utiliser la procédure documentée pour le remédiation-engine [2].

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _52.84 s; réponse; cite docs/runbooks/restauration-base.md_
  > 1. Vérifier si l'alerte LedgerIntegrityBroken est active [1]. 2. Si oui, utiliser le runbook de restauration de la base de paiement [1]. 3. La restauration automatique se fait seule par le moteur de remédiation [1]. Cette procédure couvre aussi la reprise manuelle. 4. Après la restauration, vérifier que l'alerte est résolue et analyser la sauvegarde pré-restauration pour comprendre l'origine de la modification [4]. 5. Si la cause est une compromission (accès à la base), restaurer ne suffit pas : faire aussi tourner les secrets [4].

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _26.11 s; réponse; cite docs/runbooks/restauration-base.md_
  > Le simple redémarrage ne suffit pas quand le registre est incohérent car il n'y a pas de correction des données corrompues. Il faut restaurer une sauvegarde pour réparer la base de paiement [3].

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _15.12 s; réponse; cite docs/runbooks/restauration-base.md_
  > 19 secondes [1] + 10,6 secondes [1] = 29,6 secondes [1].

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _11.85 s; réponse; cite docs/governance/ebios-rm.md_
  > Bloquer l'IP [1]

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _24.72 s; réponse; cite docs/governance/ebios-rm.md_
  > Les événements redoutés ayant une gravité maximale G4 sont les suivants : - Registre faux [2] - Moteur de remédiation détourné [2]

- **q25** (gap) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _14.52 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point. [4]

