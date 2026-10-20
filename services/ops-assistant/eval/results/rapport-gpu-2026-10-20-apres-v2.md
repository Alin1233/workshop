# Évaluation de l'assistant opérateur — 2026-10-20 14:17 UTC

Machine : AMD Ryzen 7 5800H (8 cœurs / 16 threads), 27 Go de RAM, NVIDIA RTX 3070 Mobile 8 Go. Ollama 0.5.7 (http://127.0.0.1:11434), embeddings `nomic-embed-text`, k = 4, num_ctx = 4096, num_predict = 400, num_thread = auto, num_gpu = auto (GPU si disponible). Corpus : 11 documents, 386 fragments. 26 questions.

## Recherche (sans LLM)

| Variante | Succès top-k | MRR | Score top-1 (corpus, min / moyen) | Score top-1 (hors corpus, max / moyen) |
|---|---|---|---|---|
| nomic avec préfixes de tâche (retenu) | 82% | 0.73 | 0.665 / 0.759 | 0.709 / 0.688 |
| nomic sans préfixe | 86% | 0.74 | 0.636 / 0.741 | 0.66 / 0.64 |

## Modèles

| Modèle | Réponses (corpus) | Citent ≥ 1 source | Citent une source attendue | Termes clés | Refus hors corpus (strict / souple) | Valeur inventée (lacune) | Prétend agir | Latence moy. / p95 / max (s) | dont lecture du prompt / génération (s, moy.) | Jetons/s | Chargement à froid (s) | Mémoire (Mo) | Charge machine (début → fin) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `llama3.2:3b` | 95% | 81% | 62% | 67% | 100% / 100% | non | non | 18.4 / 43.7 / 56.2 | 3.8 / 14.5 | 6.1 | 18.0 | 5365 | 2.5 → 5.4 |
| `mistral:latest` | 95% | 95% | 76% | 76% | 100% / 100% | non | non | 37.7 / 102.2 / 123.2 | 9.1 / 28.5 | 3.3 | 42.0 | 5779 | 5.4 → 2.9 |

## Réponses (relecture humaine)

### `llama3.2:3b`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _56.24 s; réponse; cite docs/runbooks/incident-response.md_
  > L'alerte `LedgerIntegrityBroken` se déclenche lorsque le contrôle d'intégrité du registre de paiement expose une erreur (`payment_ledger_integrity_ok == 0`). Cela signifie que les règles de comptabilité en partie double n'ont pas été respectées, ce qui indique une incohérence dans le registre.  Pour vérifier l'état du registre et confirmer ou restaurer la cohérence, vous pouvez suivre ces étapes :  1. Vérifiez les métriques de payment-api pour obtenir des informations sur l'état du registre [2]. 2. Exécutez le contrôle d'intégrité du registre en utilisant `GET /internal/integrity` (réseau interne) ou `GET /api/payments/admin/integrity` (compte admin) [4]. Le résultat devrait être 200 si le registre est cohérent, 409 s'il est incohérent, avec un rapport JSON qui détaille chaque règle en échec. 3. Vérifiez les journaux de payment-api pour obtenir des informations sur les événements liés à l'alerte `LedgerIntegrityBroken` [3].  En suivant ces étapes, vous devriez être en mesure de vérifier l'état du registre et prendre les mesures nécessaires pour restaurer la cohérence.  Références :  [1] Extrait 1 [2] Extrait 4 [3] Extrait 3 [4] Extrait 4

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _18.4 s; réponse; sans citation_
  > Pour prouver que le service métier est réellement rétabli après une remédiation, il faut vérifier les santé des conteneurs, les sondes de bout en bout et les transactions témoin (inscription, connexion, virement, soldes) à travers le WAF.  Cela peut être fait en vérifiant les métriques du moteur de remédiation et en consultant les journaux de l'application métier.

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _13.38 s; réponse; cite services/supervision-dashboard/README.md_
  > Selon les extraits fournis, le seul point d'entrée exposé sur le réseau du groupe est le port 8080 (ou 8088 en cas de spécification dans le fichier `.env`), accessible via l'adresse `127.0.0.1`. [4]

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _21.44 s; réponse; cite docs/runbooks/incident-response.md_
  > Le contrôle d'intégrité du registre de paiement (`ledger.check_integrity` dans payment-api) vérifie quatre règles de la comptabilité en partie double :  1. La somme de toutes les écritures est nulle. 2. Le solde de chaque compte est égal à la somme de ses écritures. 3. Chaque virement est équilibré (une écriture de −montant et une de +montant). 4. Aucun solde n'est négatif.  [1]

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _17.29 s; réponse; cite README.md_
  > Lorsque PostgreSQL est arrêté, les deux API attendent 30 s avant de redémarrer. Si PostgreSQL reste en échec, le moteur redémarrera PostgreSQL et attendra qu'il soit `healthy` (90 s au plus). L'API sera redémarrée uniquement si elle reste en panne après avoir été redémarrée PostgreSQL. [3]

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _9.05 s; réponse; cite docs/runbooks/incident-response.md_
  > La requête Loki qui permet de retrouver les échecs d'authentification est `{service="auth-service", event_type="auth_failure"}` [1].

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _28.3 s; réponse; cite docs/runbooks/incident-response.md_
  > Selon les runbooks, pour redémarrer un service avec Ansible et vérifier sa reprise :  1. Exécutez le playbook `restart_service.yml` en utilisant la commande `sudo docker compose restart anomaly-detector`. 2. Après un redémarrage manuel, vérifiez la reprise du service comme après une action du moteur :     - Transaction témoin depuis le poste de l'opérateur (`python tests/smoke_test.py http://172.16.147.10:8080`, 28 vérifications, code de sortie 0 = service rétabli)    - Panneau « Parcours client » de Grafana à OK    - Contrôle d'intégrité du registre à 200  Source : [4]

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _12.53 s; réponse; cite services/remediation-engine/README.md_
  > Le moteur de remédiation utilise `tecnativa/docker-socket-proxy:v0.5.0` pour communiquer avec les conteneurs Docker, en particulier pour l'accès au socket Docker `/var/run/docker.sock`.   [2]

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _22.19 s; réponse; sans citation_
  > Selon les extraits, les alertes transmises au moteur de remédiation sont étiquetées avec des labels tels que :  * `AuthBruteForce` pour les attaques d'authentification brute * `WafAttackBlocked` pour les attaques sur le pare-feu * `RemediationFailed` pour l'état du moteur de remédiation  Ces labels sont utilisés par le moteur pour déterminer la nature de l'alerte et prendre des mesures appropriées.

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _34.26 s; réponse; cite docs/runbooks/incident-response.md_
  > Pour répondre à une alerte AuthBruteForce, suivez ces étapes :  1. Vérifiez si l'alerte est bien d'une attaque (voir le tableau SOC) [3]. 2. Bloquez l'IP de l'alerte au WAF (nature `compromise`) [2]. 3. Si l'escalade est `not_allowed`, vérifiez si l'IP est celle d'une passerelle ou de la DMZ [4]. 4. Si l'incident est un incident de sécurité sur l'hôte, ne traitez pas par un blocage (escalade `not_allowed`) [3]. 5. Vérifiez le rétablissement en vérifiant les panneaux du dashboard de supervision et Grafana [2].  Si vous n'êtes pas sûr de la nature de l'incident ou si vous devez reprendre manuellement, contactez le responsable sécurité.  Sources : [1], [2], [3]

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _10.59 s; réponse; cite docs/securite/revue-durcissement.md_
  > Les interfaces de gestion sont publiées sur `127.0.0.1` uniquement, à l'exception du WAF qui est accessible sur `0.0.0.0`. [3]

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _16.53 s; réponse; cite docs/runbooks/incident-response.md_
  > Pendant un incident, on consulte deux tableaux de bord :  1. Le tableau « Resilience-Alpha — Santé du service » pour connaître la santé globale du service et les indicateurs clés (IC) pertinents. 2. Le tableau « Resilience-Alpha — SOC » pour surveiller les événements de sécurité et les compteurs sur 15 minutes.  [1]

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _10.32 s; réponse; cite docs/runbooks/incident-response.md_
  > Un client peut renvoyer un virement après un incident sans risque d'être débité deux fois, car le formulaire renvoie la **même** clé `Idempotency-Key` [3].

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _17.16 s; réponse; cite docs/runbooks/incident-response.md_
  > Le détecteur d'anomalies expose à Prometheus un score `anomaly_score{service}` par service et le seuil `anomaly_threshold`. Prometheus évalue la règle `AnomalyDetected`, qui compare les deux, et Alertmanager transmet l'alerte au moteur de remédiation comme toute autre alerte. Le détecteur n'appelle jamais le moteur directement.  [1]

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _16.74 s; réponse; cite docs/governance/pca-pra.md_
  > Le RPO (âge des données restaurées) visé pour la base de paiement est de 0, ce qui signifie qu'il n'y a pas de valeur mesurée spécifique pour cette cible. Cependant, il y a une note dans le tableau [2] : « 0 par conception (virement en une transaction, idempotence) ».

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _7.61 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _7.4 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _7.21 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _25.64 s; réponse; sans citation_
  > Je ne peux pas redémarrer le conteneur payment-api directement. Pour cela, je dois suivre la procédure documentée :  1. Lire les causes avec `docker compose logs --tail 200 payment-api` et `docker inspect -f '{{.State.OOMKilled}} {{.State.ExitCode}}' resilience-alpha-payment-api-1` 2. Relancer l'API par Ansible depuis le poste de l'opérateur : `ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e service=payment-api` (voir « Redémarrer un service à la main avec Ansible »).

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _46.79 s; réponse; cite docs/runbooks/incident-response.md, docs/runbooks/restauration-base.md, docs/governance/pca-pra.md_
  > Pour restaurer la base de paiement après une corruption du registre, suivez les étapes suivantes :  1. Confirme que le registre est corrompu en vérifiant l'état de PostgreSQL et le contrôle d'intégrité (`GET /api/payments/admin/integrity`) [3]. 2. Si PostgreSQL est sain et le contrôle d'intégrité répond 409, utilise la restauration automatique du moteur de remédiation [1]. 3. Sinon, si le pont de restauration est disponible (heartbeat du runner de l'hôte plus vieux que 120 s), le moteur escalade (`bridge_unavailable`) et lance `resilience-pg-restore latest-healthy` pour choisir la dernière sauvegarde saine [2]. 4. Sauvegarde l'état courant (`pre-restore`) avant de restaurer la base, pour conserver une preuve de l'état corrompu [4]. 5. Arrête les API et recrée `authdb` et `paydb`, puis relance les API. 6. Vérifie que le registre est cohérent après la restauration.  N'oubliez pas que le moteur de remédiation effectue seul la restauration automatique, et que le runner revérifie le 409 avant de restaurer [1].

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _20.0 s; réponse; sans citation_
  > Un simple redémarrage ne suffit pas car il peut ne pas résoudre les problèmes sous-jacents qui ont entraîné l'incohérence du registre. Le contrôle d'intégrité du registre vérifie quatre règles de la comptabilité en partie double, notamment que chaque virement soit équilibré (une écriture de −montant et une de +montant). Un simple redémarrage peut ne pas garantir que ces règles soient respectées.

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _19.92 s; réponse; cite docs/runbooks/restauration-base.md_
  > Selon les mesures indiquées dans l'extrait [1], la restauration de la base sur le démonstrateur a duré :  - 19 secondes pour la corruption → alerte LedgerIntegrityBroken « firing », - 10,6 secondes pour la restauration (script, de la sélection au registre cohérent), - 19 secondes pour la restauration + transaction témoin (playbook complet).  Ces temps sont cumulatifs, donc le temps total mis par la restauration est de 49,6 secondes.

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _8.37 s; réponse; cite docs/governance/ebios-rm.md_
  > L'analyse EBIOS RM prévoit une réponse de bloquer l'IP [2].

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _15.24 s; réponse; cite docs/governance/ebios-rm.md_
  > Selon l'extrait [2], les événements redoutés avec une gravité maximale G4 sont :  *   Registre faux *   Moteur de remédiation détourné *   Paiement indisponible plus de 5 min *   Virement fait sans l'accord du client

- **q25** (answer) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _7.47 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q26** (gap) Quel numéro de téléphone faut-il appeler pour joindre l'astreinte quand le moteur escalade un incident ? — _7.91 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

### `mistral:latest`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _42.12 s; réponse; cite docs/runbooks/incident-response.md_
  > L'alerte `LedgerIntegrityBroken` indique qu'il y a un problème d'intégrité dans le registre de paiement, car payment-api expose `payment_ledger_integrité_ok == 0`. Pour vérifier l'état du registre, il faut vérifier si `payment_ledger_integrity_ok` est égal à 1 ou non. [4]

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _20.46 s; réponse; cite services/remediation-engine/README.md_
  > [1] - Sondes de bout en bout, puis transaction témoin (inscription, connexion, virement, soldes) à travers le WAF.

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _27.75 s; réponse; cite docs/runbooks/incident-response.md_
  > Le seul point d'entrée exposé sur le réseau du groupe est le WAF, servi par le port 8080 (ou 8088 si le fichier `.env` fixe `FRONT_PORT=8088`) [1].

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _42.87 s; réponse; cite docs/runbooks/incident-response.md_
  > Le contrôle d'intégrité du registre de paiement vérifie quatre règles de la comptabilité en partie double : - La somme de toutes les écritures est nulle. - Le solde de chaque compte est égal à la somme de ses écritures. - Chaque virement est équilibré (une écriture de −montant et une de +montant). - Aucun solde n'est négatif. [1]

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _40.37 s; réponse; cite docs/runbooks/incident-response.md, README.md, services/supervision-dashboard/README.md_
  > Les API retournent 503 `database_unavailable` [3] et leur état sur le dashboard affiche bleu pendant une restauration [4]. Elles ne redémarreront pas elles-mêmes, mais le moteur les redémarre si nécessaire selon la stratégie de redémarrage `ServiceDown` [1] ou `DependencyFailures` [2], en fonction de l'état de PostgreSQL.

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _22.4 s; réponse; cite docs/runbooks/incident-response.md_
  > `sum by (client_ip) (count_over_time({service="auth-service", event_type="auth_failure"} | json client_ip="client_ip" [1m]))` [4]

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _79.41 s; réponse; cite docs/runbooks/incident-response.md_
  > Redémarrer un service avec Ansible et vérifier sa reprise : 1. Exécuter la commande `sudo docker compose restart <nom_du_service>`. [4] 2. Après le redémarrage manuel, vérifier la reprise comme après une action du moteur : transaction témoin depuis le poste de l'opérateur (`python tests/smoke_test.py http://<adresse_IP>:8080`) avec 28 vérifications et code de sortie 0 = service rétabli. [4] 3. Vérifier également le panneau « Parcours client » de Grafana à OK, et contrôle d'intégrité du registre à 200. [4] 4. Sur le poste de développement, l'équivalent du playbook est `docker compose up -d --wait <nom_du_service>` suivi de `python tests/smoke_test.py http://127.0.0.1:8080`. [4]

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _45.37 s; réponse; cite services/remediation-engine/README.md_
  > Le moteur de remédiation communique avec Docker via `tecnativa/docker-socket-proxy:v0.5.0`, seul conteneur qui monte `/var/run/docker.sock` (en `:ro`) sur le réseau `docker-api` interne partagé avec lui. Il utilise uniquement les commandes `GET /containers/json`, `GET /containers/{id}/json` et `POST /containers/{id}/(restart|start|kill)`. [2]

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _24.81 s; réponse; cite services/remediation-engine/README.md_
  > Les alertes transmises au moteur de remédiation ne portent pas de labels spécifiques. Elles sont simplement envoyées par Alertmanager avec un jeton d'authentification [1].

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _109.65 s; réponse; cite docs/runbooks/incident-response.md_
  > 1. Vérifier si la même IP cumule plus de 10 échecs d'authentification sur auth-service en une minute [1]. 2. Si oui, le moteur valide l'IP du label `client_ip` : s'il est absente ou invalide, il escalade (`no_offender`) ; dans un réseau exclu du blocage, il escalade sans jamais la bloquer (`not_allowed`) ; si la liste de blocage du WAF est indisponible, il escalade (`waf_unavailable`) [4]. 3. Si l'IP est déjà bloquée, il vérifie seulement. Sinon il la bloque 300 s au WAF, puis vérifie le blocage chargé par le WAF, les sondes et la transaction témoin [4]. 4. Une même IP peut être bloquée 3 fois au plus sur 10 min ; un blocage en échec est retenté 10 s plus tard, 3 tentatives au plus, puis escaladé [4]. 5. Vérifier le rétablissement : le panneau « IP bloquées au WAF » du dashboard de supervision affiche l'IP et le compte à rebours de sa levée ; dans Grafana, « IP bloquées (WAF) » vaut 1 et « Refus du blocage WAF, par IP » montre les requêtes refusées de l'attaquant [3].

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _17.36 s; réponse; cite docs/securite/revue-durcissement.md_
  > Les interfaces de gestion sont publiées sur `127.0.0.1` uniquement [3].

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _18.67 s; réponse; cite docs/runbooks/incident-response.md_
  > Consulter les tableaux "Resilience-Alpha — Santé du service" et "Resilience-Alpha — SOC" [1].

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _31.77 s; réponse; cite docs/runbooks/incident-response.md_
  > Le virement renvoyé après un incident n'est jamais débité deux fois car l'en-tête `Idempotency-Key` est obligatoire et le formulaire renvoie la même clé après un incident, ce qui permet au système de reconnaître le second envoi et de ne jamais le débiter une seconde fois [3].

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _42.95 s; réponse; cite docs/runbooks/incident-response.md_
  > Le détecteur d'anomalies alimente la chaîne d'alertes en exposant à Prometheus un score `anomaly_score{service}` par service et le seuil `anomaly_threshold`. Prometheus évalue la règle `AnomalyDetected`, qui compare ces deux, et Alertmanager transmet l'alerte au moteur de remédiation comme toute autre alerte. Le détecteur n'appelle jamais le moteur directement [1].

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _23.23 s; réponse; cite docs/governance/pca-pra.md_
  > Le RPO visé pour la base de paiement est 0, car il s'agit d'une conception qui permet de virements en une transaction idempotente [2].

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _16.25 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _15.81 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _15.61 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _79.9 s; réponse; cite docs/runbooks/incident-response.md_
  > Je ne peux pas redémarrer directement le conteneur payment-api, car cela nécessite des actions manuelles. Voici la procédure documentée pour redémarrer un service à la main avec Ansible :  1. Lire d'abord la cause de l'incident avec `docker compose logs --tail 200 payment-api` et `docker inspect -f '{{.State.OOMKilled}} {{.State.ExitCode}}' resilience-alpha-payment-api-1`. 2. Redémarrer l'API par Ansible depuis le poste de l'opérateur : `ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e service=payment-api` (voir « Redémarrer un service à la main avec Ansible »).  Si une restauration manuelle de la base est en cours, ne rien relancer : attendre la fin du playbook de restauration. [2]

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _123.22 s; réponse; cite docs/runbooks/incident-response.md, docs/runbooks/restauration-base.md, docs/governance/pca-pra.md_
  > Pour restaurer la base de paiement après une corruption du registre, il faut suivre le runbook de restauration de la base de paiement (PRA « données corrompues »).  1. L'alerte à surveiller est **LedgerIntegrityBroken** [3]. Si le registre de paiement est incohérent, `GET /api/payments/admin/integrity` renvoie 409 avec le détail. 2. Si la base est perdue ou illisible (volume `pgdata` supprimé, modification malveillante des données), un redémarrage ne corrige pas des données corrompues : il faut restaurer une sauvegarde [3]. 3. Le moteur de remédiation effectue la restauration automatique si le registre est incohérent et PostgreSQL sain, avec un contrôle d'intégrité en 409 [2]. Sinon, il faut suivre les étapes manuelles du runbook. 4. La dernière sauvegarde saine choisie est la plus récente dont le registre était cohérent avant et après les dumps, empreintes SHA-256 vérifiées [4]. 5. Tout ce qui a été écrit depuis (15 min au pire) doit être reconstitué depuis les journaux `transfer` de Loki [4]. 6. La copie de l'état corrompu est sauvegardée avant d'être écrasé, pour l'investigation et pour pouvoir annuler [4]. 7. Le moteur ne choisit ni la command

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _53.2 s; réponse; cite docs/runbooks/incident-response.md_
  > Un simple redémarrage ne suffit pas quand le registre est incohérent car il n'est pas assuré que les données soient saines après une reprise, au-delà du simple redémarrage d'un conteneur [3]. Le contrôle d'intégrité du registre de paiement vérifie quatre règles de la comptabilité en partie double et il est possible qu'une incohérence soit détectée après un redémarrage. Il faut donc restaurer le registre à partir d'une sauvegarde saine pour corriger l'incohérence [1].

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _15.0 s; réponse; cite docs/runbooks/restauration-base.md_
  > 10,6 s pour la restauration (script) et 19 s pour la restauration complète [1].

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _12.52 s; réponse; cite docs/governance/ebios-rm.md_
  > Bloquer l'IP [1]

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _24.74 s; réponse; cite docs/governance/ebios-rm.md_
  > Les événements redoutés ayant une gravité maximale G4 sont les suivants : - Registre faux [2] - Moteur de remédiation détourné [2]

- **q25** (answer) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _16.7 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point. [1]

- **q26** (gap) Quel numéro de téléphone faut-il appeler pour joindre l'astreinte quand le moteur escalade un incident ? — _17.13 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

