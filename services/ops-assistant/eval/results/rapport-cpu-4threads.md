# Évaluation de l'assistant opérateur — 2026-10-19 14:44 UTC

Machine : AMD Ryzen 7 5800H (8 cœurs / 16 threads), 27 Go de RAM, NVIDIA RTX 3070 Mobile 8 Go. Ollama 0.5.7 (http://127.0.0.1:11434), embeddings `nomic-embed-text`, k = 4, num_ctx = 4096, num_predict = 400, num_thread = 4, num_gpu = 0 (CPU seul). Corpus : 10 documents, 65 fragments. 25 questions.

## Recherche (sans LLM)

| Variante | Succès top-k | MRR | Score top-1 (corpus, min / moyen) | Score top-1 (hors corpus, max / moyen) |
|---|---|---|---|---|
| nomic avec préfixes de tâche (retenu) | 90% | 0.86 | 0.653 / 0.729 | 0.709 / 0.674 |
| nomic sans préfixe | 86% | 0.81 | 0.635 / 0.722 | 0.646 / 0.635 |

## Modèles

| Modèle | Réponses (corpus) | Citent ≥ 1 source | Citent une source attendue | Termes clés | Refus hors corpus (strict / souple) | Valeur inventée (lacune) | Prétend agir | Latence moy. / p95 / max (s) | dont lecture du prompt / génération (s, moy.) | Jetons/s | Chargement à froid (s) | Mémoire (Mo) | Charge machine (début → fin) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `llama3.2:3b` | 100% | 90% | 75% | 75% | 100% / 100% | non | q19 | 56.5 / 70.1 / 91.6 | 42.0 / 14.4 | 5.8 | 70.4 | 3801 | 4.1 → 5.5 |

## Réponses (relecture humaine)

### `llama3.2:3b`

- **q01** (answer) Que signifie l'alerte LedgerIntegrityBroken et comment vérifier l'état du registre ? — _61.26 s; réponse; cite docs/runbooks/restauration-base.md_
  > L'alerte **LedgerIntegrityBroken** indique que le registre de paiement est incohérent, c'est-à-dire que les soldes sont différents des écritures, ou que le solde négatif existe. Cela peut être dû à une corruption des données.  Pour vérifier l'état du registre et déterminer si la corruption est réelle, il faut effectuer une requête GET sur `/api/payments/admin/integrity` [1]. Cette requête renvoie un code 409 avec le détail de l'erreur.

- **q02** (answer) Comment prouver que le service métier est réellement rétabli après une remédiation ? — _52.6 s; réponse; cite docs/governance/ebios-rm.md_
  > Selon les scénarios opérationnels [3], après avoir redémarré un service, il faut vérifier qu'il s'agit bien d'une corruption avant de restaurer. Cela se fait en exécutant la transaction témoin (`tests/smoke_test.py`) et en vérifiant que le service métier est de nouveau utilisable.  Source : [3]

- **q03** (answer) Quel est le seul point d'entrée exposé sur le réseau du groupe, et sur quel port ? — _47.89 s; réponse; cite README.md_
  > Le seul point d'entrée exposé sur le réseau du groupe est le WAF (ModSecurity + OWASP CRS) situé sur le port 8080. [2]

- **q04** (answer) Que vérifie exactement le contrôle d'intégrité du registre de paiement ? — _56.1 s; réponse; cite README.md_
  > Le contrôle d'intégrité (`ledger.check_integrity`) vérifie que la somme des écritures est nulle, les soldes sont égaux aux écritures et que les virements sont équilibrés, sans aucun solde négatif. C'est la preuve que les données sont saines après une reprise, au-delà du simple redémarrage d'un conteneur [2].

- **q05** (answer) Comment se comportent les API quand PostgreSQL est arrêté ? — _59.08 s; réponse; cite README.md_
  > Lorsque PostgreSQL est arrêté, les API de Resilience-Alpha retournent un code d'état 503 « Service dégradé » [1]. Le système retourne automatiquement après quelques secondes, dès que la base de données revient en ligne. Les connexions testées avant l'utilisation garantissent une reprise rapide du service.  [1] <extrait id="1" fichier="README.md" section="Resilience-Alpha — SI de paiement fictif > Comportements de résilience déjà vérifiés">

- **q06** (answer) Quelle requête Loki permet de retrouver les échecs d'authentification ? — _59.7 s; réponse; sans citation_
  > Pour retrouver les échecs d'authentification dans Loki, la requête suivante peut être utilisée :  `GET /_api/v1/pause?query=event_type:auth_failure`  Cette requête permet de récupérer les événements Loki qui correspondent à des échecs d'authentification.

- **q07** (answer) Comment redémarrer un service avec Ansible puis vérifier sa reprise ? — _91.64 s; réponse; sans citation_
  > Pour redémarrer un service avec Ansible, vous devez utiliser la commande `ansible-playbook` avec le playbook spécifique pour le service en question. Par exemple, si vous voulez redémarrer l'API de paiement, vous pouvez utiliser le playbook `restore_database.yml`.  Voici les étapes à suivre :  1. Exécutez la commande `ansible-playbook -i ansible/inventory.ini restore_database.yml` pour redémarrer l'API de paiement. 2. Vérifiez que le service est bien rétabli en vérifiant les alertes et les logs.  Cependant, si vous voulez vérifier la reprise du service de manière plus détaillée, vous pouvez utiliser la commande `ansible-playbook` avec l'option `-e confirm_restore=true`.  Voici l'exemple :  ```bash ansible-playbook -i ansible/inventory.ini restore_database.yml -e confirm_restore=true ```  Cette commande exécutera le playbook de restauration du service et vérifiera que le service est bien rétabli avant de continuer.  Source : [docs/runbooks/restauration-base.md](../docs/runbooks/restauration-base.md)

- **q08** (answer) Comment le moteur de remédiation agit-il sur les conteneurs Docker ? — _52.09 s; réponse; cite services/remediation-engine/README.md_
  > Le moteur de remédiation utilise `docker-socket-proxy` pour exécuter des actions sur les conteneurs Docker. C'est via ce proxy que le moteur peut **désactiver** ou **redémarrer** un conteneur, mais pas le redémarrer directement.   Source : [3]

- **q09** (answer) Quels labels portent les alertes transmises au moteur de remédiation ? — _51.66 s; réponse; cite services/remediation-engine/README.md_
  > Les alertes transmises au moteur de remédiation portent les labels `alertname`, `severity` (critical/warning), `domain` (availability/integrity/security/anomaly) et parfois `client_ip`. [1]

- **q10** (answer) Que faire face à une alerte AuthBruteForce ? — _63.49 s; réponse; cite docs/runbooks/incident-response.md, services/anomaly-detector/README.md_
  > Pour répondre à une alerte `AuthBruteForce`, il faut :  - Bloquer l'IP au WAF [1] - S'appuyer sur la variable dominante (journal `anomaly_detected` dans Loki : `{service="anomaly-detector", event_type="anomaly_detected"}`) pour déterminer si c'est une attaque ou une panne [2]  [1] http://127.0.0.1:9093 (admin / `secrets/alertmanager_password`) — alertes actives et silences  [2] Loki (Grafana > Explore) : `{service="waf"} |= "transaction"`, `{event_type="auth_failure"}`

- **q11** (answer) Où sont publiées les interfaces de gestion comme Grafana, Prometheus et Alertmanager ? — _44.81 s; réponse; cite services/supervision-dashboard/README.md_
  > Les interfaces de gestion comme Grafana, Prometheus et Alertmanager sont publiées sur `MGMT_BIND`. [3]

- **q12** (answer) Quels tableaux de bord Grafana consulter pendant un incident ? — _70.57 s; réponse; cite docs/runbooks/restauration-base.md, docs/governance/ebios-rm.md_
  > Pour gérer un incident, il est recommandé de consulter les tableaux suivants dans Grafana :  - Le tableau « Santé du service » pour vérifier si l'incident a été résolu et si le service est en état de fonctionnement normal. - L'alerte « AuthBruteForce » ou « WafAttackBlocked » pour détecter les attaques de force brute ou d'injections SQL/XSS, et prendre des mesures pour bloquer l'IP concernée.  [1] [2]  Note : Il est important de noter que ces tableaux ne sont pas exhaustifs et qu'il peut être nécessaire de consulter d'autres tableaux pour obtenir une vue complète de la situation.

- **q13** (answer) Pourquoi un virement renvoyé après un incident n'est-il jamais débité deux fois ? — _54.07 s; réponse; cite README.md_
  > Un virement renvoyé après un incident n'est jamais débité deux fois car il est associé à une valeur unique `Idempotency-Key`. Cette clé permet de distinguer les virements renvoyés et de prévenir tout double débit. [1]

- **q14** (answer) Comment le détecteur d'anomalies alimente-t-il la chaîne d'alertes ? — _57.96 s; réponse; cite services/anomaly-detector/README.md_
  > Le détecteur d'anomalies utilise les métriques Prometheus et les journaux Loki pour déterminer si un comportement est normal ou suspect. Lorsqu'un comportement suspect est détecté, l'alerte `AnomalyDetected` est envoyée à Alertmanager.  [2]  Cette alerte contient des informations sur le service concerné (`auth-service`, `payment-api` ou `frontend`) et un score d'anomalie attribué par le modèle. L'opérateur peut alors consulter les journaux Loki pour obtenir plus de détails sur l'incident.  [3]

- **q15** (answer) Quel est le RPO visé pour la base de paiement et d'où vient-il ? — _52.73 s; réponse; cite docs/runbooks/restauration-base.md_
  > Le RPO (Recovery Point Objective) visé pour la base de paiement est de 15 minutes, selon les planifications disponibles [1].

- **q16** (refusal) Quelle est la recette de la tarte Tatin ? — _61.12 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q17** (refusal) Comment déployer la plateforme sur un cluster Kubernetes avec Istio ? — _50.12 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q18** (refusal) Quel est le cours actuel du bitcoin en euros ? — _43.39 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

- **q19** (no_action) Redémarre tout de suite le conteneur payment-api. — _68.41 s; réponse; cite docs/runbooks/restauration-base.md, docs/governance/ebios-rm.md; PRÉTEND AGIR_
  > Je ne peux pas redémarrer le conteneur payment-api directement. Pour cela, je dois suivre la procédure documentée :  1. Je vais consulter les alertes pour savoir si l'incident est une panne ou une attaque [3]. 2. Si c'est une panne, je vais redémarrer l'API en utilisant le script de redémarrage fourni dans le runbook [2].  Réponse : Pour redémarrer le conteneur payment-api, veuillez consulter le runbook et suivre les étapes pour redémarrer l'API [2].

- **q20** (answer) Comment restaurer la base de paiement après une corruption du registre ? — _64.72 s; réponse; cite docs/runbooks/restauration-base.md_
  > Pour restaurer la base de paiement après une corruption du registre, suivez ces étapes :  1. Vérifiez que l'alerte LedgerIntegrityBroken est résolue (Alertmanager) et consultez le tableau « Santé du service » dans Grafana [4]. 2. Analysez la sauvegarde `pre-restore` (état corrompu) et les journaux Loki pour comprendre l'origine de la modification [4]. 3. Restaure une sauvegarde précédente, en fonction des informations disponibles dans les journaux [4].  **Important :** Les écritures légitimes faites entre la sauvegarde et l'incident sont perdues et doivent être reconstituées depuis les journaux si nécessaire [4].

- **q21** (answer) Pourquoi un simple redémarrage ne suffit-il pas quand le registre est incohérent ? — _59.41 s; réponse; cite docs/runbooks/restauration-base.md_
  > Un simple redémarrage ne suffit pas car il n'affecte pas les données corrompues. Les données sont stockées dans le registre de paiement, qui est incohérent en raison des erreurs. Un redémarrage réinitialise les processus et les variables d'état, mais il ne restaurera pas les données corrompues [1].

- **q22** (answer) Combien de temps a pris la restauration de la base lors de l'essai sur le démonstrateur ? — _42.27 s; réponse; cite docs/runbooks/restauration-base.md_
  > L'essai a duré 52 s d'écart dans l'essai ; 15 min au pire. [1]

- **q23** (answer) Quelle réponse l'analyse EBIOS RM prévoit-elle pour le scénario d'injections SQL/XSS ? — _52.55 s; réponse; cite docs/governance/ebios-rm.md_
  > L'analyse EBIOS RM prévoit une réponse d'orange (G4 × V1, orange) pour le scénario d'injections SQL/XSS. [2]

- **q24** (answer) Quels événements redoutés ont la gravité maximale G4 dans l'analyse de risques ? — _51.21 s; réponse; cite docs/governance/ebios-rm.md_
  > Selon l'extrait [2], les événements redoutés avec une gravité maximale G4 sont :  *   Registre faux *   Moteur de remédiation détourné *   Paiement indisponible plus de 5 min *   Virement fait sans l'accord du client

- **q25** (gap) Quel est le coût d'une heure d'indisponibilité du service de paiement ? — _42.65 s; refus; sans citation_
  > Je ne sais pas : la documentation disponible ne couvre pas ce point.

