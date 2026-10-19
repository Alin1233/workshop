# Reste à faire, par domaine

État au 19/10/2026. ✅ = livré et vérifié, ☐ = à faire. Le détail de chaque composant se trouve dans le README de son dossier.

## Développement
- ✅ SI de paiement : auth (JWT RS256), API de paiement (partie double, idempotence, contrôle d'intégrité), front React/Tailwind, PostgreSQL
- ☐ **Moteur de remédiation** (`services/remediation-engine/`) : webhook Alertmanager → décision → action → vérification par transaction témoin. **C'est l'élément décisif pour la note (0/5 si la reprise n'est pas autonome en direct)**
- ☐ **Dashboard de supervision React/Tailwind** (`services/supervision-dashboard/`) : composants, alertes, chronologie de la reprise (écran du Clip Chrono)
- ✅ Documentation d'API exportée dans `docs/api/` (`scripts/export_openapi.py`, vérifiée par les tests)
- ✅ Tests unitaires pytest (`tests/unit/`, 49 tests sur PostgreSQL jetable) + CI GitHub Actions
- ☐ Tests du front React (aucun pour l'instant)

## Infrastructure
- ✅ Docker Compose : réseaux segmentés (edge/dmz/app/data/obs/mgmt/ai), conteneurs durcis, interfaces de gestion sur 127.0.0.1
- ✅ Prometheus (11 cibles, sondes de bout en bout blackbox à travers le WAF, 12 règles d'alerte)
- ✅ Loki + Alloy (journaux de tous les conteneurs, sans socket Docker), Alertmanager (routé vers la remédiation)
- ✅ Grafana provisionné : tableaux « Santé du service » et « SOC » (`infra/grafana/generate_dashboards.py`)
- ✅ VM PC Hôte provisionnée sur le Proxmox du labo par Ansible (`ansible/provision_proxmox.yml`) : `172.16.147.10`, Debian 13, 6 vCPU / 16 Go / 80 Go
- ✅ VM préparée par `ansible/prepare_host.yml` : Docker 29 + Compose, pare-feu nftables compatible Docker, SSH durci, mises à jour de sécurité
- ✅ Stack déployée sur la VM par `ansible/deploy.yml` (une version par commit, retour arrière, tests sur l'hôte et à travers le réseau) ; reprise d'un service par `restart_service.yml`
- ✅ Sauvegarde PostgreSQL toutes les 15 min avec état d'intégrité du registre, restauration de la dernière sauvegarde saine (`backup_database.yml`, `restore_database.yml`, runbook `docs/runbooks/restauration-base.md`) : corruption détectée en 19 s, restauration en 10,6 s
- ✅ PC Hôte et sauvegardes supervisés : node-exporter (sans socket Docker), alertes disque, mémoire, sauvegarde manquante ou en échec, rangée dédiée dans « Santé du service »
- ☐ cAdvisor / postgres-exporter : non déployés (le contrat du détecteur d'anomalies n'utilise que des métriques applicatives ; cAdvisor exige le socket Docker) — à rouvrir si le pilier IA en a besoin
- ☐ Point d'accès RESILIENCE-G6 : le PC Hôte est une VM du labo (172.16.147.10), joignable par le wifi labo et non par un point d'accès du groupe — **à faire valider par le coach** (tous les postes y arrivent avec la même IP, 172.16.255.252)
- ☐ README de déploiement final vérifié sur une machine vierge

## IA / Data
- ☐ **Détecteur d'anomalies ML** (`services/anomaly-detector/` + `ml/`) : jeu de données normal/attaque, modèle, `anomaly_score` exposé à Prometheus, règle `AnomalyDetected` à décommenter
- ☐ **Assistant RAG** (`services/ops-assistant/`) : Ollama (≤ 8 milliards de paramètres) + LangChain sur `docs/`, sans accès privilégié
- ☐ Choisir où tourne le LLM (PC Hôte, 3e PC, ou `--profile ai`) selon la RAM disponible
- ☐ Rédiger données / préparation / modèle / résultats / limites pour le dossier

## Cybersécurité
- ✅ WAF ModSecurity + OWASP CRS en unique point d'entrée (SQLi/XSS bloquées en 403, IP réelle propagée jusqu'aux API)
- ✅ SOC intégré : 5 règles LogQL (force brute, rafale de jetons invalides, blocages WAF, violations d'intégrité, pannes de dépendance) → Alertmanager — testées
- ✅ Script SOPS + age (`scripts/sops_secrets.py`) — **non testé** (sops/age absents du poste)
- ☐ Générer les clés age de l'équipe, remplir `.sops.yaml`, chiffrer et versionner `secrets.enc.json`
- ☐ Sécuriser l'accès du moteur de remédiation à Docker (docker-socket-proxy restreint, webhook authentifié)
- ☐ Revue de durcissement (Trivy, mots de passe, en-têtes, réglage du niveau de paranoïa du WAF)

## Transformation / Gouvernance
- ☐ EBIOS RM (`docs/governance/ebios-rm.md`), relié aux alertes et aux remédiations réelles
- ☐ PCA/PRA avec RTO/RPO **mesurés** sur le démonstrateur (`docs/governance/pca-pra.md`) ; premières mesures (restauration de la base) dans `docs/runbooks/restauration-base.md`
- ☐ Analyse NIS2/DORA : exigences pertinentes vs démontrables (`docs/governance/nis2-dora.md`)
- ☐ Runbooks (`docs/runbooks/`) — servent aussi de corpus au RAG

## Rendus (jeudi 23h59)
- ☐ `Workshop2026-M2-G<n>-Dossier.pdf` (8-12 pages, contribution de chacun)
- ☐ `Workshop2026-M2-G<n>-Pres.pptx`
- ☐ `Workshop2026-M2-G<n>-VidChrono.mp4` (≤ 60 s, plan continu : incident → anomalie → réaction → service rétabli)
- ☐ `Workshop2026-M2-G<n>-Code.zip` (aucun secret en clair : vérifier que `secrets/` est exclu)
