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
- ✅ Prometheus (10 cibles, sondes de bout en bout blackbox à travers le WAF, 7 règles d'alerte)
- ✅ Loki + Alloy (journaux de tous les conteneurs, sans socket Docker), Alertmanager (routé vers la remédiation)
- ✅ Grafana provisionné : tableaux « Santé du service » et « SOC » (`infra/grafana/generate_dashboards.py`)
- ☐ Tester les playbooks Ansible (`ansible/`) depuis WSL ; écrire la sauvegarde/restauration PostgreSQL
- ☐ Métriques conteneurs et base (cAdvisor / postgres-exporter) si le ML en a besoin — attention à la RAM et aux privilèges
- ☐ Configurer le point d'accès Windows RESILIENCE-G<n> (192.168.137.1) et le pare-feu ; tester depuis un autre poste
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
- ☐ **Scénario d'attaque principal** depuis le PC Attaquant (`attacks/`) + 1 ou 2 secondaires
- ☐ Sécuriser l'accès du moteur de remédiation à Docker (docker-socket-proxy restreint, webhook authentifié)
- ☐ Revue de durcissement (Trivy, mots de passe, en-têtes, réglage du niveau de paranoïa du WAF)

## Transformation / Gouvernance
- ☐ EBIOS RM (`docs/governance/ebios-rm.md`), relié aux alertes et aux remédiations réelles
- ☐ PCA/PRA avec RTO/RPO **mesurés** sur le démonstrateur (`docs/governance/pca-pra.md`)
- ☐ Analyse NIS2/DORA : exigences pertinentes vs démontrables (`docs/governance/nis2-dora.md`)
- ☐ Runbooks (`docs/runbooks/`) — servent aussi de corpus au RAG

## Rendus (jeudi 23h59)
- ☐ `Workshop2026-M2-G<n>-Dossier.pdf` (8-12 pages, contribution de chacun)
- ☐ `Workshop2026-M2-G<n>-Pres.pptx`
- ☐ `Workshop2026-M2-G<n>-VidChrono.mp4` (≤ 60 s, plan continu : attaque → anomalie → réaction → service rétabli)
- ☐ `Workshop2026-M2-G<n>-Code.zip` (aucun secret en clair : vérifier que `secrets/` est exclu)
