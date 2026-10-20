# PCA / PRA — Resilience-Alpha

Plan de continuité (PCA : tenir pendant l'incident) et de reprise d'activité (PRA : revenir à un service utilisable) de la plateforme de virements fictive. Pilier Transformation / Gouvernance, mis à jour le 20/10/2026. Les **coûts sont fictifs** (hypothèses H1 à H8, § 2.2) et restent **à valider en équipe** ; chaque durée vient d'un essai dont l'environnement est indiqué.

**Légende des mesures** : **[local]** pile Docker du poste de développement ; **[VM]** PC Hôte ou VM de recette sur le Proxmox du labo ; **[non mesuré]** objectif ou comportement attendu, sans chronométrage. Aucun essai n'a encore été fait depuis un vrai second poste : l'attaquant des recettes est un conteneur du réseau `edge`.

Documents liés : [EBIOS RM](ebios-rm.md) (scénarios S1 à S6), [NIS2 / DORA](nis2-dora.md) (classification, notification), [réponse à incident](../runbooks/incident-response.md) (conduite alerte par alerte), [restauration de la base](../runbooks/restauration-base.md), [recette du moteur](../../services/remediation-engine/docs/recette.md).

## Synthèse pour la direction

- **Fonction la plus critique : exécuter un virement.** Durée maximale d'interruption admissible (DMIA) : **5 min**, seuil de l'événement redouté « paiement indisponible plus de 5 min » (EBIOS, G3). Coût fictif d'un arrêt : 240 € à 5 min, ≈ 18,5 k€ à 30 min, ≈ 26 k€ à 1 h, ≈ 160 k€ à 2 h ; au-delà de 5 min, pénalités des partenaires et départs de clients dominent.
- **Panne d'API rétablie et vérifiée sans humain en 43 à 46 s [local]**, transaction témoin comprise, soit ≈ 37 € de coût fictif. 85 % de ce délai sert à confirmer et acheminer l'alerte (choix délibéré) ; le moteur réagit en ≈ 7 s.
- **Compromissions confinées** en 29,5 s (force brute) et 32,5 s (injections) par les règles SOC, en 66 à 88 s par le détecteur ML [local] ; **registre corrompu restauré et vérifié en 31,9 s [local]**, avec une perte de données bornée à 15 min (52 s dans l'essai [VM]).
- **Perte du PC Hôte reconstruite en ≈ 6 min 16 [VM]**, mais ce PRA est **incomplet** : sans séquestre des secrets (SOPS pas encore en place), le compte admin restauré est inaccessible, et les données perdues remontent à la dernière copie hors hôte, faite à la main.
- **Écart principal : personne n'est prévenu d'une escalade.** Ce que le moteur ne sait pas corriger n'est vu que si quelqu'un regarde l'écran : incompatible avec le délai de notification DORA de 4 h.
- **Arbitrage** : la disponibilité est rétablie automatiquement ; une compromission est **confinée** automatiquement (blocage, restauration), mais son **éradication** (secrets, comptes, cause) reste humaine. Un service rétabli ne clôt pas un incident de sécurité.
- **À prouver avant le jury** : rejouer sur la VM depuis un vrai second poste. Au labo, tous les postes partagent l'IP NAT 172.16.255.252 : bloquer l'attaquant bloque aussi le jury pendant la durée du blocage.
- **Investissements recommandés** : d'abord séquestre des secrets, alerte humaine et copie hors hôte chiffrée (≈ 2 j·h) ; puis restauration à un instant donné (PITR), qui ramène la perte de données de 15 min à quelques secondes ; enfin PostgreSQL haute disponibilité et second site.

## 1. Périmètre et contexte

**Entité fictive** : établissement de paiement agréé de taille moyenne exploitant sa propre plateforme de virements (hypothèse de [nis2-dora.md](nis2-dora.md) § 1 : DORA s'applique, autorité compétente ACPR).

**Périmètre technique** : la solution livrée, sur un seul PC Hôte (VM Debian 13 `172.16.147.10`, 6 vCPU / 16 Go, Proxmox du labo) déployé par Ansible. Parcours client : WAF (ModSecurity + OWASP CRS, seul port publié) → frontal React → `auth-service` (JWT RS256 de 15 min) et `payment-api` (registre en partie double, idempotence, contrôle d'intégrité) → PostgreSQL (`authdb`, `paydb`). Chaîne de résilience : Prometheus (16 règles) et Loki (5 règles SOC), détecteur ML → Alertmanager → moteur de remédiation → proxy Docker, liste de blocage du WAF, pont de restauration de l'hôte. Hors périmètre : réseau et Proxmox du labo, poste de l'opérateur.

**Ce que « continuité » veut dire ici.** Le service est **rétabli** quand un client peut de nouveau faire un virement exact, pas quand un conteneur redémarre. Le moteur ne déclare un incident rétabli qu'après contrôle des conteneurs, des sondes de bout en bout et une **transaction témoin** passée par le WAF (deux comptes neufs, connexion, virement de 1,00 € avec clé d'idempotence, contrôle des deux soldes). Trois objectifs à ne pas confondre :

| Objectif | Question | Exemple | Automatisé ? |
|---|---|---|---|
| Rétablir la disponibilité | le client peut-il payer ? | redémarrer `payment-api` | oui |
| Confiner une compromission | l'attaque ou la donnée fausse est-elle arrêtée ? | bloquer l'IP, restaurer la dernière sauvegarde saine | oui, dans les limites du § 5 |
| Éradiquer et réparer | cause supprimée, pertes reconstituées, autorités prévenues ? | rotation des secrets, reconstitution des virements, notification | non (§ 5.5, § 6) |

## 2. Analyse d'impact sur l'activité (BIA)

### 2.1 Fonctions critiques et dépendances

| Fonction | Dépendances techniques | Événement redouté (EBIOS) | Particularité de l'architecture |
|---|---|---|---|
| F1 Exécuter un virement | WAF → frontal → `payment-api` → `paydb` | « Paiement indisponible plus de 5 min » (G3) | `payment-api` vérifie le JWT avec la clé publique, sans appeler `auth-service` |
| F2 S'authentifier | WAF → frontal → `auth-service` → `authdb` | « Virement fait sans l'accord du client » (G3), si une force brute réussit | une session ouverte survit jusqu'à 15 min à une panne d'`auth-service` |
| F3 Garantir l'intégrité du registre | `payment-api`, PostgreSQL, contrôle toutes les 15 s, sauvegardes saines | « Registre faux » (G4) | le contrôle voit une incohérence (soldes ≠ écritures, virement déséquilibré, solde négatif), pas une fraude équilibrée |
| F4 Observer et reprendre | Prometheus, Loki, Alertmanager, détecteur, moteur, proxy Docker, pont, Grafana, dashboard | « Moteur détourné » (G4), « Logs perdus ou modifiés » (G2) | tout est sur le PC Hôte : sa perte emporte aussi l'observation et les preuves |

### 2.2 Hypothèses de coût (fictives, à valider)

| # | Hypothèse | Valeur retenue |
|---|---|---|
| H1 | Volume | 1 000 000 clients actifs ; 288 000 virements par jour ouvré sur 12 h, soit **400 virements/min** (pics non modélisés) |
| H2 | Montant moyen | 250 €, soit 100 000 €/min de flux retardés (un retard pour les partenaires, pas une perte comptable) |
| H3 | Revenu | 0,40 € de commission par virement, soit **160 €/min** |
| H4 | Abandon (virement jamais représenté) | 10 % pendant les 5 premières minutes (le client renvoie, l'idempotence évite le double débit), 30 % de 5 à 30 min, 50 % au-delà |
| H5 | Pénalités des partenaires (SLA) | 2 000 € par tranche de 15 min entamée au-delà des 5 premières minutes, plafond 50 000 € par incident |
| H6 | Coûts opérationnels | cellule de crise de 6 personnes à 100 €/h dès que l'incident dépasse 5 min ; 2 % des virements touchés font un appel au support à 4 € |
| H7 | Réputation (attrition) | 100 clients (0,01 %) partent entre 5 min et 1 h ; 1 000 (0,1 %) de plus par heure entamée ensuite ; valeur d'un client 120 € |
| H8 | Reconstitution après restauration | 2 € par virement perdu (contrôle et ré-imputation depuis les journaux `transfer`) |

### 2.3 Coût d'un arrêt du virement (F1) selon sa durée

| Durée | Commissions (H3, H4) | Pénalités (H5) | Crise et support (H6) | Attrition (H7) | **Total** |
|---|---|---|---|---|---|
| 46 s (reprise automatique mesurée) | 12 € | 0 | 25 € | 0 | **≈ 37 €** |
| 5 min (DMIA) | 80 € | 0 | 160 € | 0 | **240 €** |
| 30 min (astreinte humaine efficace) | 1 280 € | 4 000 € | 1 260 € | 12 000 € | **18 540 €** |
| 1 h | 3 680 € | 8 000 € | 2 520 € | 12 000 € | **26 200 €** |
| 2 h | 8 480 € | 16 000 € | 5 040 € | 132 000 € | **161 520 €** |
| 4 h | 18 080 € | 32 000 € | 10 080 € | 372 000 € | **432 160 €** |

Lecture : le coût change de régime à **5 min** (pénalités, départs), ce qui fonde la DMIA de F1. La reprise automatique vaut, à chaque panne, l'écart entre ≈ 37 € et le coût d'une intervention humaine : ≈ 18,5 k€ si une astreinte agit en 30 min, beaucoup plus si personne n'est prévenu. Le tableau se recalcule en changeant H1 à H7.

### 2.4 Coût des autres fonctions

- **F2 Authentification** : les nouvelles connexions échouent aussitôt ; les clients déjà connectés paient jusqu'à l'expiration de leur jeton (15 min). Hypothèse : la moitié du coût de F1 pendant 15 min, le même coût ensuite.
- **F3 Intégrité** : le coût se compte par incident. Restaurer la dernière sauvegarde saine efface les écritures légitimes faites depuis : au pire 15 min, soit jusqu'à **6 000 virements (1,5 M€)** à reconstituer (12 000 € selon H8, plus les réclamations de clients qui voient un virement disparaître) ; 52 s dans l'essai du 19/10 [VM], soit ≈ 350 virements (≈ 700 €). S'y ajoute l'exposition réglementaire (§ 2.6).
- **F4 Observation et reprise** : aucun coût direct tant que le métier tourne, mais toute panne survenue pendant son absence redevient manuelle, et la DMIA de F1 n'est plus tenable sans astreinte.

### 2.5 DMIA et perte de données admissible par fonction

| Fonction | DMIA | Perte de données maximale admissible (PDMA) | Justification |
|---|---|---|---|
| F1 Virement | 5 min | aucun virement **confirmé** perdu lors d'une panne ; 15 min acceptés lors d'une restauration (EBIOS § 5) | changement de régime de coût (§ 2.3) |
| F2 Authentification | 5 min pour les nouvelles connexions, 15 min pour les sessions ouvertes | 15 min (comptes créés, mots de passe changés depuis la sauvegarde) | durée du jeton |
| F3 Intégrité | aucune tolérance à servir des soldes faux : confiner dès la détection ; restaurer en 5 min | 15 min pour le démonstrateur ; quasi nulle en contexte industriel (§ 9.2) | G4 ; une restauration détruit aussi des écritures saines |
| F4 Observation et reprise | 30 min (le temps de mettre un humain dans la boucle) | journaux : 7 jours de rétention ; chronologie des incidents : à conserver, c'est la preuve pour la notification | sans F4, la DMIA de F1 repose sur un humain |

### 2.6 Lien avec l'incident majeur au sens de DORA

La classification suit les critères rappelés dans [nis2-dora.md](nis2-dora.md) (clients touchés, durée, pertes de données, criticité du service, impact économique et réputationnel) ; le § 2.3 alimente le critère économique. Lecture commune avec nis2-dora.md § 3 : une panne d'API corrigée en moins d'une minute reste **mineure** (enregistrée, non notifiée) ; une corruption du registre (S5) touche un service critique et suppose un accès malveillant aux données : **probablement majeure**, même restaurée en 32 s. Déclencheurs internes proposés pour **ouvrir** l'examen de classification (pas pour conclure) : compromission de données confirmée (S5, fuite), F1 indisponible au-delà de la DMIA, escalade non résolue en 30 min. Les seuils chiffrés des normes techniques de DORA sur la classification restent à reprendre en équipe.

## 3. Objectifs RTO / RPO et valeurs mesurées

### 3.1 Cibles et mesures

RTO : de la perturbation au service **vérifié** par la transaction témoin. Pour une attaque, « confinement » : de son début à l'IP bloquée et vérifiée. RPO : âge des données restaurées. Les cibles découlent du § 2.5 : 2 min pour une panne laissent sous la DMIA de 5 min la place d'une seconde tentative, puis d'une escalade.

| Scénario | Grandeur | Cible | Mesuré | Où | Source | Écart |
|---|---|---|---|---|---|---|
| Panne d'API (S3) | RTO | ≤ 2 min | 46 s ; 43 s au 2e essai | [local] | moteur README « Tester » ; supervision README « Recette » | tenu ; pas encore rejoué sur la VM |
| Panne d'API (S3) | réaction du moteur (webhook → vérifié) | — | 6,7 s ; 7,0 s ; 17,0 s lors d'une revérification | [local] | TODO ; supervision README ; TODO (rangée Grafana) | dispersion non expliquée : mesurer une série |
| Panne d'API (S3) | RPO | 0 | 0 par conception (virement en une transaction, idempotence) | [non mesuré] | README racine, « Modèle métier » | tester un virement en vol pendant l'arrêt |
| Base injoignable (S4) | RTO | ≤ 2 min | comportement vérifié (503, retour seul), durée non relevée | [local] | README racine | à chronométrer |
| Saturation (S3) | RTO | ≤ 5 min | aucune action avant ≈ 4 min (`for: 1m` + 3 min d'observation) ; un redémarrage ne règle pas la surcharge | [local] | revue § 7.3 ; moteur README | non tenu |
| Force brute (S1) | confinement | ≤ 1 min | 29,5 s | [local] | recette § 1 | tenu ; effet du NAT non mesuré |
| Injections (S2) | confinement | ≤ 1 min | 32,5 s | [local] | recette § 2 | tenu |
| Attaque lente vue par le ML (S1) | confinement | ≤ 2 min | 65,8 s (force brute à 9/min) ; 87,5 s (jetons invalides à 15/min) ; à 5/min : escalade sans blocage | [local] | recette § 4B, § 4C | tenu si l'IP est attribuable |
| Registre corrompu (S5) | RTO automatique | ≤ 5 min | 31,9 s (pont, runner de développement) | [local] | recette § 3 | pont non éprouvé sur la VM |
| Registre corrompu (S5) | RTO par l'opérateur | — | alerte en 19 s, playbook en 19 s, hors temps de décision humaine | [VM] | runbook restauration | |
| Registre corrompu (S5) | restauration seule | — | 10,6 s (script) [VM] ; 10,8 s et 9,9 s (script), 11,0 à 12,0 s de la demande au résultat (pont) [local] | [VM], [local] | runbook restauration | |
| Registre corrompu (S5) | RPO | ≤ 15 min | 52 s dans l'essai ; borne de 15 min (timer) | [VM] | runbook restauration ; ansible README | `BackupMissing` n'alerte qu'après 30 min |
| Perte du PC Hôte | RTO | ≤ 30 min | 376 s ≈ 6 min 16 : reconstruction 311 s + playbook de restauration 65 s, hors détection et décision | [VM] de recette (4 vCPU / 8 Go) | ansible README | tenu techniquement ; témoin 26/28 (admin) |
| Perte du PC Hôte | RPO | ≤ 15 min | âge de la dernière copie hors hôte, faite à la main : non borné | [VM] | ansible README ; runbook restauration | non tenu |
| Perte des secrets | RTO | ≤ 30 min | — (SOPS non testé) | [non mesuré] | TODO, Sécurité | non tenu |
| Moteur arrêté | détection | ≤ 1 min | règle `RemediationEngineDown` (`for: 30s`) | [non mesuré] | `availability.yml` | personne n'est prévenu |

### 3.2 Où passe le temps de reprise

Jalons relevés, en secondes depuis la perturbation :

| Segment | Panne d'API [local] | Force brute [local] | Registre corrompu [local] | Ce qui fixe la durée |
|---|---|---|---|---|
| Perturbation → alerte `firing` | 31 s (28 s au 2e essai) | 21,5 s | 11,2 s | scrape (sondes 5 s, `up` 10 s), évaluation (Prometheus 10 s, ruler Loki 15 s), `for:` (15 s / 0 s / 0 s), fenêtre LogQL (> 10 échecs en 1 min), contrôle d'intégrité toutes les 15 s |
| Alerte → webhook reçu | 8 s (8 s) | 7,0 s | 8,7 s | `group_wait` d'Alertmanager (5 s) et acheminement |
| Webhook → action faite | 6 s (conteneur sain) | 0,1 s | 11,6 s (restauration faite) | décision, `start` et healthcheck ; liste du WAF et rechargement ; `resilience-pg-restore` |
| Action → vérifié | 1 s | 0,9 s | 0,4 s | sondes, intégrité, transaction témoin |
| **Total** | **46 s** | **29,5 s** | **31,9 s** | |
| Part détection + acheminement | 85 % | 97 % | 62 % | |

Pour la panne d'API, `for: 15s` coûte en pratique 20 s : Prometheus évalue toutes les 10 s et l'alerte passe `firing` à la deuxième évaluation qui suit la première observation, d'où une plage de ≈ 20 à 35 s, cohérente avec les 28 et 31 s mesurés. Le moteur n'est pas le goulet : l'essentiel est un temps de confirmation choisi. Pour une restauration, c'est l'action elle-même (11,6 s) qui pèse le plus.

### 3.3 Leviers et contreparties

| Levier | Gain estimé | Contrepartie | Décision |
|---|---|---|---|
| `for: 15s` → `5s` sur `ServiceDown`, `EndToEndProbeFailed` | ≈ 10 s | un redémarrage de 2 s ou une sonde lente ouvre un incident ; aujourd'hui `docker compose restart frontend` (2 s) ne déclenche rien (revue § 8) | gardé pour la démo |
| Évaluation Prometheus 10 s → 5 s | 5 à 10 s (le `for:` effectif passe de 20 à 15 s) | un peu de CPU pour 16 règles | recommandé après la démo |
| `group_wait` 5 s → 1 s | ≈ 4 s | plus de notifications par incident ; le moteur corrèle déjà les alertes d'une même cible | acceptable |
| Ruler Loki 15 s → 5 s | jusqu'à 10 s sur les règles SOC | fenêtres LogQL de 1 à 2 min réévaluées trois fois plus souvent | à mesurer |
| Seuils SOC abaissés (`AuthBruteForce` > 10 échecs/min/IP) | quelques secondes | derrière le NAT du labo, quelques fautes de frappe du jury feraient bloquer tout le monde | refusé |
| `for: 20s` de `AnomalyDetected` réduit | jusqu'à 20 s sur le chemin ML | faux positifs ; le ML sert aux attaques lentes, où la précision compte plus que la vitesse | refusé |
| Contrôle d'intégrité 15 s → 5 s | jusqu'à 10 s sur S5 | contrôle complet du registre plus fréquent, coût croissant avec le volume | contrôle incrémental en contexte industriel |

**Arbitrage** : un redémarrage intempestif, ou un blocage qui coupe tout le labo, coûte plus que 10 s de détection. Les délais sont gardés ; le RTO reste 2,5 fois sous sa cible (46 s pour 2 min).

## 4. Scénarios couverts

La table de décision du moteur couvre les 21 alertes (16 Prometheus, 5 Loki ; un test le vérifie). Les trois familles ci-dessous restent séparées dans le code, les journaux et les métriques (`nature`). Conduite détaillée alerte par alerte : [incident-response.md](../runbooks/incident-response.md).

### 4.1 Disponibilité : rétablir le service

| Scénario (EBIOS) | Détection (délai de la règle) | Réponse | Vérification | RTO / RPO attendus | Données perdues | Risque résiduel |
|---|---|---|---|---|---|---|
| D1 API arrêtée ou plantée (S3) | `ServiceDown`, `EndToEndProbeFailed` (`for: 15s`), `HighErrorRate` (`for: 30s`) ; `AnomalyDetected` (`probe_failed`) rattachée, sans action en double | crash : Docker relance (`restart: unless-stopped`) ; conteneur arrêté ou malade : le moteur redémarre le maillon en panne, PostgreSQL d'abord ; un maillon `starting` est attendu, pas redémarré | conteneurs `healthy`, sondes à 1, transaction témoin | 43 à 46 s [local] / 0 | aucune : la requête en vol échoue et se renvoie avec la même clé | cause non traitée (un redémarrage masque un bogue) ; au-delà de 3 redémarrages en 10 min : escalade |
| D2 Base injoignable (S4) | `DependencyFailures` (> 3 en 1 min, `for: 0s`), `ServiceDown`, sondes | redémarrer PostgreSQL s'il est arrêté ou en échec, puis l'API seulement si elle ne revient pas seule en 30 s ; jamais de restauration (503 n'est pas 409) | comme D1 | 2 min visées [non mesuré] / 0 si le volume est intact | aucune | volume `pgdata` perdu : pas de 409, donc pas de restauration automatique ; escalade puis restauration par l'opérateur (RPO 15 min) |
| D3 Saturation (S3) | `HighLatencyP95` (`for: 1m`), `HighErrorRate`, `AnomalyDetected` (`latency_p95`) | observer 3 min, redémarrer si l'alerte persiste ; chemin ML : redémarrage | comme D1 | ≥ 4 min avant action, cible non tenue / 0 | aucune | 240 connexions (60 en parallèle) ont fait redémarrer `auth-service` sans régler la charge (revue § 7.3) ; aucune limitation de débit au WAF ni au frontal |
| D4 Détecteur ML arrêté ou aveugle | `AnomalyDetectorDown`, `AnomalyDetectorBlind` (`for: 1m`) | un seul redémarrage par 30 min (service sans état) ; source aveugle : observation | conteneur `healthy` | — / — | scores de la période | attaques lentes non vues ; les règles SOC restent actives |

### 4.2 Compromission et données : confiner, puis éradiquer

| Scénario (EBIOS) | Détection (délai de la règle) | Réponse | Vérification | Confinement / RPO | Données perdues | Risque résiduel |
|---|---|---|---|---|---|---|
| C1 Force brute (S1) | `AuthBruteForce` (> 10 échecs/min pour une IP, `for: 0s`, ruler toutes les 15 s) ; `LoginFailureSpike` (> 20/min au total, `for: 30s`) ; ML `login_failures_per_min` | bloquer l'IP au WAF (TTL 300 s) ; IP exclue (réseau interne, passerelle) ou non attribuable : escalade | configuration réellement chargée par le WAF, sondes, témoin | 29,5 s (SOC), 65,8 s (ML) [local] / — | aucune | un mot de passe deviné avant le blocage reste compromis (jeton valable 15 min, aucune révocation) ; changement d'IP ; attaque répartie : escalade (risque accepté, EBIOS) |
| C2 Injections SQLi/XSS (S2) | `WafAttackBlocked` (> 5 requêtes interrompues par le WAF en 2 min pour une IP) | chaque charge reconnue est déjà refusée en 403 (13/13 en démo) ; le blocage coupe la suite des essais | comme C1 | 32,5 s [local] / — | aucune | 5 charges sur 47 du jeu élargi passent le niveau 1 et ne comptent pas ; dernier rempart : requêtes paramétrées |
| C3 Jetons invalides, attaque lente (S1) | `InvalidTokenFlood` (> 20/min pour une IP) ; sous ce seuil : ML (`for: 20s`) puis attribution Loki (≥ 10 événements en 2 min) | blocage ; attribution insuffisante : escalade `no_offender`, aucun blocage | comme C1 | 87,5 s [local] / — | aucune | attaque répartie ou très lente non bloquée |
| C4 Registre corrompu (S5) | `LedgerIntegrityBroken` (Prometheus, `for: 0s`) et `LedgerIntegrityViolationLogged` (Loki), corrélées en un incident | confirmer (PostgreSQL sain et contrôle en 409), puis pont → `resilience-pg-restore latest-healthy` ; copie `pre-restore` conservée ; base injoignable : reclassée en D2 | intégrité 200, sondes, témoin | 31,9 s [local] ; 19 s + 19 s par l'opérateur [VM] / ≤ 15 min (52 s à l'essai) | écritures depuis la sauvegarde saine : virements, comptes créés | accès de l'auteur non coupé tant que les secrets n'ont pas tourné ; 1 restauration par 15 min (moteur), 3 par heure (hôte), puis escalade ; une fraude équilibrée échappe au contrôle |
| C5 Fausses alertes au moteur (S6) | pas d'alerte ; refus 401 comptés (`remediation_webhook_rejected_total`, rangée Grafana) | prévention : jeton porteur, table fermée, anti-boucle, aucune route d'action | — | — | — | jeton partagé : qui lit les secrets de l'hôte peut forger des alertes, bornées par la table |
| C6 Fuite de données (hors S1 à S6) | aucune règle de la table | manuelle : investigation (Loki, copie `pre-restore`), rotation des secrets et des clés JWT, réinitialisation des mots de passe, notification | — | [non mesuré] | — | restaurer ne corrige pas une fuite ; copie hors hôte non chiffrée (empreintes argon2id) ; scénario à ajouter à l'EBIOS |

### 4.3 Infrastructure et secrets : reprise humaine

| Scénario | Détection | Réponse | Vérification | RTO / RPO attendus | Données perdues | Risque résiduel |
|---|---|---|---|---|---|---|
| I1 Perte du PC Hôte | rien d'automatique : toute l'observation tourne sur l'hôte ; plus aucune page servie | manuelle : `provision_proxmox.yml` (63 s), `prepare_host.yml` (91 s), `deploy.yml` (157 s), `restore_database.yml -e backup_from_local=…` (65 s) | témoin sur l'hôte et à travers le réseau (`deploy.yml`), puis après la restauration | 376 s hors détection et décision [VM] / dernière copie hors hôte | tout depuis cette copie ; journaux Loki, historique du moteur, sauvegardes planifiées et copies `pre-restore` restées sur l'hôte | secrets régénérés : connexion admin en échec (témoin 26/28) ; preuves d'investigation perdues |
| I2 Perte ou compromission des secrets | perte : services en échec, webhook en 503 (fermé par défaut) ; compromission : aucune détection | manuelle (§ 5.4) | témoin 28/28 | [non mesuré] | — | sans séquestre, perdre les secrets, c'est perdre l'accès admin |
| I3 Moteur arrêté ou en échec | `RemediationEngineDown` (`for: 30s`), `RemediationFailed` (`for: 0s`, fenêtre de 10 min) | aucune auto-remédiation (anti-boucle) ; un crash est relancé par Docker | — | dépend d'un humain | — | Alertmanager n'a aucun destinataire humain |
| I4 Disque, mémoire, sauvegardes | `HostDiskSpaceLow` (`for: 5m`), `HostMemoryLow` (`for: 2m`), `BackupMissing` (> 30 min), `BackupFailed` | escalade `policy`, aucune action | `journalctl -u resilience-pg-backup`, rangée « PC Hôte et sauvegardes » | dépend d'un humain | RPO dépassé jusqu'à l'intervention | comme I3 |

## 5. Choix de restauration et arbitrages

### 5.1 Redémarrer ou recréer

- Le **moteur** ne fait que `start` et `restart` (plus `kill -HUP` pour recharger le WAF) par le proxy Docker : il ne peut ni créer, ni supprimer, ni exécuter. Seuls 6 services nommés sont redémarrables ; un conteneur absent n'est jamais recréé (escalade).
- **Recréer** un service (`restart_service.yml` : `--force-recreate` sur la version active, puis transaction témoin) ou **revenir** au commit précédent (`deploy.yml -e deploy_ref=…`, volumes conservés) sont des gestes d'opérateur : ils exigent Compose, donc des droits équivalents à root, refusés au moteur par conception.
- Un redémarrage rétablit vite mais masque la cause ; le budget (3 redémarrages par 10 min, 20 s d'écart minimum) empêche la boucle et force l'escalade.

### 5.2 Restaurer la dernière sauvegarde saine

- **Seulement sur corruption confirmée** : PostgreSQL sain **et** contrôle d'intégrité en 409. Une base arrêtée (503) est une panne ; la restaurer détruirait des données saines.
- **Sauvegarde choisie** : la plus récente dont le registre était cohérent avant et après les dumps (une sauvegarde prise après la corruption est écartée), empreintes SHA-256 vérifiées.
- **Perte assumée** : tout ce qui a été écrit depuis (15 min au pire), à reconstituer depuis les journaux `transfer` de Loki (§ 2.4).
- **Preuve conservée** : l'état corrompu est sauvegardé (`pre-restore`) avant d'être écrasé, pour l'investigation et pour pouvoir annuler. Limite : cette copie reste sur l'hôte.
- **Garde-fous** : le moteur ne choisit ni la commande ni ses arguments (pont de fichiers, commande fixe) ; le runner revérifie le 409, restaure une fois à la fois et 3 fois par heure au plus ; une restauration en échec n'est jamais rejouée.
- Pendant la restauration, les deux API sont arrêtées exprès (≈ 10 s). Le moteur ne les relance pas pour ses propres demandes, mais il ignore celles de l'opérateur (§ 5.6).

### 5.3 Bloquer une IP : durée et NAT du labo

- Blocage au WAF avant ModSecurity (`403 blocked_by_remediation`), **300 s** par défaut (`WAF_BLOCK_TTL_SECONDS`, 90 s pendant la recette) ; levée effective au TTL plus au plus 15 s (période de fond du moteur). Réseaux internes, passerelles et moteur ne sont jamais bloqués ; 3 blocages de la même IP en 10 min au plus, puis escalade.
- **NAT du labo** : sur la VM, tous les postes (attaquant, jury, opérateurs) arrivent avec l'IP **172.16.255.252**. Bloquer l'attaquant **coupe tout le monde** pendant le TTL, alors que le moteur annonce « rétabli et vérifié » : sa transaction témoin part de la dmz, exclue du blocage. Choix pour la démonstration : TTL de 60 à 120 s. Correction durable : une IP par poste (point d'accès du groupe en 192.168.137.0/24).
- Arbitrage : un TTL long fait attendre l'attaquant plus longtemps, mais rend un faux positif plus coûteux.

### 5.4 Rotation des secrets : manuelle

Aucune rotation n'est automatisée, et le séquestre SOPS + age (`scripts/sops_secrets.py`) est écrit mais **non testé** : clés de l'équipe non générées, `.sops.yaml` à compléter. Pour tourner les secrets après une compromission, il faudrait :
1. générer de nouvelles valeurs (`init_secrets.py` ne crée que les secrets manquants : il faut un mode « rotation ») ;
2. changer dans PostgreSQL les mots de passe des rôles `auth_svc` et `pay_svc`, car `db/init` ne tourne qu'au premier démarrage du volume ;
3. remplacer la paire RSA des JWT (toutes les sessions tombent, ce qui est acceptable pour des jetons de 15 min) ;
4. réinitialiser le mot de passe admin dans `authdb` (le compte existant n'est pas mis à jour au démarrage) ;
5. recréer les conteneurs qui lisent leurs secrets au démarrage (le jeton du webhook et le mot de passe du dashboard, eux, sont relus à chaque usage) ;
6. rechiffrer et versionner `secrets.enc.json`.

Durée non mesurée. Tant que le séquestre n'existe pas, **perdre l'hôte, c'est aussi perdre les secrets**.

### 5.5 Ce qui n'est pas automatisé, et pourquoi

| Situation | Réponse du moteur | Pourquoi aucun automate |
|---|---|---|
| Disque ou mémoire de l'hôte, sauvegarde manquante ou en échec | escalade `policy` | agir sur l'hôte exige des droits que le moteur n'a pas ; libérer de la place ou relancer une sauvegarde peut effacer des preuves |
| `LedgerIntegrityCheckStale` | escalade | sans contrôle à jour, une restauration se ferait à l'aveugle |
| Détecteur aveugle ou arrêté | observation ; un seul redémarrage par 30 min | ce n'est ni une panne métier ni une attaque : jamais d'action sur le SI métier |
| Alerte visant le moteur ou son proxy | journalisée seulement | anti-boucle : un moteur qui se répare lui-même peut s'emballer |
| Alerte inconnue de la table | escalade | jamais d'action à l'aveugle |
| Attaque sans IP dominante (< 10 événements en 2 min) | escalade `no_offender` | bloquer sur une attribution faible couperait des clients légitimes, voire tout le labo |
| Restauration en échec, budget épuisé | escalade | rejouer détruirait davantage d'écritures |
| Perte de l'hôte, fuite, rotation des secrets, notification | aucune | hors de portée d'un conteneur non privilégié ; décisions qui engagent la direction |

### 5.6 Règles d'exploitation pendant une reprise manuelle

- Avant une restauration par playbook, poser un silence Alertmanager **limité** aux alertes de disponibilité des API (`alertname=~"ServiceDown|EndToEndProbeFailed|HighErrorRate|DependencyFailures|AnomalyDetected"` et `service=~"auth-service|payment-api|auth|payments"` : `auth` et `payments` sont les étiquettes des sondes de bout en bout) et le lever aussitôt après ; les alertes d'intégrité restent actives. Procédure et commandes : [runbook § 9](../runbooks/incident-response.md#9-restauration-lancée-par-lopérateur--poser-un-silence-ciblé). Sinon le moteur relance les API arrêtées ; à l'inverse, un silence trop large posé pendant la revue de durcissement a retardé de 69 s la reprise d'un vrai arrêt de `payment-api` (revue § 8).
- Après toute reprise manuelle : `python tests/smoke_test.py` (28 vérifications) et contrôle d'intégrité.

## 6. Responsabilités (RACI)

R : réalise ; **A** : rend compte et arbitre (un seul par ligne) ; C : consulté ; I : informé. Le moteur agit (R) mais n'est jamais **A** : la responsabilité reste humaine.

| Activité | Dev | Infra | IA/Data | Sécurité | Transformation | Direction | Moteur | Opérateur d'astreinte |
|---|---|---|---|---|---|---|---|---|
| Détecter : règles, seuils, détecteur en service | C | **A**, R (Prometheus, Alertmanager) | R (détecteur ML) | R (règles SOC) | I | – | I | I |
| Décider : alertes de la table | **A** (table de décision) | C | C (tri ML) | C | – | – | R | I |
| Décider : escalade de disponibilité, hôte, sauvegardes | C | **A** | C | I | I | – | I | R |
| Décider : escalade de compromission, fuite, alerte inconnue | C | C | C | **A** | I | I | I | R |
| Exécuter : redémarrage | **A** | C | – | – | – | – | R | I |
| Exécuter : blocage d'IP, restauration automatique | C | C (pont) | – | **A** | – | – | R | I |
| Exécuter : recréation, restauration par playbook, reconstruction de l'hôte | C | **A** | – | C | – | I | – | R |
| Exécuter : rotation des secrets, réinitialisation des comptes | C | R | – | **A** | – | I | – | R |
| Vérifier la reprise (témoin, intégrité, blocage chargé) | **A** | C | – | C | – | – | R (après ses actions) | R (après une reprise manuelle) |
| Communiquer : clients, partenaires, équipes | – | C | – | C | R | **A** | – | C |
| Classer l'incident et notifier l'ACPR (DORA) | – | C | – | C | R | **A** | – | C |
| Revue post-incident et suivi des actions | R | R | R | R | **A** | I | – | R |
| Maintenir le plan, approuver sa révision annuelle | C | C | C | C | R | **A** | – | C |
| Tester le plan (§ 8) | R | R | R | R | **A** | I | – | C |

- **Opérateur d'astreinte** : rôle à créer. Dans le démonstrateur, c'est l'équipe présente ; aucune alerte ne lui parvient automatiquement (§ 9.1).
- **Notification DORA** (délais rappelés dans [nis2-dora.md](nis2-dora.md) : initiale sous 4 h après la classification et au plus 24 h après la détection, intermédiaire sous 72 h, finale sous 1 mois). La chronologie horodatée du moteur (`GET /api/incidents/{id}` : alerte, détection, décision, action, vérification) sert de base factuelle au premier rapport ; Transformation le prépare, la Direction le valide.

## 7. Continuité pendant l'incident (PCA)

### 7.1 Ce que voit le client

Le front interroge les deux `/health` (authentification, paiements) toutes les 5 s, affiche une pastille et un bandeau, puis revient seul à la normale et recharge aussitôt le solde.

| Situation | Pastille | Bandeau | Ce qui reste possible |
|---|---|---|---|
| Paiements seuls en panne | « Service dégradé » | « Les paiements sont perturbés » : « Vous pouvez renvoyer un virement : il ne sera jamais débité deux fois. » | la session est conservée ; le solde affiché indique son heure |
| Authentification seule en panne | « Service dégradé » | « La connexion est perturbée » : « Votre session reste active : seules les nouvelles connexions sont touchées. » | virements des clients déjà connectés |
| Les deux (PostgreSQL arrêté, restauration en cours) | « Service indisponible » | « Services momentanément indisponibles » : « Aucun virement ne sera débité deux fois. » | consultation du dernier solde chargé |
| IP bloquée par le moteur | — | pages et API refusées (`403 blocked_by_remediation`) | rien depuis cette IP pendant le TTL (au labo : depuis aucun poste) |
| Perte du PC Hôte | — | aucune page servie | rien |

Garanties sous-jacentes : un virement est une seule transaction (entier ou absent) ; la clé `Idempotency-Key` est obligatoire et le formulaire renvoie la **même** clé après un incident, si bien qu'un nouvel essai ne débite jamais deux fois ; une base arrêtée donne `503 database_unavailable`, jamais une erreur 500.

### 7.2 Ce que voit l'opérateur

- **Dashboard de supervision** (`http://127.0.0.1:8091`, par tunnel SSH sur la VM) : bandeau *Opérationnel* / *Incident en cours* / *Remédiation en cours* / *Service rétabli*, chronomètre depuis la première anomalie, décision (nature et action), chronologie horodatée par le moteur, IP bloquées avec compte à rebours, état du pont. Limite : les incidents d'exploitation (hôte, sauvegardes, détecteur, moteur) n'y apparaissent qu'en remarque, pas dans le bandeau.
- **Grafana**, tableau « Santé du service » : rangée **Remédiation** (incidents ouverts, IP bloquées, actions en échec et escalades en rouge dès la première, durées détection → rétablissement et alerte → rétablissement en p50 / p95, refus du webhook, journal `remediation_*`, annotations d'incident sur tous les graphiques) et rangée « PC Hôte et sauvegardes » (âge de la dernière sauvegarde, durée de la dernière restauration).
- **Alertmanager** pour les alertes actives et les silences ; **assistant RAG** pour retrouver une procédure (il n'agit pas ; ≈ 1 min par réponse mesurée en CPU, davantage sur la VM).

## 8. Tests réalisés et à réaliser

### 8.1 Campagne des 19 et 20/10/2026

| Date | Environnement | Scénario | Résultat | Mesure clé | Source |
|---|---|---|---|---|---|
| 19/10 | [VM] PC Hôte | corruption (1 000 € crédités en base) → `LedgerIntegrityBroken` → restauration par playbook | PASS | alerte 19 s ; script 10,6 s ; playbook 19 s ; 52 s de données perdues | runbook restauration |
| 19/10 | [VM] de recette jetable, clone neuf | perte du PC Hôte : création, préparation, déploiement, restauration de la copie locale | PASS partiel | 311 s + 65 s ; témoin 26/28 (connexion admin, secrets non restaurés) | ansible README |
| 19/10 | [VM] | playbooks de reprise `restart_service`, `backup_database`, `restore_database` | PASS | — | ansible README |
| 20/10 | [local] | arrêt de `payment-api` | PASS | 46 s ; incident clos à +69 s | moteur README |
| 20/10 | [local] | arrêt de `payment-api` filmé sur le dashboard | PASS, 2 défauts d'affichage corrigés | 43 s ; 37 s de la première anomalie à l'écran au service vérifié | supervision README |
| 20/10 | [local] | pont : runner de développement, puis unités `systemd-run --user` | PASS ; registre sain → `precondition_failed` | 10,8 / 12,0 s ; 9,9 / 11,0 s | runbook restauration |
| 20/10 | [local], attaquant = conteneur `edge` | recette de compromission : scénarios 1, 2, 3, 4A, 4B, 4C positif et négatif | PASS (7/7) | 29,5 s ; 32,5 s ; 31,9 s ; « déjà bloquée » ; 87,5 s ; 65,8 s ; escalade | recette |
| 20/10 | [local] | conteneur `starting` pendant une alerte, après correctif | PASS | 0 redémarrage | recette |
| 20/10 | [local] | revue de durcissement : 12 refus 403 d'API ; injections ; 240 connexions (60 en parallèle) | PASS ; constat | aucune alerte ; blocage 300 s puis levée ; redémarrage d'`auth-service` inutile contre la charge | revue § 7 |
| 20/10 | [local] | rangée Grafana « Remédiation » | PASS | revérification : 17,0 s de la détection au rétablissement | TODO |

### 8.2 À faire avant le jury (gel du code jeudi 22/10, 17 h)

1. **Infra** : déployer `main` sur la VM (moteur, proxy Docker, pont, dashboard ; secrets `remediation_webhook_token` et `supervision_password` créés au déploiement).
2. **Sécurité** : rejouer D1, C1, C2 et C4 depuis un **vrai second poste** (`scripts/scenarios/attack.py --target http://172.16.147.10:8080`) et relever les mêmes jalons ; vérifier l'effet du NAT avec un TTL de 60 à 120 s.
3. **Infra** : éprouver le pont sur la VM (root sans capacités, `inbox/` à l'uid 10001) ; il n'a tourné qu'en local.
4. **Sécurité et Infra** : clés age, `.sops.yaml`, `secrets.enc.json` versionné, puis rejouer la perte de l'hôte : témoin attendu 28/28.
5. **Dev** : chronométrer D2 (arrêt de PostgreSQL) et un virement en vol pendant une panne (RPO 0 à prouver).
6. **Infra** : rejouer une restauration par l'opérateur avec un silence limité (§ 5.6).
7. **Dev** : après fusion de la couche SQLAlchemy de `payment-api`, relancer les tests, le smoke test et la recette d'intégrité (le contrôle et la restauration dépendent du schéma du registre).

### 8.3 Calendrier de tests en contexte industriel

| Fréquence | Test | Critère de réussite |
|---|---|---|
| À chaque fusion touchant le moteur, les règles ou les playbooks de sauvegarde | tests unitaires et `scripts/scenarios/run_recette.py` en préproduction | tous les scénarios PASS, RTO dans la cible |
| Mensuelle | restauration d'une sauvegarde hors site sur une base jetable | registre 200, âge ≤ RPO |
| Trimestrielle | recette complète S1 à S5 (comme le recommande nis2-dora.md § 4) | PASS, écarts suivis jusqu'à correction |
| Semestrielle | perte de l'hôte sur VM jetable, secrets compris | témoin 28/28 en moins de 30 min |
| Annuelle | exercice de crise avec la direction, la communication et une notification simulée ; revue du plan | délais DORA tenus, plan réapprouvé |

## 9. Risques résiduels et recommandations

### 9.1 Ce qui subsiste après la reprise

| Risque résiduel | Scénarios | Traitement |
|---|---|---|
| Escalade vue seulement si quelqu'un regarde : Alertmanager n'a que le moteur comme destinataire | tous | recommandation 2 |
| Cause d'une panne non traitée par un redémarrage ; surcharge non résolue | D1, D3 | revue post-incident ; capacité et limitation de débit |
| Compte deviné avant le blocage, jeton encore valable 15 min, pas de révocation | C1 | réinitialisation forcée, liste de révocation |
| Attaquant qui change d'IP ou répartit son attaque | C1 à C3 | escalade ; risque accepté dans l'EBIOS |
| Au labo, jury bloqué alors que l'écran affiche « rétabli » | C1 à C3 | TTL court ; une IP par poste |
| Écritures légitimes perdues (15 min au pire) et à reconstituer | C4 | H8 ; restauration à un instant donné |
| Auteur d'une corruption qui garde son accès à la base | C4 | rotation des secrets (manuelle, § 5.4) |
| Fraude équilibrée invisible pour le contrôle d'intégrité | C4 | contrôles métier, journal en ajout seul |
| `authdb` et `paydb` sauvegardées l'une après l'autre : un utilisateur créé entre les deux dumps peut n'exister que dans une base | C4, I1 | sauvegarde cohérente des deux bases |
| RPO de 15 min dépassable jusqu'à ≈ 31 min sans alerte (`BackupMissing` à 30 min, `for: 1m`) | C4, I1 | seuil à 20 min |
| Copie hors hôte non chiffrée ; preuves (Loki, historique du moteur, `pre-restore`) perdues avec l'hôte | I1 | recommandations 1 et 3 |
| Moteur compromis : il peut redémarrer n'importe quel conteneur, bloquer des IP 300 s, demander une restauration (refusée sans vraie corruption) | S6 | recommandation 10 |
| Pont jamais exécuté sur la VM ; aucun rejeu depuis un vrai second poste | tous | § 8.2 |

### 9.2 Recommandations à la direction (contexte industriel)

Coûts : ordres de grandeur estimés par l'équipe, à valider ; bénéfices rapportés au § 2.

| Priorité | Recommandation | Coût | Bénéfice |
|---|---|---|---|
| 1 | **Séquestre des secrets** : clés age de l'équipe, `secrets.enc.json` chiffré par SOPS et versionné (déjà déchiffré par `deploy.yml` s'il existe) | ≈ 0,5 j·h | PRA « perte de l'hôte » complet (admin, rôles, clés JWT) |
| 2 | **Alerte humaine** : second destinataire Alertmanager vers l'astreinte pour `RemediationFailed`, `RemediationEngineDown`, alertes `operator` et toute compromission ; **astreinte** organisée | ≈ 0,5 j·h + forfait d'astreinte | escalade traitée en 30 min au lieu de « quand quelqu'un regarde » : ≈ 18,5 k€ au lieu de 160 k€ et plus pour un arrêt (§ 2.3) ; écart DORA comblé |
| 3 | **Copie hors hôte planifiée, chiffrée (age) et immuable** | ≈ 1 j·h + stockage | RPO de la perte de l'hôte borné à 15 min ; preuves conservées |
| 4 | **Une IP par client** (point d'accès du groupe, ou proxy de confiance qui transmet l'IP d'origine) | ≈ 0,5 j·h au labo | blocage ciblé, plus de blocage collatéral |
| 5 | **PostgreSQL : archivage des journaux de transactions et restauration à un instant donné (PITR)** | ≈ 3 à 5 j·h | RPO de 15 min à quelques secondes ; restaurer juste avant la corruption sans perdre jusqu'à 6 000 virements |
| 6 | **Limitation de débit et plan de capacité** | ≈ 2 j·h | traite la saturation (D3), qu'un redémarrage ne règle pas |
| 7 | **TLS de bout en bout**, puis HSTS | ≈ 2 j·h | jetons et soldes protégés en transit (risque accepté dans l'EBIOS pour le prototype) |
| 8 | **Rotation des secrets outillée** (mode rotation, mots de passe des rôles, révocation des jetons) | ≈ 3 j·h | éradication d'une compromission en minutes |
| 9 | **PostgreSQL haute disponibilité** (réplication en continu, bascule) | ≈ 10 j·h + 1 serveur | panne de la base sans restauration ; RTO de la base sous la minute |
| 10 | **Proxy Docker à liste blanche par conteneur** ; mTLS au lieu du jeton partagé | ≈ 2 j·h | réduit ce qu'un moteur compromis peut faire |
| 11 | **Second site** actif / passif, base répliquée, sauvegardes hors site | ≈ 2 fois l'hébergement + ≈ 20 j·h | survit à la perte du site ; la perte de l'hôte passe d'une reconstruction à une bascule |

Pour la démonstration : D1 reste le scénario le plus sûr (≈ 45 s, tient dans le Clip Chrono) ; C1 seulement avec un TTL court et en prévenant le jury du NAT ; C4 seulement après l'essai du pont sur la VM ; aucun test de charge pendant le passage (revue § 7.3).

## 10. Maintien du plan

- **Propriétaire** : Transformation ; **approbation** : Direction, une fois par an et après tout incident majeur.
- **Mise à jour obligatoire** quand change : la table de décision ou une règle d'alerte (`for:`, seuils, `group_wait`, TTL de blocage) ; le schéma du registre ou le contrôle d'intégrité ; la fréquence ou le lieu des sauvegardes ; l'hébergement (VM, second site) ; la liste des services ; une hypothèse de coût (H1 à H8) ; la réglementation.
- **Mise à jour après** : tout incident réel ou escalade, tout test en échec, toute revue post-incident.
- **Re-test** : selon le § 8.3 ; une mesure plus ancienne qu'une modification du composant mesuré ne vaut plus preuve.
- Le plan est versionné avec le code (`docs/governance/`) et indexé par l'assistant RAG des opérateurs.

## Écarts relevés entre les sources

| Point | Sources | Valeur retenue |
|---|---|---|
| « Perte du PC Hôte ≈ 6 min 15 » présentée comme 311 s + 13,8 s, ce qui ferait ≈ 5 min 25 | TODO ; runbook restauration | 311 s + 65 s (playbook complet, dont 13,8 s de restauration) = 376 s ≈ 6 min 16 (tableau d'`ansible/README.md`) |
| Restauration « ≈ 10 s » | TODO | 10,6 s [VM] ; 10,8 s et 9,9 s [local] (runbook restauration) |
| Corruption → alerte : 19 s ou 11,2 s | runbook (19/10, VM) ; recette (20/10, local) | les deux : écart dû au contrôle toutes les 15 s, au scrape et à l'évaluation, plage ≈ 0 à 35 s |
| Arrêt de `payment-api` : 46 s ou 43 s | moteur README ; supervision README | deux essais distincts, les deux cités |
| Réaction du moteur : 6,7 s, 7,0 s, 17,0 s ; « durée moyenne 3,6 s » | TODO ; supervision README | 6,7 et 7,0 s ; 17,0 s reste à expliquer ; la moyenne de 3,6 s précède le correctif « durées observées seulement si le moteur a agi » et ne doit pas être citée comme temps de réaction |
| Blocage par le chemin ML « ~87 s » | TODO | 87,5 s (jetons invalides) et 65,8 s (force brute), recette § 4B et § 4C |
| « Service dégradé » pendant une restauration | runbook restauration | « Service indisponible » : la restauration arrête les deux API, et le front affiche cet état quand les deux `/health` échouent |
| « Restauration en 11-12 s » | nis2-dora.md | segment demande → résultat du pont ; le RTO vu du client est 31,9 s [local] |
| « Trivy encore à faire », « sauf `ollama/ollama:latest` » | nis2-dora.md | Trivy fait le 20/10 ; Ollama figé en 0.40.6 (revue de durcissement) |
| « Il lui manque encore le HTTPS et les sauvegardes », « moteur en cours » | ebios-rm.md | sauvegardes et moteur livrés ; HTTPS toujours absent |

## Sources

- Mesures : [recette du moteur](../../services/remediation-engine/docs/recette.md), [README du moteur](../../services/remediation-engine/README.md) (« Tester », table de décision, anti-boucle), [`decisions.py`](../../services/remediation-engine/app/decisions.py), [README du dashboard](../../services/supervision-dashboard/README.md) (« Recette en direct »), [runbook de restauration](../runbooks/restauration-base.md), [README Ansible](../../ansible/README.md) et playbooks, [revue de durcissement](../securite/revue-durcissement.md), [TODO](../TODO.md).
- Délais de détection : [`availability.yml`](../../infra/prometheus/rules/availability.yml), [`host.yml`](../../infra/prometheus/rules/host.yml), [`soc.yml`](../../infra/loki/rules/fake/soc.yml), `infra/alertmanager/alertmanager.yml` (`group_wait`), `infra/prometheus/prometheus.yml` (scrape et évaluation).
- Gouvernance : [EBIOS RM](ebios-rm.md), [NIS2 / DORA](nis2-dora.md), [README racine](../../README.md) (architecture, comportements de résilience).
