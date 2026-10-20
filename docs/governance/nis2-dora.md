# Enjeux NIS2 / DORA — Resilience-Alpha

Nous partons de notre architecture et de nos essais, pas d'une liste générique d'obligations : pour chaque exigence, nous indiquons si elle concerne l'entité fictive, ce que le prototype en démontre réellement, et ce qu'il faudrait de plus en production.

## 1. Quel texte s'applique ?

**Hypothèse** : l'entité fictive est un établissement de paiement agréé (DSP2), de taille moyenne, qui exploite sa propre plateforme de virements.

- **DORA s'applique directement** (règlement (UE) 2022/2554, art. 2 §1 b : établissements de paiement). C'est le texte qui fixe nos obligations.
- **NIS2 ne s'applique pas directement** : les établissements de paiement ne figurent pas à l'annexe I (secteur bancaire = établissements de crédit). Et même pour une banque, DORA prime : NIS2 (art. 4) s'efface devant un acte sectoriel au moins équivalent pour la gestion des risques et la notification d'incidents.
- **NIS2 reste utile** comme grille de lecture de l'art. 21 (dix mesures concrètes, plus lisibles que les art. 5 à 16 de DORA) et parce qu'elle s'applique à nos fournisseurs (hébergeur, cloud, centre de données), ce qui renforce le volet « prestataires » de DORA.

En France, l'autorité compétente pour les incidents DORA d'un établissement de paiement est l'ACPR.

## 2. Exigences pertinentes vs démontrables

Légende : ✅ démontré par un essai · ◐ partiellement (mécanisme présent, pas le processus) · ❌ non démontrable en 4 jours.

Les mesures citées viennent de la recette du 20/10 sur la pile locale (`services/remediation-engine/docs/recette.md`) ; le pont de restauration n'a pas encore été rejoué sur la VM.

| Exigence | Pertinente pour l'entité fictive ? | Démontrée par le prototype ? | Preuve / lien | Ce qui manquerait en contexte industriel |
|---|---|---|---|---|
| DORA — gouvernance et cadre de gestion du risque TIC (art. 5-6) | Oui : l'organe de direction est responsable du risque TIC | ◐ Le cadre existe sous forme de documents, pas d'organe qui l'approuve | `docs/governance/ebios-rm.md`, `pca-pra.md`, table de décision (`GET /api/decision-table`, chaque règle reliée à un scénario EBIOS) | Approbation et revue annuelle par la direction, fonction de contrôle du risque TIC indépendante, audit interne, formation des dirigeants |
| DORA — identification, protection, détection (art. 8-10) | Oui | ✅ Cartographie des flux, réseaux segmentés, WAF unique point d'entrée, 16 règles Prometheus + 5 règles SOC Loki, détecteur ML | README racine (Architecture), `docker-compose.yml`, `infra/prometheus/rules/`, `infra/loki/`, `ml/README.md` | Inventaire des actifs tenu à jour (CMDB), classification des données, supervision 24/7, rétention des journaux au-delà de 7 jours |
| DORA — réponse et rétablissement, sauvegardes (art. 11-12) | Oui, c'est le cœur du sujet | ✅ Reprise sans opérateur : panne d'API rétablie et vérifiée par transaction témoin en ≈ 46 s (6,7 s après le webhook) ; corruption du registre → restauration en 11-12 s ; sauvegarde toutes les 15 min (RPO ≤ 15 min) ; perte du PC Hôte reconstruite en ≈ 6 min 15 | `services/remediation-engine/`, `docs/runbooks/restauration-base.md`, `ansible/backup_database.yml`, `restore_database.yml`, recette | Sauvegardes séparées physiquement et logiquement, chiffrées et immuables (ici sur le PC Hôte et le poste de l'opérateur) ; secrets sauvegardés (SOPS pas encore en place, donc PRA incomplet) ; site de secours ; PCA testé avec les métiers |
| DORA — gestion des incidents TIC (détection, classification, notification) (art. 17-19) | Oui | Détection ✅ · classification ◐ · notification ❌ | Détection : alertes → Alertmanager → moteur. Classification : le moteur distingue disponibilité et compromission, corrèle les alertes en un incident et horodate sa chronologie (`/api/incidents/{id}`, dashboard de supervision). Notification : aucune ; Alertmanager n'a qu'un destinataire, le moteur, et une escalade ne produit qu'un état, un journal et une métrique (`RemediationFailed`) | Classification selon les critères DORA (clients touchés, durée, pertes de données, criticité du service, impact économique et réputationnel) ; astreinte humaine prévenue ; notification à l'ACPR d'un incident majeur (initiale sous 4 h après classification et 24 h max après détection, intermédiaire sous 72 h, finale sous 1 mois) ; registre des incidents ; analyse des causes ; information des clients |
| DORA — tests de résilience opérationnelle numérique (art. 24-26) | Oui pour le programme de tests annuel ; TLPT seulement si l'entité est désignée significative | ◐ Tests de scénarios rejoués et mesurés, pas de programme ni de testeurs indépendants | Recette (force brute, injections, corruption, anomalie ML, arrêt de service), `scripts/scenarios/`, 389 tests pytest + 139 Vitest en CI (`.github/workflows/`), reconstruction de la VM depuis un clone neuf (311 s) | Programme annuel validé par la direction, scans de vulnérabilités (Trivy encore à faire), tests d'intrusion par des tiers indépendants, TLPT tous les 3 ans si significatif, suivi de correction des écarts |
| DORA — risque lié aux prestataires TIC tiers (art. 28-30) | Oui : hébergement, images de conteneurs, modèles d'IA | ◐ Mesures techniques seulement | Images en version figée (sauf `ollama/ollama:latest`), LLM local (aucune donnée envoyée à une API externe), accès Docker limité par `docker-socket-proxy` | Registre d'informations des contrats TIC, clauses contractuelles obligatoires (art. 30 : audit, localisation des données, sortie), stratégie de sortie, analyse du risque de concentration ; le Proxmox du labo est en réalité un prestataire non contractualisé |
| NIS2 — mesures de gestion des risques (art. 21) | Pas en droit (DORA prime), mais utilisées comme liste de contrôle | Voir le détail ci-dessous | | |
| ↳ a) analyse des risques et politiques de sécurité | Oui | ✅ | `ebios-rm.md` (6 scénarios reliés aux alertes) | Politique de sécurité signée, revue périodique |
| ↳ b) gestion des incidents | Oui | ✅ détection et réponse, ❌ processus humain | Voir ligne DORA art. 17-19 | Cellule de crise, astreinte, retour d'expérience |
| ↳ c) continuité, sauvegardes, reprise, gestion de crise | Oui | ✅ technique, ❌ gestion de crise | Voir ligne DORA art. 11-12, `pca-pra.md` | Exercices de crise avec la direction et la communication |
| ↳ d) sécurité de la chaîne d'approvisionnement | Oui | ◐ | Voir ligne DORA art. 28-30 | Évaluation des fournisseurs, SBOM, signature des images |
| ↳ e) sécurité du développement et de la maintenance, vulnérabilités | Oui | ◐ | Tests et CI, OpenAPI vérifiée (`docs/api/`), déploiement par commit avec retour arrière (`ansible/deploy.yml`) | Scan de dépendances et d'images en CI, revue de code obligatoire, politique de divulgation |
| ↳ f) évaluation de l'efficacité des mesures | Oui | ✅ à l'échelle du prototype | Chaque réponse est vérifiée (conteneurs, sondes, intégrité, transaction témoin) et chronométrée | Indicateurs suivis dans le temps, audits |
| ↳ g) cyber-hygiène et formation | Oui | ❌ | — | Sensibilisation des équipes, formation des dirigeants (exigée aussi par DORA art. 5) |
| ↳ h) cryptographie | Oui (données de paiement) | ◐ | JWT RS256, mots de passe en argon2id | HTTPS de bout en bout (absent, risque accepté dans EBIOS), chiffrement des sauvegardes et de la base, gestion des clés |
| ↳ i) RH, contrôle d'accès, gestion des actifs | Oui | ◐ | Rôle admin sur les routes sensibles, interfaces de gestion sur 127.0.0.1, Prometheus / Alertmanager / Loki authentifiés, SSH durci | Gestion des identités (arrivées, départs), revue des droits, comptes nominatifs au lieu de `admin` partagé |
| ↳ j) authentification multifacteur, communications sécurisées | Oui | ❌ | — | MFA pour les clients (DSP2 l'exige déjà) et les administrateurs, canal de crise de secours |
| NIS2 — notification d'incident (24 h / 72 h / 1 mois) (art. 23) | Non en droit : remplacée par la notification DORA, plus exigeante (4 h) | ❌ | Même constat que la ligne DORA art. 17-19 | Même chose que DORA ; à retenir pour nos prestataires soumis à NIS2, qui doivent nous prévenir de leurs propres incidents |

## 3. Ce que 4 jours démontrent, et ce qu'ils ne peuvent pas démontrer

**Ce que le prototype prouve, mesures à l'appui** : la détection et la réponse technique. Une panne, une attaque ou une corruption de données est détectée, qualifiée (panne, attaque, données touchées), traitée sans opérateur, puis vérifiée par une vraie transaction. Chaque étape est horodatée. C'est le socle des art. 10 à 12 de DORA.

**Ce qu'il ne peut pas prouver**, parce que ce sont des processus d'organisation qui se jugent dans la durée : la gouvernance (approbation et revue par la direction), la notification au régulateur, la gestion contractuelle des prestataires, les tests réalisés par des tiers indépendants, la formation. Nous les traitons comme des recommandations, pas comme des résultats.

**Un écart concret** : notre automate traite très bien les incidents qu'il sait corriger, mais un incident escaladé n'est vu que si quelqu'un regarde le dashboard. En production, c'est inacceptable au regard du délai de 4 h fixé par DORA.

**Classification d'après nos scénarios** : une panne d'API corrigée en moins d'une minute reste un incident mineur ; elle est enregistrée mais pas notifiée. En revanche, la corruption du registre (S5) affecte un service critique et implique un accès malveillant aux données : elle serait probablement classée **majeure** même si la restauration prend 12 s. Réparer vite ne dispense donc pas de notifier.

## 4. Recommandations à la direction, par priorité

1. **Prévenir un humain à chaque escalade** et à chaque incident de compromission (second destinataire Alertmanager vers l'astreinte) : peu coûteux, comble l'écart le plus visible.
2. **Préremplir la notification DORA** à partir de la chronologie que le moteur enregistre déjà (détection, décision, action, vérification), avec une grille de classification majeur / mineur appliquée par l'opérateur.
3. **Sortir les sauvegardes et les secrets du PC Hôte** : copie chiffrée et immuable sur un autre site, clés age de l'équipe et secrets chiffrés par SOPS. Sans cela, le PRA « perte du PC Hôte » reste incomplet.
4. **Tenir le registre des prestataires TIC** (hébergeur, images, modèles d'IA) avec leurs plans de sortie.
5. **Programme de tests annuel** : Trivy et scan des dépendances en CI, puis test d'intrusion externe ; rejouer chaque trimestre les scénarios de la recette, qui servent déjà de tests de non-régression de la résilience.
6. **Combler les écarts de protection acceptés pour le prototype** : HTTPS, MFA, comptes nominatifs.
