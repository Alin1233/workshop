# Analyse de risques EBIOS RM — Resilience-Alpha

Nous retenons 6 scénarios, chacun relié à une alerte de la plateforme et à une réponse automatique.

## 1. Cadrage

L'objectif est de garantir des virements fictifs exacts et traçables, avec un service capable de repartir seul après un incident. La plateforme dispose d'un WAF (unique point d'entrée, HTTPS sur le port 8443 par une autorité locale), de réseaux cloisonnés, de conteneurs durcis, de logs centralisés, d'une double authentification (imposée à l'admin) et d'une sauvegarde de la base toutes les 15 minutes.

| Événement redouté | Gravité (G1 à G4) |
| --- | --- |
| Registre faux | G4 |
| Moteur de remédiation détourné | G4 |
| Paiement indisponible plus de 5 min | G3 |
| Virement fait sans l'accord du client | G3 |
| Logs perdus ou modifiés | G2 |

## 2 et 3. Sources de risque et scénarios stratégiques

| Qui | Pour quoi faire | Comment |
| --- | --- | --- |
| Cybercriminel | Voler de l'argent | Deviner des mots de passe clients |
| Hacktiviste | Bloquer les paiements | Saturer la plateforme |
| Fraudeur | Truquer des soldes | Passer le WAF ou voler les accès à la base |
| Initié | Truquer des soldes, effacer ses traces | Son accès au PC Hôte |
| Attaquant déjà dans un conteneur | Faire couper les services par l'automate | Envoyer de fausses alertes au moteur |

Nous écartons l'acteur étatique, peu intéressé par une plateforme fictive.

## 4. Scénarios opérationnels

Les scénarios sont joués depuis le second PC ou simulés. Pour la réponse, la règle est simple : on redémarre si c'est une panne, on restaure si les données sont touchées, on bloque si c'est une attaque. Ces réponses sont toutes livrées et automatiques : la table de décision du moteur (`GET /api/decision-table`, 21 règles) cite pour chaque alerte son scénario EBIOS.

Mesures : [local] sur la pile du poste de développement (recette `services/remediation-engine/docs/recette.md`), [VM] sur le PC Hôte le 21/10 (attaquant simulé par un conteneur du réseau `edge`).

| Scénario | Alertes | Réponse automatique | Mesure |
| --- | --- | --- | --- |
| S1 Force brute | `AuthBruteForce`, `InvalidTokenFlood`, `LoginFailureSpike` ; sous ces seuils, `AnomalyDetected` (ML) | Bloquer l'IP au WAF, levée automatique au bout du TTL | IP bloquée en 29,5 s [local], 35,2 s [VM] ; 66 s par le ML [local] |
| S2 Injections SQL/XSS | `WafAttackBlocked` | Bloquer l'IP (chaque charge reconnue est déjà refusée en 403) | 32,5 s [local] |
| S3 API saturée ou plantée | `ServiceDown`, `EndToEndProbeFailed`, `HighErrorRate`, `HighLatencyP95` ; `AnomalyDetected` rattachée | Redémarrer l'API, puis transaction témoin | Service vérifié en 43 à 46 s [local], 48 s [VM] |
| S4 Base injoignable | `DependencyFailures` | Redémarrer PostgreSQL, puis l'API si elle ne revient pas seule | API en 503 puis retour seul, durée non relevée [local] |
| S5 Registre modifié en base | `LedgerIntegrityBroken` et `LedgerIntegrityViolationLogged`, corrélées | Vérifier la corruption (base saine et registre en 409), puis restaurer la dernière sauvegarde saine | 31,9 s [local], 34 s [VM] |
| S6 Fausses alertes au moteur | Aucune | Prévention : webhook authentifié par jeton, proxy Docker restreint, restauration par un pont sans paramètre et limitée à 3 par heure | Sans objet |

Après chaque réponse, une transaction témoin (`tests/smoke_test.py`) confirme que le service remarche. Attention : une panne de base fait aussi tomber la jauge d'intégrité, donc le moteur doit vérifier qu'il s'agit bien d'une corruption avant de restaurer.

## 5. Traitement

Mesures en place (toutes livrées et vérifiées) :

- moteur de remédiation (S1 à S5) ;
- blocage d'IP au WAF (S1, S2) ;
- sauvegarde toutes les 15 minutes et restauration de la dernière sauvegarde saine (S5) ;
- webhook authentifié, proxy Docker restreint et pont de restauration sans paramètre (S6) ;
- détection d'anomalies par ML (S1, S3) ;
- double authentification, imposée à l'admin (S1) ;
- limites de mémoire par conteneur (S3, S4).

Ce que nous acceptons :

- perdre les virements faits depuis la dernière sauvegarde, 15 minutes au pire ;
- laisser passer une attaque venant de plusieurs IP : le moteur escalade sans bloquer ;
- ne pas traiter la saturation : un redémarrage ne règle pas une surcharge ;
- garder des images avec des failles connues sans correctif publié, justifiées dans la revue de durcissement ;
- bloquer tous les postes du labo avec l'attaquant : derrière le NAT du wifi, ils ont la même IP ;
- ne pas mettre les secrets sous séquestre, faute de SOPS : la reconstruction du PC Hôte reste incomplète.

## Cartographie du risque

Gravité (G1 à G4) × vraisemblance (V1 à V4). Zone rouge si le produit vaut 8 ou plus, orange de 4 à 6, verte jusqu'à 3.

| Scénario | Avant traitement | Après traitement |
| --- | --- | --- |
| S1 Force brute | G3 × V3, rouge | G3 × V2, orange |
| S2 Injections SQL/XSS | G4 × V1, orange | G4 × V1, orange |
| S3 API saturée ou plantée | G3 × V3, rouge | G2 × V3, orange |
| S4 Base injoignable | G3 × V2, orange | G2 × V2, orange |
| S5 Registre modifié en base | G4 × V2, rouge | G3 × V1, vert |
| S6 Fausses alertes au moteur | G4 × V2, rouge | G4 × V1, orange |

La remédiation, le blocage d'IP, les sauvegardes et la protection du moteur sortent S1, S3, S5 et S6 de la zone rouge. Les notes restent à valider ensemble.
