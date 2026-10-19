# Analyse de risques EBIOS RM — Resilience-Alpha

19/10/2026 · Mathys Perols

Premier jet, à relire en équipe. Nous retenons 6 scénarios, chacun relié à une alerte de la plateforme et à une réponse automatique. Quatre sont en zone rouge aujourd'hui, plus aucun après traitement si le moteur de remédiation est prêt.

## 1. Cadrage

Ce que nous protégeons : des virements fictifs justes, tracés, et qui repartent seuls après un incident. Le socle est déjà en place (WAF, réseaux cloisonnés, conteneurs durcis, logs centralisés). Il manque le HTTPS et les sauvegardes.

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

Les scénarios sont joués depuis le second PC ou simulés. Pour la réponse, la règle est simple : on redémarre si c'est une panne, on restaure si les données sont touchées, on bloque si c'est une attaque.

| Scénario | Alerte | Réponse prévue |
| --- | --- | --- |
| S1 Force brute | `AuthBruteForce` | Bloquer l'IP au WAF |
| S2 Injections SQL/XSS | `WafAttackBlocked` | Bloquer l'IP |
| S3 API saturée ou plantée | `ServiceDown`, `EndToEndProbeFailed` | Redémarrer l'API |
| S4 Base injoignable | `DependencyFailures` | Redémarrer PostgreSQL |
| S5 Registre modifié en base | `LedgerIntegrityBroken` | Restaurer la sauvegarde |
| S6 Fausses alertes au moteur | Aucune | Webhook authentifié (prévention) |

Après chaque réponse, une transaction témoin (`tests/smoke_test.py`) confirme que le service remarche. Attention : une panne de base fait aussi tomber la jauge d'intégrité, donc le moteur doit vérifier qu'il s'agit bien d'une corruption avant de restaurer.

## 5. Traitement

Mesures prévues :

- moteur de remédiation (S1 à S5), en cours ;
- blocage d'IP au WAF (S1 à S3) ;
- sauvegarde et restauration de la base (S5) ;
- webhook authentifié et droits Docker limités (S6) ;
- détection d'anomalies par ML (S1, S3), en cours ;
- limites de mémoire et de CPU par conteneur (S3, S4).

Ce que nous acceptons : perdre les virements faits depuis la dernière sauvegarde, laisser passer une attaque venant de plusieurs IP, et ne traiter ni le HTTPS ni les images compromises dans ce prototype.

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
