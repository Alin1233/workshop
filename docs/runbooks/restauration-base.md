# Runbook — restauration de la base de paiement (PRA « données corrompues »)

## Quand l'utiliser
- Alerte **LedgerIntegrityBroken** (`domain: integrity`) : le registre de paiement est incohérent (soldes différents
  des écritures, virement déséquilibré, solde négatif). `GET /api/payments/admin/integrity` renvoie 409 avec le détail.
- Base perdue ou illisible (volume `pgdata` supprimé, modification malveillante des données).

Un redémarrage ne corrige **pas** des données corrompues : il faut restaurer une sauvegarde.

## Sauvegardes disponibles
- **Planifiées** toutes les 15 min sur le PC Hôte (timer systemd `resilience-pg-backup.timer`) : RPO ≤ 15 min.
- Une sauvegarde = `pg_dump` de `authdb` et `paydb`, empreintes SHA-256 et `meta.json`, qui indique si le registre
  était **cohérent** (`"integrity": "ok"`) au moment de la sauvegarde.
- Stockées dans `/var/backups/resilience-alpha/` (root uniquement), 96 conservées (24 h), la dernière saine toujours gardée.
- Surveillance : alertes **BackupFailed** (dernière sauvegarde en échec) et **BackupMissing** (aucune sauvegarde réussie
  depuis 30 min) ; âge de la dernière sauvegarde et durée de la dernière restauration dans la rangée « PC Hôte et
  sauvegardes » du tableau Grafana « Santé du service » (métriques `resilience_backup_*` et `resilience_restore_*`).
- Copie hors de l'hôte : `ansible-playbook -i ansible/inventory.ini ansible/backup_database.yml` (sur le poste de l'opérateur,
  dans `~/.local/share/resilience-alpha/backups/`).

```bash
ssh resilience@172.16.147.10 'sudo sh -c "cat /var/backups/resilience-alpha/*/meta.json"'
```

## Restaurer
```bash
ansible-playbook -i ansible/inventory.ini ansible/restore_database.yml -e confirm_restore=true
ansible-playbook -i ansible/inventory.ini ansible/restore_database.yml -e confirm_restore=true -e backup=20261019T131506Z-scheduled
```

Déroulé automatique :
1. choix de la **dernière sauvegarde saine** (une sauvegarde prise après la corruption est écartée) et vérification des empreintes ;
2. sauvegarde de l'état courant (type `pre-restore`) : **preuve pour l'investigation**, et moyen d'annuler la restauration ;
3. arrêt de `auth-service` et `payment-api` : le front affiche « Service dégradé » ;
4. recréation de `authdb` et `paydb` depuis la sauvegarde, avec leurs propriétaires et leurs droits ;
5. redémarrage des API, contrôle d'intégrité du registre (200 attendu), puis transaction témoin.

## Mesures sur le démonstrateur (19/10/2026)
Scénario : 1 000 € crédités directement en base sur un compte client, sans écriture comptable.

| Étape | Durée |
|---|---|
| Corruption → alerte LedgerIntegrityBroken « firing » | 19 s |
| Restauration (script, de la sélection au registre cohérent) | 10,6 s |
| Restauration + transaction témoin (playbook complet) | 19 s |
| Données perdues | celles écrites depuis la sauvegarde restaurée (52 s d'écart dans l'essai ; 15 min au pire) |

## Après la restauration
- Vérifier que l'alerte est résolue (Alertmanager) et le tableau « Santé du service » dans Grafana.
- Analyser la sauvegarde `pre-restore` (état corrompu) et les journaux Loki pour comprendre l'origine de la modification.
- Les écritures légitimes faites entre la sauvegarde et l'incident sont perdues : à reconstituer depuis les journaux
  (`{service="payment-api"} | json | event_type="transfer"`) si nécessaire.
- Si la cause est une compromission (accès à la base), restaurer ne suffit pas : faire aussi tourner les secrets.

## Limites
- `authdb` et `paydb` sont sauvegardées l'une après l'autre : un utilisateur créé entre les deux dumps peut n'exister que dans une base.
- La copie hors de l'hôte n'est pas chiffrée : les bases contiennent des empreintes de mots de passe (argon2id).
- La restauration est déclenchée par un opérateur : le moteur de remédiation ne l'appelle pas (encore).
