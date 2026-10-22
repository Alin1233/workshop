# Runbook — restauration de la base de paiement (PRA « données corrompues »)

## Quand l'utiliser
- Alerte **LedgerIntegrityBroken** (`domain: integrity`) : le registre de paiement est incohérent (soldes différents
  des écritures, virement déséquilibré, solde négatif). `GET /api/payments/admin/integrity` renvoie 409 avec le détail.
- Base perdue ou illisible (volume `pgdata` supprimé, modification malveillante des données).

Un redémarrage ne corrige **pas** des données corrompues : il faut restaurer une sauvegarde.
Le moteur de remédiation le fait seul (voir « Restauration automatique ») ; ce runbook couvre aussi la reprise manuelle.

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
Avant une restauration lancée à la main, poser le silence Alertmanager ciblé décrit dans
[incident-response.md](incident-response.md), section « Restauration lancée par l'opérateur » : le moteur ne sait pas
qu'une restauration qu'il n'a pas demandée est en cours et relancerait les API arrêtées par le script. Lever le silence
dès la fin.

```bash
ansible-playbook -i ansible/inventory.ini ansible/restore_database.yml -e confirm_restore=true
ansible-playbook -i ansible/inventory.ini ansible/restore_database.yml -e confirm_restore=true -e backup=20261019T131506Z-scheduled
```

Déroulé automatique :
1. choix de la **dernière sauvegarde saine** (une sauvegarde prise après la corruption est écartée) et vérification des empreintes ;
2. sauvegarde de l'état courant (type `pre-restore`) : **preuve pour l'investigation**, et moyen d'annuler la restauration ;
3. arrêt de `auth-service` et `payment-api` : les deux `/health` échouent et le front affiche « Service indisponible » ;
4. recréation de `authdb` et `paydb` depuis la sauvegarde, avec leurs propriétaires et leurs droits ;
5. redémarrage des API, contrôle d'intégrité du registre (200 attendu), puis transaction témoin.

## Restauration automatique (moteur de remédiation)
Sur `LedgerIntegrityBroken`, le moteur vérifie que la base répond et que `/internal/integrity` renvoie **409** (une base
arrêtée donne 503 : c'est un problème de disponibilité, pas une corruption), puis demande la restauration à l'hôte.
Il tourne dans un conteneur non privilégié (uid 10001) sans socket Docker brut : il **n'exécute rien**, il dépose une
demande dans un répertoire partagé (le « pont »). L'hôte exécute `resilience-pg-restore latest-healthy`, le même script
que le playbook : sélection de la dernière sauvegarde saine, état courant conservé, API arrêtées, contrôle à 200.

```
moteur (conteneur, uid 10001)          pont (/var/lib/resilience-alpha/remediation-bridge, /bridge dans le moteur)       hôte (root)
request_restore(incident) ──écrit──▶ inbox/request.json ──PathExists──▶ resilience-remediation-bridge.service
                          ◀──lit──── outbox/result-<id>.json ◀──écrit── valide, verrou, 409 ?, resilience-pg-restore
available()               ◀──lit──── outbox/heartbeat.json  ◀──30 s── resilience-remediation-bridge-heartbeat.timer
```

### Protocole
| Fichier | Écrit par | Contenu |
|---|---|---|
| `inbox/request.json` | moteur : `inbox/.request-<id>.tmp` (0640) puis `rename()` | `{"schema": 1, "action": "restore-latest-healthy", "request_id": <32 hex>, "incident_id": …, "created_at": <epoch>, "requested_by": "remediation-engine"}` |
| `outbox/result-<request_id>.json` | runner, fichier temporaire puis `rename()` | `{"request_id", "incident_id", "ok", "status", "detail", "runner", "finished_at"}` ; succès : `detail` = JSON imprimé par `resilience-pg-restore` (`restored`, `backup_created_at`, `backup_age_seconds`, `restore_seconds`) |
| `outbox/heartbeat.json` | runner, toutes les 30 s (et toutes les 10 s pendant une restauration) | `written_at`, `busy`, `active_request_id`, `docker_ok` ; **périmé au-delà de 120 s** → pont indisponible |
| `outbox/rejected.json` | runner | motif du dernier refus d'une demande sans identifiant exploitable (jamais son contenu) |

- **Statuts** : `restored`, `failed` (sortie du script jointe), `busy`, `timeout`, `rejected` (schéma), `expired`,
  `precondition_failed` (le registre n'est pas en 409 : rien à restaurer), `rate_limited` (3 restaurations par heure au plus).
- **Une seule restauration à la fois** : côté moteur, une seule demande en vol (la seconde reçoit `busy` sans rien écrire) ;
  côté hôte, un verrou `flock` hors du pont, et une demande arrivée pendant une restauration reçoit `busy` tout de suite ;
  `resilience-pg-restore` prend aussi son propre verrou (code 75) : le playbook de l'opérateur et le pont ne se chevauchent pas.
- **Jamais en retard** : une demande non prise en charge en 30 s est retirée par le moteur ; le runner refuse toute demande de
  plus de 120 s (`expired`). Un runner revenu après une panne ne restaure donc pas des heures plus tard (perte de données).
- **Ménage** : temporaires abandonnés (> 10 min), résultats de plus de 24 h (100 gardés au plus), à chaque heartbeat.

### Modèle de sécurité
Un processus root lit des fichiers d'un répertoire où écrit l'uid 10001 : le moteur, s'il était compromis, ne doit rien
obtenir de plus qu'une restauration légitime.
- **Droits** : racine du pont `root 0755` et `outbox/` `root 0755` (le moteur lit, ne peut ni écrire ni remplacer
  `inbox/`/`outbox/`) ; `inbox/` `10001:root 2770` (seul l'uid du moteur, et root, y écrit ; setgid : les demandes prennent
  le groupe root et restent lisibles par le runner sans `CAP_DAC_OVERRIDE`) ; verrou et historique dans
  `/var/lib/resilience-alpha/remediation-runner` (`root 0700`), hors du pont : le moteur ne peut pas bloquer le verrou.
- **Lecture de la demande** : `openat(O_NOFOLLOW | O_NONBLOCK)` par descripteur de répertoire (pas de lien symbolique suivi,
  pas de FIFO bloquante), puis sur le fichier ouvert : fichier ordinaire, **un seul lien** (un lien dur vers un fichier de
  l'hôte est refusé), propriétaire 10001, 4 Kio au plus. La demande est supprimée (`unlinkat`, sans suivre) avant toute
  action ; un répertoire est seulement renommé (pas de suppression récursive par root).
- **Schéma strict** : clés exactes, types, clés répétées et `NaN` refusés, `request_id` en 32 hex (il nomme le fichier de
  résultat), `incident_id` `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Un refus ne renvoie qu'un code, jamais un extrait du contenu
  (un lien vers un fichier système sensible de l'hôte ne fuit pas dans `outbox/`).
- **Aucune interpolation** : la seule action existante est `restore-latest-healthy` ; la commande est fixe (`argv`, sans shell)
  et rien de la demande n'y entre. Le runner revérifie lui-même que le registre est en **409** avant de restaurer, et limite
  à 3 restaurations par heure : un moteur compromis ne peut ni restaurer une base saine ni enchaîner les restaurations.
- **Écritures du runner** : fichier temporaire au nom aléatoire créé en `O_EXCL | O_NOFOLLOW`, `fsync`, puis `rename()` ;
  le runner refuse de travailler si la racine ou `outbox/` est inscriptible par un autre que lui.

### Unités systemd (installées par `deploy.yml`, `ansible/tasks/remediation_bridge_install.yml`)
| Unité | Rôle |
|---|---|
| `resilience-remediation-bridge.path` | `PathExists=…/inbox/request.json` → démarre le service |
| `resilience-remediation-bridge.service` | oneshot : `resilience-remediation-bridge process` (validation, verrou, contrôle 409, restauration, résultat) |
| `resilience-remediation-bridge-heartbeat.timer` | toutes les 30 s (`AccuracySec=1s`) |
| `resilience-remediation-bridge-heartbeat.service` | heartbeat (`docker compose ps` depuis l'unité durcie → `docker_ok`) et ménage ; `Requisite=` l'unité .path : si elle s'arrête, le heartbeat périme et le moteur escalade |

Durcissement des deux services : `CapabilityBoundingSet=` (aucune capacité), `NoNewPrivileges`, `ProtectSystem=strict` avec
écriture seulement sur le pont, l'état, les sauvegardes et les métriques textfile, `ProtectHome=tmpfs`, `PrivateTmp`,
`PrivateDevices`, `PrivateNetwork` + `RestrictAddressFamilies=AF_UNIX` (le socket Docker est un fichier, joignable sans réseau),
`ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`, `ProtectProc=invisible`, `RestrictNamespaces`, `RestrictSUIDSGID`,
`MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`.
**Non restreignable** : le script appelle `docker compose` (stop/up/exec) : il faut root et le socket Docker, qui équivaut
à root sur l'hôte. Ni `User=` (sauvegardes root 0700, et un membre du groupe docker vaut root), ni le proxy de socket du moteur
(il faudrait autoriser `exec`). Le durcissement limite donc les dégâts d'un bogue du runner, pas d'un abus du socket :
la vraie barrière est que le moteur ne choisit ni la commande ni ses arguments.

```bash
systemctl status resilience-remediation-bridge.path resilience-remediation-bridge-heartbeat.timer
journalctl -u resilience-remediation-bridge -u resilience-remediation-bridge-heartbeat   # événements remediation_bridge_*
sudo cat /var/lib/resilience-alpha/remediation-bridge/outbox/heartbeat.json
```
`deploy.yml` échoue si le heartbeat ne voit pas Docker depuis l'unité durcie (`docker_ok`). Unité .path en échec (trop de
déclenchements) : `sudo systemctl restart resilience-remediation-bridge.path`.

### En développement (sans systemd)
`scripts/remediation_bridge_dev.py` (développement uniquement) remplace les unités et `resilience-pg-restore` : même code de
protocole et de validation, restauration équivalente en Python (`docker compose exec pg_dump` / `pg_restore`, contrôle 409
avant, sauvegarde pre-restore, arrêt/relance des API, contrôle 200 après), sauvegardes dans `.dev-backups/` (ignoré par git).

```bash
python3 scripts/remediation_bridge_dev.py init     # avant `docker compose up` : sinon Docker crée .remediation-bridge en root
python3 scripts/remediation_bridge_dev.py backup   # registre sain
python3 scripts/remediation_bridge_dev.py run      # rôle des unités systemd (Ctrl-C pour arrêter)
```

Essai du 20/10 sur la stack locale (1 000 € crédités en base sur un compte, `/internal/integrity` en 409, puis
`RestoreBridge.request_restore` depuis l'hôte) :

| Chemin | Restauration (script) | De la demande au résultat (moteur) | Après |
|---|---|---|---|
| runner de développement | 10,8 s | 12,0 s | registre 200, transaction témoin 28/28 |
| runner de l'hôte + `resilience-pg-restore` rendu par Ansible, unités transitoires `systemd-run --user` (.path + durcissement ci-dessus) | 9,9 s | 11,0 s | registre 200 |

Même demande sur un registre sain : `precondition_failed` (HTTP 200), rien n'est restauré. Non testé sur la VM : uid
root sans capacités, droits 10001 sur `inbox/`.

## Mesures sur le démonstrateur (19/10/2026)
Scénario : 1 000 € crédités directement en base sur un compte client, sans écriture comptable.

| Étape | Durée |
|---|---|
| Corruption → alerte LedgerIntegrityBroken « firing » | 19 s |
| Restauration (script, de la sélection au registre cohérent) | 10,6 s |
| Restauration + transaction témoin (playbook complet) | 19 s |
| Données perdues | celles écrites depuis la sauvegarde restaurée (52 s d'écart dans l'essai ; 15 min au pire) |

## Perte totale du PC Hôte
Reconstruire l'hôte puis restaurer la dernière copie locale (procédure : `ansible/README.md`, « Recette sur une machine
vierge ») :

```bash
ansible-playbook -i ansible/inventory.ini ansible/restore_database.yml -e confirm_restore=true -e backup_from_local=<nom>
```

Mesuré le 19/10 sur une VM neuve : hôte reconstruit en 311 s, données restaurées en 13,8 s (≈ 6 min 15 au total).
Données perdues : depuis la dernière copie locale (`backup_database.yml`), pas depuis la dernière sauvegarde planifiée,
restée sur l'hôte perdu.

**Les secrets doivent être restaurés avec les données.** Sinon, le compte admin garde l'ancien mot de passe
(la connexion admin échoue avec les nouveaux secrets). Tant que `secrets.enc.json` (SOPS) n'est pas versionné, conserver
`shared/secrets` de l'ancien hôte, ou réinitialiser le mot de passe admin après la reprise.

## Après la restauration
- Vérifier que l'alerte est résolue (Alertmanager) et le tableau « Santé du service » dans Grafana.
- Analyser la sauvegarde `pre-restore` (état corrompu) et les journaux Loki pour comprendre l'origine de la modification.
- Les écritures légitimes faites entre la sauvegarde et l'incident sont perdues : à reconstituer depuis les journaux
  (`{service="payment-api"} | json | event_type="transfer"`) si nécessaire.
- Si la cause est une compromission (accès à la base), restaurer ne suffit pas : faire aussi tourner les secrets.

## Limites
- `authdb` et `paydb` sont sauvegardées l'une après l'autre : un utilisateur créé entre les deux dumps peut n'exister que dans une base.
- La copie hors de l'hôte n'est pas chiffrée : les bases contiennent des empreintes de mots de passe (argon2id).
- La restauration automatique revient à la dernière sauvegarde saine : les écritures légitimes faites depuis sont perdues
  (15 min au pire) ; au-delà de 3 restaurations par heure, ou si le registre n'est pas en 409, elle passe à l'opérateur.
