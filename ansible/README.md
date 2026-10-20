# Ansible — automatisation du déploiement et des opérations de reprise (pilier INFRA)

Les playbooks se lancent depuis WSL2 (Ansible ne s'exécute pas nativement sous Windows), à la racine du dépôt.
Ils pilotent le PC Hôte, la VM Proxmox du groupe 6 (`[pc_hote]` dans `inventory.ini`), par SSH.

```bash
python3 -m pip install --user ansible-core       # ou : sudo apt install ansible
ansible-playbook ansible/provision_proxmox.yml   # 1. créer la VM (une fois)
ansible-playbook -i ansible/inventory.ini ansible/prepare_host.yml   # 2. Docker, pare-feu, SSH (une fois)
ansible-playbook -i ansible/inventory.ini ansible/deploy.yml         # 3. déployer le commit courant
ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e service=payment-api   # reprise
ansible-playbook -i ansible/inventory.ini ansible/backup_database.yml                          # sauvegarde + copie locale
ansible-playbook -i ansible/inventory.ini ansible/restore_database.yml -e confirm_restore=true  # PRA données
```

## Provisionnement de la VM PC Hôte (Proxmox du labo)

Le PC Hôte du groupe 6 est la VM `4600 i1-workshop-resilience-g6-host` (Debian 13, 6 vCPU, 16 Go, 80 Go,
`172.16.147.10/16`) dans le pool `I1` du Proxmox `https://proxmox.labo.loc` (wifi labo uniquement).
Paramètres dans `vars/proxmox_vm.yml`.

Prérequis, une seule fois, hors du dépôt :
- `~/.config/proxmox/claude.env` (mode 600) : `PROXMOX_URL`, `PROXMOX_TOKEN_ID`, `PROXMOX_TOKEN_SECRET` ;
- `~/.config/proxmox/proxmox-labo.pem` : certificat auto-signé du Proxmox, épinglé pour garder la vérification TLS
  (empreinte SHA-256 `DD:BA:7C:C4:DA:4C:B5:6D:FA:1E:11:54:7B:3E:9A:CE:14:79:8B:5E:7A:BF:00:00:D8:92:30:0F:FD:84:25:BB`) :

```bash
openssl s_client -connect proxmox.labo.loc:443 </dev/null 2>/dev/null | openssl x509 > ~/.config/proxmox/proxmox-labo.pem
```

```bash
set -a; . ~/.config/proxmox/claude.env; set +a
ansible-playbook ansible/provision_proxmox.yml
ssh resilience@172.16.147.10
```

Le playbook est idempotent (relancé, il ne change rien) et ne touche qu'aux ID de `pve_allowed_vmids` : le token
administre tout le pool `I1`, VM des autres groupes comprises. Ne jamais le lancer en `-vvv`, qui afficherait le secret.

## Préparation du PC Hôte

```bash
ansible-playbook -i ansible/inventory.ini ansible/prepare_host.yml
```

- **Docker** : dépôt officiel, clé vérifiée par son empreinte, `live-restore` (les conteneurs survivent à un redémarrage
  du démon) et `no-new-privileges` par défaut. `resilience` n'est pas dans le groupe `docker` (équivalent root) : `sudo docker …`.
- **Pare-feu** (`templates/nftables.conf.j2`) : entrée refusée par défaut sauf SSH depuis `172.16.0.0/16` et le port du WAF.
  Pas de `flush ruleset`, et l'arrêt du service ne supprime que la table `host_filter` : les règles de Docker sont préservées.
  Les ports publiés par Docker passent par FORWARD et **ne sont pas filtrés par cette table** : ce qui ne doit pas être
  exposé reste publié sur `127.0.0.1` dans `docker-compose.yml`.
- **SSH** : clé uniquement, `root` interdit, `AllowUsers resilience`, tunnels locaux seulement. Accès aux interfaces de gestion :

```bash
ssh -N -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 -L 8091:127.0.0.1:8091 resilience@172.16.147.10
```

  Prometheus, Alertmanager et Loki demandent un identifiant : `admin` / `shared/secrets/<service>_password` ; de même le
  dashboard de supervision (écran du Clip Chrono, http://127.0.0.1:8091) : `admin` / `shared/secrets/supervision_password`.

- **Mises à jour** : sécurité Debian automatique, sans redémarrage ; Docker, hors de ces dépôts, ne bouge pas pendant la démo.

## Déploiement

```bash
ansible-playbook -i ansible/inventory.ini ansible/deploy.yml                    # commit courant (HEAD)
ansible-playbook -i ansible/inventory.ini ansible/deploy.yml -e deploy_ref=v1  # un commit, une branche ou un tag
```

```
/opt/resilience-alpha/
├── releases/<commit>/     une version par commit (git archive), jamais modifiée après extraction ; 3 conservées
│   └── secrets -> ../../shared/secrets
├── shared/secrets/        0700 root : générés au premier déploiement (ou restaurés par SOPS), conservés ensuite
└── current -> releases/<commit>
```

- **Ce qui est déployé est un commit**, pas la copie de travail : les modifications non commitées sont signalées et ignorées.
- **Secrets hors des versions** : `shared/.env` (écrit par le playbook, relié dans chaque version) fixe `SECRETS_DIR` sur
  `shared/secrets`. Compose ne recrée pas un conteneur dont seul le chemin d'un secret change : avec un chemin par version,
  les API restaient montées sur une version supprimée ensuite et ne redémarraient plus (`bind source path does not exist`).
- **Aucun conteneur sur une ancienne version** : après `up`, les conteneurs qui montent encore un fichier d'une autre version
  sont recréés, et une version encore montée n'est jamais supprimée par le ménage.
- **Retour arrière** : redéployer le commit précédent (`-e deploy_ref=<commit>`) ; la base et les volumes nommés sont conservés.
- Compose est lancé depuis le chemin réel de la version : les conteneurs qui montent une configuration du dépôt
  sont recréés à chaque nouvelle version, jamais laissés sur l'ancienne configuration.
- Vérifications : transaction témoin et chaîne d'observation **sur l'hôte**, puis transaction témoin **depuis le poste
  de l'opérateur**, à travers le réseau et le pare-feu, comme le PC attaquant ou le jury.
- Les mots de passe affichés par `init_secrets.py` sont masqués (`no_log`). Pour les lire :
  `ssh resilience@172.16.147.10 sudo cat /opt/resilience-alpha/shared/secrets/admin_password`
  (idem `grafana_admin_password`, `prometheus_password`, `alertmanager_password`, `loki_password`).
- Les hash bcrypt de ces comptes sont calculés par `htpasswd` dans un conteneur `httpd:2.4-alpine` jetable quand
  la bibliothèque Python `bcrypt` est absente (cas de la VM) : rien à installer sur l'hôte.

## Sauvegarde et restauration PostgreSQL

Procédure, mesures et limites : [docs/runbooks/restauration-base.md](../docs/runbooks/restauration-base.md).

- `deploy.yml` installe `/usr/local/sbin/resilience-pg-backup` et `resilience-pg-restore` (`templates/`) et le timer
  systemd `resilience-pg-backup.timer` : une sauvegarde toutes les 15 min (`pc_hote_backup_calendar`), soit un RPO ≤ 15 min.
- Chaque sauvegarde (`/var/backups/resilience-alpha/<horodatage>-<type>/`, 0700 root) contient un `pg_dump` par base,
  les empreintes SHA-256 et l'**état d'intégrité du registre** relevé avant et après les dumps.
- `restore_database.yml` restaure par défaut la **dernière sauvegarde saine** : une sauvegarde prise après une corruption
  n'est jamais choisie d'office. L'état courant est conservé avant écrasement (`pre-restore`), pour l'investigation.
- Les scripts écrivent leurs mesures pour node-exporter (`/var/lib/node-exporter/textfile/*.prom`) : alertes
  `BackupFailed` et `BackupMissing`, rangée « PC Hôte et sauvegardes » du tableau Grafana « Santé du service ».
- Ni les rôles ni leurs mots de passe ne sont sauvegardés : `db/init/01-create-service-databases.sh` les recrée depuis les secrets.
- **Restauration automatique** : `deploy.yml` installe aussi le pont de remédiation (`tasks/remediation_bridge_install.yml`,
  `files/resilience-remediation-bridge.py`). Le moteur, conteneur non privilégié, ne fait que déposer une demande dans
  `/var/lib/resilience-alpha/remediation-bridge/inbox/` (`REMEDIATION_BRIDGE_DIR` dans `shared/.env`) ; l'unité
  `resilience-remediation-bridge.path` lance `resilience-pg-restore latest-healthy` (root sans capacités, unité durcie),
  seulement si le registre est en 409, une seule à la fois, 3 par heure au plus. Un timer tient un heartbeat à jour ; le
  déploiement échoue si l'unité durcie ne joint pas Docker. Protocole et modèle de sécurité : runbook ci-dessus.
- `resilience-pg-restore` prend un verrou (code 75 si une restauration tourne déjà) : playbook et pont ne se chevauchent pas.

## Recette sur une machine vierge et PRA « perte du PC Hôte »

Une VM jetable (profil `recette` de `vars/proxmox_vm.yml` : `4601`, 4 vCPU, 8 Go, `172.16.147.11`) rejoue toute
l'installation depuis un clone neuf du dépôt, puis reçoit la dernière copie locale des données. C'est aussi le
scénario PRA « perte totale du PC Hôte » : reconstruire l'hôte, puis restaurer les données.

```bash
set -a; . ~/.config/proxmox/claude.env; set +a
ansible-playbook -i ansible/inventory.ini ansible/backup_database.yml        # copie locale récente des données
ansible-playbook ansible/provision_proxmox.yml -e vm_profile=recette
ansible-playbook -i ansible/inventory-recette.ini ansible/prepare_host.yml
ansible-playbook -i ansible/inventory-recette.ini ansible/deploy.yml
ansible-playbook -i ansible/inventory-recette.ini ansible/restore_database.yml -e confirm_restore=true -e backup_from_local=<nom>
ansible-playbook ansible/destroy_proxmox_vm.yml -e vm_profile=recette -e confirm_destroy=true
```

`destroy_proxmox_vm.yml` ne supprime qu'un profil marqué `disposable: true` : le PC Hôte ne peut pas l'être.

Résultat du 19/10, depuis un clone neuf (ni `secrets/`, ni `.env`) :

| Étape | Durée | Résultat |
|---|---|---|
| `provision_proxmox.yml -e vm_profile=recette` | 63 s | VM créée, SSH par clé |
| `prepare_host.yml` | 91 s | Docker, pare-feu, SSH durci |
| `deploy.yml` | 157 s | images construites, 3 vérifications OK (dont la transaction témoin à travers le réseau) |
| **Hôte reconstruit, sans données** | **311 s** | |
| `restore_database.yml -e backup_from_local=…` | 65 s (restauration seule : 13,8 s) | données restaurées, registre cohérent ; **transaction témoin 26/28** |
| `destroy_proxmox_vm.yml` | 13 s | VM et disques supprimés, PC Hôte intact |

**Limite du PRA « perte du PC Hôte » : les secrets.** Sur un hôte reconstruit, `init_secrets.py` génère de nouveaux
secrets, mais le compte admin restauré garde l'empreinte de l'**ancien** mot de passe (`seed_admin` ne crée le compte que
s'il n'existe pas) : la connexion admin échoue avec le nouveau mot de passe et réussit avec l'ancien. Les données et les
comptes clients sont intacts ; les rôles PostgreSQL et les clés JWT, recréés depuis les nouveaux secrets, fonctionnent.
Pour une reprise complète, les secrets doivent être restaurés avec les données : `secrets.enc.json` chiffré par SOPS + age
(pilier Cyber), que `deploy.yml` déchiffre déjà s'il est versionné.

| Playbook | Rôle | État |
|---|---|---|
| `provision_proxmox.yml` | clone du template Debian 13 cloud-init → ressources → disque → démarrage → SSH (`-e vm_profile=recette`) | testé (19/10) |
| `destroy_proxmox_vm.yml` | supprime une VM jetable (recette), disques compris ; refuse le PC Hôte | testé (19/10) |
| `prepare_host.yml` | Docker Engine + Compose, pare-feu nftables, durcissement SSH, mises à jour de sécurité | testé (19/10) |
| `deploy.yml` | commit → version extraite → secrets → `docker compose up --wait` → tests sur l'hôte et à travers le réseau | testé (19/10) |
| `restart_service.yml` | recrée un service autorisé de la version active et vérifie la reprise réelle | testé (19/10) |
| `backup_database.yml` | sauvegarde à la demande + copie vérifiée sur le poste de l'opérateur ; (ré)installe la sauvegarde planifiée | testé (19/10) |
| `restore_database.yml` | restaure la dernière sauvegarde saine (ou `-e backup=<nom>`), contrôle d'intégrité, transaction témoin | testé (19/10) |

## À faire
- [ ] Chiffrer la copie locale des sauvegardes (age, clé de l'équipe)
- [ ] Pendant une restauration, ne pas « réparer » les API arrêtées : le moteur le sait (`RestoreBridge.in_flight`, heartbeat
  `busy`) ; pour une restauration lancée par l'opérateur, silence Alertmanager ciblé posé à la main (procédure et
  commandes : `docs/runbooks/incident-response.md`, « Restauration lancée par l'opérateur ») ; reste à l'automatiser dans
  `restore_database.yml`
- [x] Moteur de remédiation et restauration : ni playbook ni API Docker, un pont de fichiers vers une unité systemd de l'hôte
  (le moteur ne choisit ni la commande ni ses arguments)
- [ ] Tester le pont sur la VM (root sans capacités, `inbox/` à l'uid 10001) : essai local fait avec `systemd-run --user`
- [ ] SOPS sur le PC Hôte : installer `sops` et la clé age (ou déchiffrer sur le poste de l'opérateur) avant de versionner `secrets.enc.json`
