# Ansible — automatisation du déploiement et des opérations de reprise (pilier INFRA)

Ansible ne s'exécute pas nativement sous Windows : lancer les playbooks depuis WSL2 (Docker Desktop doit avoir
l'intégration WSL activée pour que `docker compose` y fonctionne).

```bash
# dans WSL, à la racine du dépôt
python3 -m pip install --user ansible-core
ansible-playbook -i ansible/inventory.ini ansible/deploy.yml
ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e service=payment-api
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

| Playbook | Rôle | État |
|---|---|---|
| `provision_proxmox.yml` | clone du template Debian 13 cloud-init → ressources → disque → démarrage → SSH | testé (19/10) |
| `deploy.yml` | secrets (SOPS) → `docker compose up --wait` → test de bout en bout | prêt, non testé (pas d'Ansible sur le poste de dev) |
| `restart_service.yml` | redémarre un service et vérifie la reprise réelle | prêt, non testé |
| `backup_database.yml` / `restore_database.yml` | sauvegarde / restauration PostgreSQL | **à faire** |

## À faire
- [ ] Tester les deux playbooks depuis WSL
- [ ] Sauvegarde `pg_dump` planifiée + restauration (base des scénarios PRA « données corrompues »)
- [ ] Décider si le moteur de remédiation appelle ces playbooks ou l'API Docker (expliquer le choix au jury)
- [ ] Playbook de préparation du PC Hôte (point d'accès RESILIENCE-G<n>, pare-feu Windows, ports)
