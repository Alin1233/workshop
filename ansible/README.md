# Ansible — automatisation du déploiement et des opérations de reprise (pilier INFRA)

Ansible ne s'exécute pas nativement sous Windows : lancer les playbooks depuis WSL2 (Docker Desktop doit avoir
l'intégration WSL activée pour que `docker compose` y fonctionne).

```bash
# dans WSL, à la racine du dépôt
python3 -m pip install --user ansible-core
ansible-playbook -i ansible/inventory.ini ansible/deploy.yml
ansible-playbook -i ansible/inventory.ini ansible/restart_service.yml -e service=payment-api
```

| Playbook | Rôle | État |
|---|---|---|
| `deploy.yml` | secrets (SOPS) → `docker compose up --wait` → test de bout en bout | prêt, non testé (pas d'Ansible sur le poste de dev) |
| `restart_service.yml` | redémarre un service et vérifie la reprise réelle | prêt, non testé |
| `backup_database.yml` / `restore_database.yml` | sauvegarde / restauration PostgreSQL | **à faire** |

## À faire
- [ ] Tester les deux playbooks depuis WSL
- [ ] Sauvegarde `pg_dump` planifiée + restauration (base des scénarios PRA « données corrompues »)
- [ ] Décider si le moteur de remédiation appelle ces playbooks ou l'API Docker (expliquer le choix au jury)
- [ ] Playbook de préparation du PC Hôte (point d'accès RESILIENCE-G<n>, pare-feu Windows, ports)
