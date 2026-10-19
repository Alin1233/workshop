# Analyse de risques EBIOS RM — À RÉDIGER (pilier TRANSFORMATION)

1. **Cadrage et socle de sécurité** — valeurs métier (exécuter un virement, authentifier, garantir l'intégrité du registre), biens supports (services de `docker-compose.yml`), événements redoutés et gravité
2. **Sources de risque** — couples source / objectif visé
3. **Scénarios stratégiques** — chemins d'attaque par l'écosystème
4. **Scénarios opérationnels** — modes opératoires techniques (à relier aux scénarios de la branche `cyber`)
5. **Traitement du risque** — mesures (WAF, SOC, remédiation, secrets SOPS…), risques résiduels

> Lier chaque scénario retenu à une alerte (`infra/prometheus/rules`, `infra/loki/rules`) et à une action de remédiation.
