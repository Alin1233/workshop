# 00 — Reconnaissance (non intrusive)

**Objectif** — Établir l'inventaire de départ du SI avant toute attaque : ports ouverts, bannières de service, en-têtes HTTP, routes exposées à travers le WAF. Étape préalable, pas une attaque.

**Prérequis** — `nmap`, `curl`, `ffuf` (optionnel), une wordlist (`/usr/share/wordlists/dirb/common.txt` par défaut). Depuis le PC Attaquant uniquement.

**Commande**
```bash
./recon.sh 192.168.137.1 8080
```

**Effet attendu** — Aucun effet sur le service. Bruit léger côté logs. Résultats horodatés dans `attacks/logs/recon-*`.

**Détection attendue** — Aucune alerte dédiée (volume faible). Peut apparaître dans les journaux d'accès nginx/WAF.

**Remédiation attendue** — Aucune. Sert de point de comparaison « avant incident » pour le dossier.
