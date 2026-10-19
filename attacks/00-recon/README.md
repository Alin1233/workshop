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

---

## `vuln-scan.sh` — CVE sur les versions réellement exécutées (SCA)

**Objectif** — Inventorier les vulnérabilités connues (CVE) des bibliothèques et images que le SI exécute, avec la version corrigée. Point d'entrée du *CVE path* du skill `/redteam` (triage → exploit).

**Pourquoi un scan dédié** — Les `requirements.txt` Python sont des **plages** (`fastapi>=0.115,<1`), pas des versions figées : la version réellement vulnérable est celle que pip a résolue **dans l'image**. Le script lit donc les versions *construites / en cours d'exécution*, pas les manifestes.

**Prérequis** — `trivy` (ou `grype`), `docker`, `npm`. Exécuté **sur le PC Hôte** (accès aux images/conteneurs), en gris-boîte. `sudo dnf install -y trivy`.

**Commande**
```bash
./vuln-scan.sh                 # images du docker-compose + images de service
./vuln-scan.sh ollama/ollama:latest
```

**Sortie** — `attacks/logs/vulnscan-*/` : rapports trivy/grype par image, `pip freeze` des services Python, `npm audit` du frontend, et `findings-HIGH-CRITICAL.txt` (CVE → version installée → version corrigée).

**Note durcissement** — `ollama/ollama:latest` n'est pas épinglé (dérive de tag + risque chaîne d'appro) ; à épingler. La pile applicative est récente : scanner avant de supposer une CVE exploitable.
