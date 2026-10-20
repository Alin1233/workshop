#!/usr/bin/env python3
"""Orchestrateur de recette côté hôte : rejoue un scénario de compromission **par la chaîne d'alertes** et
rassemble les preuves (bibliothèque standard + CLI Docker). On n'appelle jamais directement le moteur.

Déroulé d'un scénario réseau (force brute, injections, jetons invalides, anomalie ML) :
  1. démarre un conteneur « attaquant » sur le réseau `edge` (son IP edge est vue par le WAF comme l'IP cliente
     réelle — cf. services/remediation-engine/docs/waf-blocking.md) et un conteneur « témoin tiers » (autre IP edge) ;
  2. lance `attack.py` dans l'attaquant contre http://waf:8080 (aucun appel direct au moteur) ;
  3. interroge Alertmanager (quand l'alerte « firing »), Prometheus (règles) et l'API d'état du moteur (chronologie
     de l'incident : détection, décision, action de blocage, vérification, rétablissement, retombée, clôture) ;
  4. vérifie les réponses du WAF : l'attaquant reçoit 403 blocked_by_remediation, le témoin tiers et l'hôte 200 ;
  5. attend la levée automatique du blocage au TTL et revérifie que l'attaquant est de nouveau servi (200).

Les horodatages sont donnés en secondes depuis le début de l'attaque. Les identifiants Alertmanager/Prometheus
sont lus dans `secrets/` (admin / *_password) ; aucun secret n'est écrit en dur.

Usage :
  python3 scripts/scenarios/run_recette.py brute-force   --rate 25 --duration 30
  python3 scripts/scenarios/run_recette.py injections     --rate 25 --duration 40
  python3 scripts/scenarios/run_recette.py invalid-tokens --rate 30 --duration 40      # franchit le seuil SOC
  python3 scripts/scenarios/run_recette.py ml-anomaly     --rate 15 --duration 100     # sous le seuil SOC
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCENARIOS_DIR = REPO / "scripts" / "scenarios"
SECRETS = REPO / "secrets"

# scénario d'orchestration → attaque attack.py, alertes attendues, et clé d'incident à suivre.
# `incident_key` : si None, l'incident est retrouvé par l'IP (blocage SOC, clé ip:<IP>) ; sinon par cette clé de
# corrélation (chemin ML, clé anomaly:<service>) car l'incident d'anomalie n'est pas indexé sur l'IP.
SCENARIOS = {
    "brute-force": {"attack": "brute-force", "alerts": ["AuthBruteForce"], "incident_key": None},
    "injections": {"attack": "injections", "alerts": ["WafAttackBlocked"], "incident_key": None},
    "invalid-tokens": {"attack": "invalid-tokens", "alerts": ["InvalidTokenFlood"], "incident_key": None},
    # Chemin ML : jetons invalides sous le seuil SOC → AnomalyDetected (payment-api) → blocage par le chemin ML.
    "ml-anomaly": {"attack": "invalid-tokens", "alerts": ["AnomalyDetected"], "incident_key": "anomaly:payment-api"},
    # Chemin ML : force brute sous les seuils SOC → AnomalyDetected (auth-service), variable login_failures_per_min.
    "ml-brute-force": {"attack": "brute-force", "alerts": ["AnomalyDetected"], "incident_key": "anomaly:auth-service"},
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def sh(cmd, timeout=60, check=False):
    # Cette méthode permet d'exécuter une commande et d'en renvoyer (code, stdout, stderr).
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} → {res.returncode} : {res.stderr.strip()}")
    return res.returncode, res.stdout, res.stderr


def secret(name):
    # Cette méthode permet de lire un secret (mot de passe) depuis le dossier secrets/ (jamais en dur dans le code).
    return (SECRETS / name).read_text(encoding="utf-8").strip()


def http_json(url, user=None, password=None, timeout=10):
    # Cette méthode permet de lire une API JSON (Alertmanager/Prometheus) avec authentification basique optionnelle.
    req = urllib.request.Request(url)
    if user is not None:
        req.add_header("Authorization", "Basic " + b64encode(f"{user}:{password}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return json.loads(res.read().decode())
    except (urllib.error.URLError, ValueError) as exc:
        return {"error": str(exc)}


def engine_api(project, path):
    # Cette méthode permet d'interroger l'API d'état en lecture seule du moteur DEPUIS son conteneur (aucun port publié).
    code, out, err = sh(["docker", "exec", f"{project}-remediation-engine-1", "python", "-c",
                         f"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000{path}').read().decode())"],
                        timeout=30)
    if code != 0:
        return {"error": err.strip()}
    try:
        return json.loads(out)
    except ValueError:
        return {"error": out.strip()[:200]}


def container_ip(name, network):
    # Cette méthode permet de lire l'IP d'un conteneur sur un réseau donné.
    code, out, _ = sh(["docker", "inspect", "-f",
                       f"{{{{(index .NetworkSettings.Networks \"{network}\").IPAddress}}}}", name])
    return out.strip() if code == 0 else ""


def start_client(name, network):
    # Cette méthode permet de démarrer (ou réutiliser) un conteneur client python sur le réseau edge.
    sh(["docker", "rm", "-f", name])
    sh(["docker", "run", "-d", "--name", name, "--network", network,
        "-v", f"{SCENARIOS_DIR}:/s:ro", "--entrypoint", "sleep", "python:3.12-slim", "3600"], check=True)
    return container_ip(name, network)


def waf_status(container, path="/"):
    # Cette méthode permet de lire le code HTTP et le corps vus par un conteneur client via le WAF interne (edge).
    code, out, _ = sh(["docker", "exec", container, "python", "-c",
                       "import urllib.request,urllib.error,sys\n"
                       "try:\n r=urllib.request.urlopen('http://waf:8080" + path + "',timeout=6)\n"
                       " print(r.status, r.read(200).decode('utf-8','replace'))\n"
                       "except urllib.error.HTTPError as e:\n print(e.code, e.read(200).decode('utf-8','replace'))\n"
                       "except Exception as e:\n print(0, e)"])
    return out.strip()


def host_status(target):
    # Cette méthode permet de lire le code HTTP vu par l'hôte à travers le port publié du WAF (IP passerelle, exclue).
    try:
        with urllib.request.urlopen(target + "/", timeout=6) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return 0


def find_alert(project, names, client_ip, am_user, am_pw):
    # Cette méthode permet de retrouver, dans Alertmanager, une alerte « firing » attendue (et son startsAt).
    data = http_json("http://127.0.0.1:9093/api/v2/alerts?active=true&silenced=false&inhibited=false",
                     am_user, am_pw)
    if not isinstance(data, list):
        return None
    for a in data:
        labels = a.get("labels", {})
        if labels.get("alertname") in names and (not client_ip or labels.get("client_ip") == client_ip):
            return {"alertname": labels["alertname"], "client_ip": labels.get("client_ip"),
                    "startsAt": a.get("startsAt"), "state": a.get("status", {}).get("state")}
    return None


def incident_for_ip(project, client_ip):
    # Cette méthode permet de retrouver l'incident du moteur qui porte l'IP attaquante (ouvert ou récemment clos).
    state = engine_api(project, "/api/state")
    for bucket in ("open_incidents", "recent_incidents"):
        for inc in state.get(bucket, []):
            key = inc.get("key", "")
            if client_ip and client_ip in key:
                return engine_api(project, f"/api/incidents/{inc['id']}")
    # repli : parcours des incidents récents
    for inc in engine_api(project, "/api/incidents?limit=20") or []:
        if client_ip and client_ip in inc.get("key", ""):
            return engine_api(project, f"/api/incidents/{inc['id']}")
    return None


def incident_by_key(project, key, t0):
    # Cette méthode permet de retrouver le dernier incident portant une clé de corrélation donnée (ex. anomaly:auth-service)
    # ouvert après t0 : l'incident d'anomalie n'étant pas indexé sur l'IP, on le suit par sa clé.
    best = None
    for inc in engine_api(project, "/api/incidents?limit=30") or []:
        if inc.get("key") == key and (epoch(inc.get("created_at")) or 0) >= t0 - 3:
            if best is None or (epoch(inc.get("created_at")) or 0) >= (epoch(best.get("created_at")) or 0):
                best = inc
    return engine_api(project, f"/api/incidents/{best['id']}") if best else None


def epoch(iso_s):
    # Cette méthode permet de convertir un horodatage ISO en epoch (None si absent).
    if not iso_s or str(iso_s).startswith("0001-"):
        return None
    try:
        return datetime.fromisoformat(str(iso_s).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def timeline_offsets(incident, t0):
    # Cette méthode permet d'extraire de la chronologie les jalons clés, en secondes depuis le début de l'attaque.
    marks = {}
    for ev in incident.get("timeline", []):
        name, ts = ev.get("event"), epoch(ev.get("at"))
        if ts is None:
            continue
        off = round(ts - t0, 1)
        key = {"state:detected": "détection (webhook)", "triage": "triage (variable dominante)",
               "state:decided": "décision", "action:block_ip": "blocage effectué",
               "verification:waf_block": "blocage vérifié", "state:recovered": "rétabli et vérifié",
               "state:escalated": "escalade (pas de blocage)", "state:observing": "observation (pas de blocage)",
               "alert:resolved": "alerte retombée", "closed": "incident clos",
               "verification:witness": "transaction témoin"}.get(name)
        if name == "action:block_ip" and ev.get("detail", {}).get("result") != "success":
            key = None
        if key and key not in marks:
            marks[key] = off
    return marks


def poll(project, names, client_ip, t0, watch_s, am_user, am_pw, incident_key=None):
    # Cette méthode permet de suivre l'apparition de l'alerte, puis l'issue de l'incident (blocage, escalade ou
    # observation) pendant `watch_s` secondes. Pour un incident d'anomalie (clé anomaly:<service>), l'alerte
    # AnomalyDetected ne porte pas de client_ip : on la retrouve donc sans filtre d'IP.
    alert_seen, action_seen, incident_id = None, None, None
    alert_ip = None if incident_key else client_ip
    deadline = time.time() + watch_s
    while time.time() < deadline:
        if alert_seen is None:
            a = find_alert(project, names, alert_ip, am_user, am_pw)
            if a:
                fired = epoch(a.get("startsAt"))
                alert_seen = {**a, "seen_offset_s": round(time.time() - t0, 1),
                              "firing_offset_s": round(fired - t0, 1) if fired else None}
                print(f"  + alerte {a['alertname']} firing à +{alert_seen['firing_offset_s']}s "
                      f"(startsAt={a['startsAt']}, vue à +{alert_seen['seen_offset_s']}s)", flush=True)
        inc = incident_by_key(project, incident_key, t0) if incident_key else incident_for_ip(project, client_ip)
        if inc:
            incident_id = inc.get("id")
            blocked = any(e.get("event") == "action:block_ip" and e.get("detail", {}).get("result") == "success"
                          for e in inc.get("timeline", []))
            if blocked and action_seen is None:
                action_seen = round(time.time() - t0, 1)
                print(f"  + blocage de {inc.get('service') or client_ip} à +{action_seen}s "
                      f"(incident {incident_id})", flush=True)
            state = inc.get("state")
            if state in ("recovered", "escalated"):
                print(f"  + incident {incident_id} → {state}"
                      + (" (aucun blocage)" if not blocked else ""), flush=True)
                return alert_seen, incident_id, inc
        time.sleep(2)
    return alert_seen, incident_id, (incident_by_key(project, incident_key, t0) if incident_key
                                     else incident_for_ip(project, client_ip))


def wait_unblock(project, client_ip, attacker, t0, max_s):
    # Cette méthode permet d'attendre la levée EFFECTIVE du blocage : l'entrée disparaît de l'état du moteur (expiration
    # logique au TTL) PUIS le WAF sert de nouveau l'attaquant (le fichier est réécrit et nginx rechargé par la tâche de
    # fond `expire()`, au plus une période après le TTL). On mesure l'instant où le WAF rend 200.
    deadline = time.time() + max_s
    logical = None
    while time.time() < deadline:
        blocks = [b["ip"] for b in engine_api(project, "/api/state").get("blocked_ips", [])]
        if client_ip not in blocks and logical is None:
            logical = round(time.time() - t0, 1)
        if logical is not None and waf_status(attacker).startswith("200"):
            return {"logical_s": logical, "enforced_s": round(time.time() - t0, 1)}
        time.sleep(3)
    return {"logical_s": logical, "enforced_s": None}


def main():
    parser = argparse.ArgumentParser(description="Orchestrateur de recette (chaîne d'alertes complète).")
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--target", default="http://127.0.0.1:8088", help="WAF vu de l'hôte")
    parser.add_argument("--project", default="resilience-alpha")
    parser.add_argument("--network", default="resilience-alpha_edge")
    parser.add_argument("--rate", type=int, default=25)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--watch", type=int, default=120, help="durée de suivi alerte/incident (s)")
    parser.add_argument("--unblock-wait", type=int, default=150, help="attente max de la levée au TTL (s), 0 = ne pas attendre")
    parser.add_argument("--out", default=None, help="fichier JSON de preuves")
    args = parser.parse_args()

    cfg = SCENARIOS[args.scenario]
    attack_cmd, alert_names, incident_key = cfg["attack"], cfg["alerts"], cfg["incident_key"]
    am_pw = secret("alertmanager_password")
    attacker = f"recette-attacker-{args.scenario}"
    bystander = f"recette-bystander-{args.scenario}"

    print(f"== Recette {args.scenario} ({now_iso()}) ==", flush=True)
    attacker_ip = start_client(attacker, args.network)
    bystander_ip = start_client(bystander, args.network)
    print(f"  attaquant edge={attacker_ip}  témoin tiers edge={bystander_ip}", flush=True)
    print("  (aucune seconde machine réelle disponible : conteneur edge = second poste simulé)", flush=True)

    t0 = time.time()
    print(f"  lancement de l'attaque à t0={now_iso()}", flush=True)
    attack_summary = {}
    if incident_key:
        # Incident d'anomalie : le blocage (ou l'escalade) survient PENDANT l'attaque (le score met ~1 min à monter,
        # `for: 20s` ensuite). On lance donc l'attaque en tâche de fond et on suit l'incident en parallèle.
        sh(["docker", "exec", "-d", attacker, "python3", "/s/attack.py", attack_cmd,
            "--target", "http://waf:8080", "--rate", str(args.rate), "--duration", str(args.duration)])
        attack_summary = {"note": "attaque détachée, incident d'anomalie suivi en parallèle",
                          "rate_per_min": args.rate, "duration_s": args.duration}
        print(f"  attaque détachée (brute-force {args.rate}/min, {args.duration}s)", flush=True)
    else:
        code, out, err = sh(["docker", "exec", attacker, "python3", "/s/attack.py", attack_cmd,
                             "--target", "http://waf:8080", "--rate", str(args.rate), "--duration", str(args.duration)],
                            timeout=args.duration + 120)
        for line in out.splitlines():
            if line.startswith("{"):
                attack_summary = json.loads(line)
        t0 = attack_summary.get("started_epoch", t0)
        print(f"  attaque : {attack_summary.get('statuses')} ({attack_summary.get('requests')} req)", flush=True)

    alert_seen, incident_id, incident = poll(args.project, alert_names, attacker_ip, t0, args.watch, "admin", am_pw,
                                             incident_key=incident_key)
    blocked = bool(incident) and any(a.get("action") == "block_ip" and a.get("result") == "success"
                                     for a in (incident or {}).get("actions", []))

    checks = {
        "attaquant_waf": waf_status(attacker),
        "temoin_tiers_waf": waf_status(bystander),
        "hote_waf_http": host_status(args.target),
    }
    print(f"  WAF → attaquant: {checks['attaquant_waf'][:60]}", flush=True)
    print(f"  WAF → témoin tiers: {checks['temoin_tiers_waf'][:60]}", flush=True)
    print(f"  WAF → hôte (port publié): {checks['hote_waf_http']}", flush=True)
    decision_reason = (incident or {}).get("decision", {}).get("reason") if incident else None
    if decision_reason:
        print(f"  décision : {decision_reason}", flush=True)

    unblock_off = None
    if args.unblock_wait and blocked:
        print(f"  attente de la levée automatique (TTL)…", flush=True)
        unblock_off = wait_unblock(args.project, attacker_ip, attacker, t0, args.unblock_wait)
        print(f"  + {attacker_ip} : expiration logique +{unblock_off['logical_s']}s, "
              f"levée effective (WAF sert de nouveau) +{unblock_off['enforced_s']}s", flush=True)
        checks["attaquant_waf_apres_levee"] = waf_status(attacker)
        print(f"  WAF → attaquant après levée: {checks['attaquant_waf_apres_levee'][:60]}", flush=True)

    offsets = timeline_offsets(incident or {}, t0) if incident else {}
    triage = next((e.get("detail", {}) for e in (incident or {}).get("timeline", []) if e.get("event") == "triage"), {})
    evidence = {
        "scenario": args.scenario, "run_at": now_iso(), "attacker_ip": attacker_ip, "bystander_ip": bystander_ip,
        "attack": attack_summary, "alert": alert_seen, "incident_id": incident_id,
        "incident_state": (incident or {}).get("state"), "incident_key": (incident or {}).get("key"),
        "blocked": blocked, "decision_reason": decision_reason,
        "dominant_feature": triage.get("dominant_feature"), "anomaly_score": triage.get("anomaly_score"),
        "escalation": (incident or {}).get("escalation"), "offsets_s": offsets,
        "unblock_offset_s": unblock_off, "checks": checks,
        "block_entries": engine_api(args.project, "/api/state").get("blocked_ips", []),
    }
    out_path = Path(args.out) if args.out else (REPO / f"/tmp/recette-{args.scenario}.json")
    try:
        Path(out_path).write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  preuves → {out_path}", flush=True)
    except OSError:
        pass
    print("  JALONS (s depuis le début de l'attaque) : " + json.dumps(offsets, ensure_ascii=False), flush=True)

    sh(["docker", "rm", "-f", attacker, bystander])
    print(json.dumps(evidence, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
