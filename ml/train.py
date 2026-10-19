"""Entraînement reproductible du détecteur d'anomalies et évaluation chiffrée.

Entrées :
- un (ou plusieurs) CSV de variables exportés par `ml/export_features.py` ;
- `ml/data/labels.csv` produit par `ml/attack_scenarios.py` (fenêtres d'attaque étiquetées).

Protocole :
- **apprentissage** sur les échantillons normaux antérieurs à `--train-until` (découpage temporel) ;
- **évaluation** des faux positifs sur le normal **tenu à l'écart** (postérieur à `--train-until`, y compris
  le trafic normal pendant les attaques et une période creuse), et du rappel sur les fenêtres d'attaque ;
- une **zone de transition** de 70 s après chaque attaque (les débits sur 1 min y restent élevés) n'est
  comptée ni comme normale ni comme attaque ;
- évaluation au niveau **échantillon** (score ≥ 0,8) et au niveau **alerte** (règle `for: 20s` simulée :
  3 échantillons consécutifs au-dessus du seuil, pas de 10 s).

Sorties :
- le modèle `<version>.json` écrit dans `services/anomaly-detector/model/` (embarqué dans l'image) et copié
  dans `ml/model/` (trace expérimentale versionnée) ;
- le rapport `ml/data/evaluation.json`.

Déterministe (aucun aléa) : le même jeu de données produit toujours le même modèle.

Usage :
    python ml/train.py --features ml/data/features.csv --labels ml/data/labels.csv --train-until <epoch>
"""

import argparse
import csv
import json
import math
import sys
from datetime import date
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "services" / "anomaly-detector"))
from app import features as feat  # noqa: E402
from app import model as model_mod  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SERVICE_MODEL_DIR = ROOT / "services" / "anomaly-detector" / "model"
ML_MODEL_DIR = ROOT / "ml" / "model"
THRESHOLD = 0.8
STEP = 10  # pas d'échantillonnage (s), identique à la boucle d'inférence et au scrape Prometheus
ALERT_FOR_SAMPLES = 3  # `for: 20s` évalué toutes les 10 s ⇒ condition vraie sur 3 évaluations consécutives
TRANSITION_S = 70  # après une attaque, la fenêtre glissante d'1 min reste « contaminée »

# Plancher d'échelle par variable : « unité d'écart minimale significative », pour éviter qu'une variable
# quasi nulle dans le normal n'explose au moindre bruit (et documenter l'échelle de sensibilité).
SCALE_FLOOR = {
    "req_rate": 0.3, "error_ratio_5xx": 0.02, "latency_p95": 0.1,
    "login_failures_per_min": 1.0, "client_errors_4xx_rate": 0.2, "probe_failed": 0.1,
    "invalid_tokens_per_min": 1.0, "req_rate_per_min": 3.0, "waf_blocks_per_min": 1.0,
}


def read_features(paths):
    # Cette méthode permet de charger et concaténer les CSV de variables en lignes {timestamp, service, variables...}.
    rows = []
    for path in paths:
        with open(path, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                parsed = {"timestamp": float(row["timestamp"]), "service": row["service"]}
                for key, value in row.items():
                    if key not in ("timestamp", "service"):
                        parsed[key] = float(value) if value not in ("", "nan", "NaN", None) else math.nan
                rows.append(parsed)
    return rows


def read_labels(path):
    # Cette méthode permet de charger les fenêtres d'attaque étiquetées (scenario, service, start, end).
    if not Path(path).exists():
        return []
    with open(path, newline="", encoding="utf-8") as handle:
        return [
            {"scenario": r["scenario"], "service": r["service"], "start": float(r["start"]), "end": float(r["end"])}
            for r in csv.DictReader(handle)
        ]


def phase_of(ts, service, labels):
    # Cette méthode permet de classer un échantillon : ("attack", label), ("transition", label) ou ("normal", None).
    # Une fenêtre d'attaque prime toujours sur la zone de transition d'une attaque précédente.
    mine = [lab for lab in labels if lab["service"] == service]
    for lab in mine:
        if lab["start"] <= ts <= lab["end"]:
            return "attack", lab
    for lab in mine:
        if lab["end"] < ts <= lab["end"] + TRANSITION_S:
            return "transition", lab
    return "normal", None


def build_matrix(rows, service):
    # Cette méthode permet de construire la matrice (n, variables) d'un service triée dans le temps, valeurs manquantes comblées.
    names = feat.feature_names(service)
    specs = {s.name: s for s in feat.FEATURES[service]}
    service_rows = sorted((r for r in rows if r["service"] == service), key=lambda r: r["timestamp"])
    raw = np.array([[r.get(n, math.nan) for n in names] for r in service_rows], dtype=float)
    medians = {n: float(np.nanmedian(raw[:, i])) if np.isfinite(raw[:, i]).any() else 0.0 for i, n in enumerate(names)}
    filled = raw.copy()
    for i, n in enumerate(names):
        col = filled[:, i]
        col[~np.isfinite(col)] = medians[n] if specs[n].nan_fill == "median" else 0.0
    return names, filled, [r["timestamp"] for r in service_rows]


def main():
    # Cette méthode permet d'entraîner le modèle sur le trafic normal et d'évaluer la détection sur les attaques.
    parser = argparse.ArgumentParser(description="Entraîne et évalue le détecteur d'anomalies.")
    parser.add_argument("--features", nargs="+", default=[str(ROOT / "ml" / "data" / "features.csv")])
    parser.add_argument("--labels", default=str(ROOT / "ml" / "data" / "labels.csv"))
    parser.add_argument("--train-until", type=float, default=None,
                        help="epoch : seuls les échantillons normaux antérieurs servent à l'apprentissage")
    parser.add_argument("--version", default=f"rz-{date.today().isoformat()}")
    parser.add_argument("--model", default=None,
                        help="évaluer ce modèle existant (aucun apprentissage) — ex. session de test indépendante")
    parser.add_argument("--report", default=str(ROOT / "ml" / "data" / "evaluation.json"))
    args = parser.parse_args()

    rows = read_features(args.features)
    labels = read_labels(args.labels)
    if not rows:
        print("Aucune donnée de variables : lancer d'abord export_features.py", file=sys.stderr)
        return 1
    train_until = args.train_until if args.train_until is not None else math.inf

    normal_vectors, feature_order, samples = {}, {}, {}
    for service in feat.SERVICES:
        names, matrix, timestamps = build_matrix(rows, service)
        feature_order[service] = names
        phases = [phase_of(ts, service, labels) for ts in timestamps]
        train_mask = np.array([p[0] == "normal" and ts <= train_until for p, ts in zip(phases, timestamps)])
        normal_vectors[service] = matrix[train_mask].tolist()
        samples[service] = (names, matrix, timestamps, phases)
        print(f"{service}: {len(timestamps)} échantillons, {int(train_mask.sum())} normaux d'apprentissage", flush=True)

    meta = {
        "threshold": THRESHOLD, "scale_floor": SCALE_FLOOR, "step_s": STEP,
        "train_until": None if math.isinf(train_until) else train_until,
        "feature_queries": {svc: {s.name: s.query for s in feat.FEATURES[svc]} for svc in feat.SERVICES},
        "n_rows": len(rows), "n_labels": len(labels),
    }
    if args.model:
        model = model_mod.RobustZScoreModel.load(args.model)
        saved = []
    else:
        model = model_mod.fit(args.version, normal_vectors, feature_order, scale_floor=SCALE_FLOOR, meta=meta)
        saved = [str(model.save(directory / f"{model.version}.json")) for directory in (SERVICE_MODEL_DIR, ML_MODEL_DIR)]
    report = {"version": model.version, "threshold": THRESHOLD, "features": [str(Path(f).name) for f in args.features],
              **evaluate(model, samples, labels, train_until)}
    Path(args.report).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print_report(report)
    if saved:
        print("\nModèle écrit :", *saved, sep="\n  ")
    print(f"Rapport : {args.report}")
    return 0


def _user_rate_index(names):
    # Cette méthode permet de retrouver la variable de débit utilisateur (pour repérer les périodes creuses).
    for candidate in ("req_rate", "req_rate_per_min"):
        if candidate in names:
            return names.index(candidate)
    return None


def evaluate(model, samples, labels, train_until):
    # Cette méthode permet de calculer précision, rappel, faux positifs et délais (échantillon et alerte).
    counts = {"tp": 0, "fn": 0, "fp_heldout": 0, "tn_heldout": 0, "fp_train": 0, "tn_train": 0}
    idle = {"n": 0, "fp": 0}
    per_scenario = {}
    false_alerts = []
    max_normal_score = {"heldout": 0.0, "train": 0.0}
    for service, (names, matrix, timestamps, phases) in samples.items():
        rate_idx = _user_rate_index(names)
        scores = [model.score_vector(service, list(row))["score"] for row in matrix]
        run = 0
        for i, (ts, score, (phase, lab)) in enumerate(zip(timestamps, scores, phases)):
            flagged = score >= THRESHOLD
            contiguous = i > 0 and abs(timestamps[i] - timestamps[i - 1] - STEP) < 1
            run = (run + 1 if contiguous else 1) if flagged else 0
            alert = run >= ALERT_FOR_SAMPLES
            if phase == "attack":
                key = f'{lab["scenario"]}@{service}'  # un scénario peut impacter plusieurs services
                e = per_scenario.setdefault(key, {"service": service, "n": 0, "hits": 0, "start": lab["start"],
                                                 "end": lab["end"], "first_hit": None, "first_alert": None, "max_score": 0.0})
                e["n"] += 1
                e["hits"] += flagged
                e["max_score"] = max(e["max_score"], score)
                if flagged and e["first_hit"] is None:
                    e["first_hit"] = ts
                if alert and e["first_alert"] is None:
                    e["first_alert"] = ts
                counts["tp" if flagged else "fn"] += 1
            elif phase == "normal":
                split = "train" if ts <= train_until else "heldout"
                counts[("fp_" if flagged else "tn_") + split] += 1
                max_normal_score[split] = max(max_normal_score[split], score)
                if rate_idx is not None and matrix[i][rate_idx] <= 1e-9:
                    idle["n"] += 1
                    idle["fp"] += flagged
                if alert and run == ALERT_FOR_SAMPLES:
                    false_alerts.append({"service": service, "timestamp": ts, "split": split})

    scenarios = {}
    for name, e in per_scenario.items():
        scenarios[name] = {
            "service": e["service"], "duration_s": round(e["end"] - e["start"]),
            "samples": e["n"], "detected_samples": e["hits"],
            "recall": round(e["hits"] / e["n"], 3) if e["n"] else 0.0,
            "max_score": round(e["max_score"], 3),
            "first_score_above_threshold_s": round(e["first_hit"] - e["start"], 1) if e["first_hit"] else None,
            "alert_delay_s": round(e["first_alert"] - e["start"], 1) if e["first_alert"] else None,
        }
    tp, fn, fp = counts["tp"], counts["fn"], counts["fp_heldout"]
    heldout_n = counts["fp_heldout"] + counts["tn_heldout"]
    train_n = counts["fp_train"] + counts["tn_train"]
    alerted = sum(1 for s in scenarios.values() if s["alert_delay_s"] is not None)
    return {
        "counts": counts,
        "precision_heldout": round(tp / (tp + fp), 3) if (tp + fp) else None,
        "recall_samples": round(tp / (tp + fn), 3) if (tp + fn) else None,
        "false_positive_rate_heldout": round(fp / heldout_n, 4) if heldout_n else None,
        "false_positive_rate_train": round(counts["fp_train"] / train_n, 4) if train_n else None,
        "false_positive_rate_idle": round(idle["fp"] / idle["n"], 4) if idle["n"] else None,
        "max_normal_score": {k: round(v, 3) for k, v in max_normal_score.items()},
        "normal_samples": {"train": train_n, "heldout": heldout_n, "idle": idle["n"]},
        "scenarios_alerted": f"{alerted}/{len(scenarios)}",
        "false_alerts": false_alerts,
        "scenarios": scenarios,
        "calibration": {s: {"t80": round(model.params[s]["t80"], 3), "beta": round(model.params[s]["beta"], 3),
                             "normal_severity_p99": round(model.params[s]["normal_severity_p99"], 3),
                             "normal_severity_max": round(model.params[s]["normal_severity_max"], 3)}
                        for s in model.params},
    }


def print_report(report):
    # Cette méthode permet d'afficher un bilan lisible de l'évaluation.
    print("\n===== Évaluation =====")
    print(f"Échantillons normaux : {report['normal_samples']}")
    print(f"Précision (normal tenu à l'écart) : {report['precision_heldout']}")
    print(f"Rappel (échantillons d'attaque)   : {report['recall_samples']}")
    print(f"Taux de FP normal tenu à l'écart  : {report['false_positive_rate_heldout']}")
    print(f"Taux de FP normal d'apprentissage : {report['false_positive_rate_train']}")
    print(f"Taux de FP en période creuse      : {report['false_positive_rate_idle']}")
    print(f"Score max sur le normal           : {report['max_normal_score']}")
    print(f"Scénarios ayant déclenché l'alerte (for 20s) : {report['scenarios_alerted']}")
    print(f"Fausses alertes simulées : {len(report['false_alerts'])} {report['false_alerts']}")
    print("Par scénario :")
    for name, s in report["scenarios"].items():
        print(f"  - {name:34s} rappel={s['recall']:<5} score max={s['max_score']:<6} "
              f"1er dépassement={_fmt_delay(s['first_score_above_threshold_s'])} alerte={_fmt_delay(s['alert_delay_s'])}")


def _fmt_delay(value):
    # Cette méthode permet d'afficher un délai en secondes, ou « non détecté ».
    return "non détecté" if value is None else f"{value}s"


if __name__ == "__main__":
    sys.exit(main())
