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
  3 échantillons consécutifs au-dessus du seuil, pas de 10 s) ;
- prétraitement **identique à la production** : les valeurs manquantes de l'apprentissage sont comblées avec la
  médiane du seul normal d'apprentissage, et toute l'évaluation passe par `features.clean_values` avec les
  médianes du modèle (`model.medians()`), exactement comme le service ;
- statistiques **par fenêtre d'attaque** (`labels.csv` est en ajout seul : un même scénario peut avoir été joué
  plusieurs fois), agrégées par `scénario@service`.

Sorties :
- le modèle `<version>.json` écrit dans `services/anomaly-detector/model/` (embarqué dans l'image) et copié
  dans `ml/model/` (trace expérimentale versionnée), avec le pointeur `CURRENT` (nom du modèle actif) mis à jour
  dans les deux répertoires : c'est lui, et non l'ordre des noms de fichiers, qui désigne le modèle déployé ;
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
THRESHOLD = model_mod.THRESHOLD  # source unique : app/model.py (comparaison « ≥ » partout)
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
    # Cette méthode permet de charger les fenêtres d'attaque étiquetées (scenario, service, start, end) ; chaque
    # ligne reçoit un identifiant de fenêtre (le fichier est en ajout seul : un scénario peut avoir plusieurs fenêtres).
    if not Path(path).exists():
        return []
    with open(path, newline="", encoding="utf-8") as handle:
        return [
            {"id": i, "scenario": r["scenario"], "service": r["service"], "start": float(r["start"]), "end": float(r["end"])}
            for i, r in enumerate(csv.DictReader(handle))
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


def service_rows(rows, service):
    # Cette méthode permet d'extraire, triées dans le temps, les variables brutes d'un service (NaN conservés),
    # associées par nom : c'est la forme exacte que reçoit le service d'inférence avant nettoyage.
    names = feat.feature_names(service)
    ordered = sorted((r for r in rows if r["service"] == service), key=lambda r: r["timestamp"])
    return names, [{n: r.get(n, math.nan) for n in names} for r in ordered], [r["timestamp"] for r in ordered]


def training_fill_medians(service, raw_values):
    # Cette méthode permet de calculer, sur le SEUL normal d'apprentissage, les médianes servant à combler les
    # variables "median" manquantes (latence sans trafic). Le modèle appris retrouve ces mêmes médianes, que le
    # service utilise ensuite en production : apprentissage et inférence partagent donc le même prétraitement.
    medians = {}
    for spec in feat.FEATURES[service]:
        if spec.nan_fill != "median":
            continue
        column = np.array([row[spec.name] for row in raw_values], dtype=float)
        medians[spec.name] = float(np.nanmedian(column)) if np.isfinite(column).any() else 0.0
    return medians


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
        names, raw_values, timestamps = service_rows(rows, service)
        feature_order[service] = names
        phases = [phase_of(ts, service, labels) for ts in timestamps]
        train_raw = [v for v, p, ts in zip(raw_values, phases, timestamps) if p[0] == "normal" and ts <= train_until]
        fill = training_fill_medians(service, train_raw)
        normal_vectors[service] = [[cleaned[n] for n in names] for cleaned in
                                   (feat.clean_values(service, v, fill) for v in train_raw)]
        samples[service] = (names, raw_values, timestamps, phases)
        print(f"{service}: {len(timestamps)} échantillons, {len(train_raw)} normaux d'apprentissage", flush=True)

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
        for directory in (SERVICE_MODEL_DIR, ML_MODEL_DIR):
            # Pointeur explicite vers le modèle actif (lu par le service) : pas de choix par tri des noms de fichiers.
            (directory / "CURRENT").write_text(f"{model.version}.json\n", encoding="utf-8")
    model.validate(feat.expected_features())
    report = {"version": model.version, "threshold": model.threshold, "features": [str(Path(f).name) for f in args.features],
              **evaluate(model, samples, labels, train_until)}
    Path(args.report).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print_report(report)
    if saved:
        print("\nModèle écrit :", *saved, sep="\n  ")
    print(f"Rapport : {args.report}")
    return 0


def evaluate(model, samples, labels, train_until):
    # Cette méthode permet de calculer précision, rappel, faux positifs et délais (échantillon et alerte), en scorant
    # chaque échantillon exactement comme le service (clean_values + médianes du modèle, association par nom).
    threshold = model.threshold
    counts = {"tp": 0, "fn": 0, "fp_heldout": 0, "tn_heldout": 0, "fp_train": 0, "tn_train": 0}
    idle = {"n": 0, "fp": 0}
    windows = {}
    false_alerts = []
    max_normal_score = {"heldout": 0.0, "train": 0.0}
    for service, (names, raw_values, timestamps, phases) in samples.items():
        rate_name = next((n for n in ("req_rate", "req_rate_per_min") if n in names), None)
        cleaned_rows = [feat.clean_values(service, values, model.medians(service)) for values in raw_values]
        scores = [model.score_values(service, cleaned)["score"] for cleaned in cleaned_rows]
        run = 0
        for i, (ts, score, (phase, lab)) in enumerate(zip(timestamps, scores, phases)):
            flagged = score >= threshold
            contiguous = i > 0 and abs(timestamps[i] - timestamps[i - 1] - STEP) < 1
            run = (run + 1 if contiguous else 1) if flagged else 0
            alert = run >= ALERT_FOR_SAMPLES
            if phase == "attack":
                # Une entrée par FENÊTRE étiquetée (id de ligne), regroupées ensuite par scénario@service.
                w = windows.setdefault(lab["id"], {"scenario": lab["scenario"], "service": service, "start": lab["start"],
                                                    "end": lab["end"], "n": 0, "hits": 0, "first_hit": None,
                                                    "first_alert": None, "max_score": 0.0})
                w["n"] += 1
                w["hits"] += flagged
                w["max_score"] = max(w["max_score"], score)
                if flagged and w["first_hit"] is None:
                    w["first_hit"] = ts
                if alert and w["first_alert"] is None:
                    w["first_alert"] = ts
                counts["tp" if flagged else "fn"] += 1
            elif phase == "normal":
                split = "train" if ts <= train_until else "heldout"
                counts[("fp_" if flagged else "tn_") + split] += 1
                max_normal_score[split] = max(max_normal_score[split], score)
                if rate_name is not None and cleaned_rows[i][rate_name] <= 1e-9:
                    idle["n"] += 1
                    idle["fp"] += flagged
                if alert and run == ALERT_FOR_SAMPLES:
                    false_alerts.append({"service": service, "timestamp": ts, "split": split})

    scenarios = aggregate_windows(windows)
    tp, fn, fp = counts["tp"], counts["fn"], counts["fp_heldout"]
    heldout_n = counts["fp_heldout"] + counts["tn_heldout"]
    train_n = counts["fp_train"] + counts["tn_train"]
    alerted = sum(s["windows_alerted"] for s in scenarios.values())
    total_windows = sum(s["windows"] for s in scenarios.values())
    return {
        "counts": counts,
        "precision_heldout": round(tp / (tp + fp), 3) if (tp + fp) else None,
        "recall_samples": round(tp / (tp + fn), 3) if (tp + fn) else None,
        "false_positive_rate_heldout": round(fp / heldout_n, 4) if heldout_n else None,
        "false_positive_rate_train": round(counts["fp_train"] / train_n, 4) if train_n else None,
        "false_positive_rate_idle": round(idle["fp"] / idle["n"], 4) if idle["n"] else None,
        "max_normal_score": {k: round(v, 3) for k, v in max_normal_score.items()},
        "normal_samples": {"train": train_n, "heldout": heldout_n, "idle": idle["n"]},
        "windows_alerted": f"{alerted}/{total_windows}",
        "false_alerts": false_alerts,
        "scenarios": scenarios,
        "calibration": {s: {"t80": round(model.params[s]["t80"], 3), "beta": round(model.params[s]["beta"], 3),
                             "normal_severity_p99": round(model.params[s]["normal_severity_p99"], 3),
                             "normal_severity_max": round(model.params[s]["normal_severity_max"], 3)}
                        for s in model.params},
    }


def aggregate_windows(windows):
    # Cette méthode permet de résumer les fenêtres par scénario@service : rappel sur l'ensemble des échantillons,
    # nombre de fenêtres alertées, délais médian et maximal, et le détail de chaque fenêtre.
    grouped = {}
    for w in sorted(windows.values(), key=lambda w: w["start"]):
        grouped.setdefault(f'{w["scenario"]}@{w["service"]}', []).append(w)
    scenarios = {}
    for key, group in grouped.items():
        per_window = [{
            "start": w["start"], "duration_s": round(w["end"] - w["start"]), "samples": w["n"], "detected_samples": w["hits"],
            "recall": round(w["hits"] / w["n"], 3) if w["n"] else 0.0, "max_score": round(w["max_score"], 3),
            "first_score_above_threshold_s": round(w["first_hit"] - w["start"], 1) if w["first_hit"] else None,
            "alert_delay_s": round(w["first_alert"] - w["start"], 1) if w["first_alert"] else None,
        } for w in group]
        n = sum(w["n"] for w in group)
        hits = sum(w["hits"] for w in group)
        delays = [w["alert_delay_s"] for w in per_window if w["alert_delay_s"] is not None]
        firsts = [w["first_score_above_threshold_s"] for w in per_window if w["first_score_above_threshold_s"] is not None]
        scenarios[key] = {
            "service": group[0]["service"], "windows": len(group), "windows_alerted": len(delays),
            "samples": n, "detected_samples": hits, "recall": round(hits / n, 3) if n else 0.0,
            "max_score": max(w["max_score"] for w in per_window),
            "first_score_above_threshold_s": float(np.median(firsts)) if firsts else None,
            "alert_delay_s": float(np.median(delays)) if delays else None,
            "alert_delay_max_s": max(delays) if delays else None,
            "per_window": per_window,
        }
    return scenarios


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
    print(f"Fenêtres d'attaque ayant déclenché l'alerte (for 20s) : {report['windows_alerted']}")
    print(f"Fausses alertes simulées : {len(report['false_alerts'])} {report['false_alerts']}")
    print("Par scénario :")
    for name, s in report["scenarios"].items():
        print(f"  - {name:34s} fenêtres={s['windows_alerted']}/{s['windows']} rappel={s['recall']:<5} score max={s['max_score']:<6} "
              f"1er dépassement={_fmt_delay(s['first_score_above_threshold_s'])} alerte (médiane)={_fmt_delay(s['alert_delay_s'])}")


def _fmt_delay(value):
    # Cette méthode permet d'afficher un délai en secondes, ou « non détecté ».
    return "non détecté" if value is None else f"{value}s"


if __name__ == "__main__":
    sys.exit(main())
