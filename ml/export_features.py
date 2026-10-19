"""Export des séries temporelles de variables depuis Prometheus/Loki vers un CSV sous ml/data/.

Utilise exactement le même code de variables que le service d'inférence (services/anomaly-detector/app/features.py)
afin que le jeu d'entraînement et le scoring en production soient cohérents (aucune logique dupliquée).

Usage (depuis le PC Hôte) :
    python ml/export_features.py --start -1800 --step 10 \
        --prometheus http://127.0.0.1:9090 --loki http://127.0.0.1:3100 --out ml/data/features.csv

Prometheus et loki-proxy exigent admin / mot de passe : lus par défaut dans secrets/prometheus_password et
secrets/loki_password (options --prometheus-password-file / --loki-password-file).

`--start`/`--end` acceptent un epoch absolu, un décalage relatif (ex. -1800 = il y a 30 min) ou vide (= maintenant).
"""

import argparse
import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "services" / "anomaly-detector"))
from app import features  # noqa: E402
from app.promclient import LokiClient, PrometheusClient  # noqa: E402


SECRETS_DIR = Path(__file__).resolve().parent.parent / "secrets"


def read_password(path: str) -> str | None:
    # Cette méthode permet de lire un mot de passe dans un fichier de secrets, ou rien si le fichier est absent.
    file = Path(path)
    return file.read_text(encoding="utf-8").strip() if file.is_file() else None


def parse_time(value, default):
    # Cette méthode permet d'interpréter un horodatage : absolu, relatif (négatif = passé), ou défaut si vide.
    if value is None or value == "":
        return default
    number = float(value)
    return number if number > 1_000_000_000 else time.time() + number


def main():
    # Cette méthode permet d'exporter la matrice des variables (une ligne par timestamp et par service) en CSV.
    parser = argparse.ArgumentParser(description="Exporte les variables du détecteur depuis Prometheus/Loki.")
    parser.add_argument("--prometheus", default="http://127.0.0.1:9090")
    parser.add_argument("--loki", default="http://127.0.0.1:3100")
    parser.add_argument("--prometheus-password-file", default=str(SECRETS_DIR / "prometheus_password"))
    parser.add_argument("--loki-password-file", default=str(SECRETS_DIR / "loki_password"))
    parser.add_argument("--start", default="-1800")
    parser.add_argument("--end", default="")
    parser.add_argument("--step", type=float, default=10.0)
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent / "data" / "features.csv"))
    args = parser.parse_args()

    end = parse_time(args.end, time.time())
    start = parse_time(args.start, end - 1800)
    prom = PrometheusClient(args.prometheus, timeout=15, password=read_password(args.prometheus_password_file))
    loki = LokiClient(args.loki, timeout=15, password=read_password(args.loki_password_file))

    print(f"Export {args.step:g}s de {start:.0f} à {end:.0f} ({(end - start) / 60:.1f} min)…", flush=True)
    rows = features.extract_range(prom, loki, start, end, args.step)

    all_columns = ["timestamp", "service"]
    for service in features.SERVICES:
        for name in features.feature_names(service):
            if name not in all_columns:
                all_columns.append(name)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=all_columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)} lignes écrites dans {out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
