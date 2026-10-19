"""Modèle de détection : z-score robuste multivarié, calibré et sérialisé en JSON portable.

Approche (semi-supervisée) : on apprend le **comportement normal** service par service. Pour chaque
variable on retient la médiane et une échelle robuste (MAD × 1.4826). En production, l'écart d'une
observation à la normale s'exprime par un z-score robuste `z = (x - médiane) / échelle` ; on ne retient
que les écarts **positifs** (une hausse est suspecte), puis on agrège en une sévérité
`S = ||max(0, z)||₂` (distance de Mahalanobis à covariance diagonale, bornée à zéro vers le bas).

La sévérité est transformée en score 0..1 par `score = 1 - exp(-(S/β)²)`. β est calibré sur les données
normales pour que le **seuil 0,8 (`THRESHOLD`) tombe juste au-dessus du bruit normal** : `score(T80) = 0,8`, où T80 est
un quantile haut des sévérités normales (avec un plancher de sécurité). Une période creuse (S≈0) donne un
score ≈ 0, et une charge ordinaire reste < 0,8 par construction.

Les variables sont associées PAR NOM (jamais par position) et un modèle est validé au chargement contre les
variables du code (`validate`) : services ou noms différents ⇒ `ModelMismatch`, le service refuse de le charger.

Pourquoi ce choix plutôt qu'Isolation Forest : modèle minuscule, déterministe, interprétable (on sait quelle
variable porte l'anomalie), sérialisable en JSON lisible et versionnable, sans couplage de version entre
l'entraînement (Python 3.14) et le service (Python 3.12). Il n'exige aucune dépendance au moment du scoring.
"""

import json
import math
from pathlib import Path

# Seuil d'alerte : SOURCE UNIQUE. Le score est calibré pour que score(T80) = THRESHOLD ; la valeur est enregistrée
# dans le modèle, exposée par le service (gauge `anomaly_threshold`) et lue telle quelle par la règle Prometheus
# `AnomalyDetected` (`anomaly_score >= anomaly_threshold`). Comparaison toujours « ≥ », partout.
THRESHOLD = 0.8
# Facteur reliant β au seuil T80 tel que 1 - exp(-(T80/β)²) = THRESHOLD (√ln 5 pour 0,8).
_THRESHOLD_FACTOR = math.sqrt(-math.log(1.0 - THRESHOLD))


class ModelMismatch(ValueError):
    """Le modèle ne correspond pas aux variables du code (services ou noms de variables différents)."""


class RobustZScoreModel:
    """Modèle z-score robuste multivarié, un jeu de paramètres par service."""

    def __init__(self, version: str, params: dict, meta: dict | None = None):
        # Cette méthode permet de construire le modèle à partir des paramètres appris (médianes, échelles, β).
        self.version = version
        self.params = params  # {service: {"features": [...], "median": {...}, "scale": {...}, "beta": float, "t80": float}}
        self.meta = meta or {}

    @property
    def threshold(self) -> float:
        # Cette méthode permet de connaître le seuil d'alerte pour lequel le modèle a été calibré.
        return float(self.meta.get("threshold", THRESHOLD))

    def validate(self, expected: dict[str, list[str]]) -> None:
        # Cette méthode permet de refuser un modèle qui ne correspond pas aux variables calculées par le code :
        # mêmes services, mêmes noms de variables, paramètres complets. Sinon un score serait calculé en silence
        # sur de mauvaises variables (ex. modèle d'une ancienne version).
        if set(self.params) != set(expected):
            raise ModelMismatch(f"services du modèle {sorted(self.params)} ≠ services du code {sorted(expected)}")
        for service, names in expected.items():
            sp = self.params[service]
            if set(sp.get("features", [])) != set(names):
                raise ModelMismatch(f"{service} : variables du modèle {sorted(sp.get('features', []))} ≠ code {sorted(names)}")
            for name in names:
                if name not in sp.get("median", {}) or name not in sp.get("scale", {}):
                    raise ModelMismatch(f"{service} : médiane ou échelle manquante pour {name}")
            if not sp.get("beta", 0) > 0:
                raise ModelMismatch(f"{service} : β absent ou nul")
        if not 0 < self.threshold < 1:
            raise ModelMismatch(f"seuil invalide : {self.threshold}")

    # ---------------------------------------------------------------- inférence (pur Python, sans dépendance)
    def medians(self, service: str) -> dict[str, float]:
        # Cette méthode permet d'exposer les médianes apprises (utilisées pour remplir les variables manquantes).
        return self.params[service]["median"]

    def score_values(self, service: str, values: dict[str, float]) -> dict:
        # Cette méthode permet de scorer un service à partir de ses variables nettoyées, associées PAR NOM.
        # Une variable absente de `values` ne contribue pas : la sévérité obtenue est alors un MINORANT de la sévérité
        # complète (toutes les contributions sont ≥ 0), ce qui permet un scoring partiel honnête (cf. main.py).
        sp = self.params[service]
        contributions: dict[str, float] = {}
        total = 0.0
        for name in sp["features"]:
            if name not in values:
                continue
            scale = sp["scale"][name]
            z = (values[name] - sp["median"][name]) / scale if scale > 0 else 0.0
            positive = z if z > 0 else 0.0
            contributions[name] = positive
            total += positive * positive
        severity = math.sqrt(total)
        beta = sp["beta"]
        score = 1.0 - math.exp(-((severity / beta) ** 2)) if beta > 0 else 0.0
        dominant = max(contributions, key=contributions.get) if contributions else None
        return {
            "score": round(score, 4),
            "severity": round(severity, 4),
            "dominant_feature": dominant,
            "contributions": contributions,
        }

    # ---------------------------------------------------------------- persistance
    def to_dict(self) -> dict:
        # Cette méthode permet de représenter le modèle comme un dictionnaire JSON-sérialisable.
        return {"version": self.version, "params": self.params, "meta": self.meta}

    def save(self, path: str | Path) -> Path:
        # Cette méthode permet d'écrire le modèle sur disque au format JSON (déterministe, versionnable).
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path, expected: dict[str, list[str]] | None = None) -> "RobustZScoreModel":
        # Cette méthode permet de recharger un modèle depuis son fichier JSON et, si `expected` est fourni,
        # de le valider contre les variables du code (ModelMismatch sinon).
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        model = cls(data["version"], data["params"], data.get("meta", {}))
        if expected is not None:
            model.validate(expected)
        return model

    @classmethod
    def from_dict(cls, data: dict) -> "RobustZScoreModel":
        # Cette méthode permet de reconstruire le modèle depuis un dictionnaire déjà chargé.
        return cls(data["version"], data["params"], data.get("meta", {}))


def fit(
    version: str,
    normal_vectors: dict[str, list[list[float]]],
    feature_order: dict[str, list[str]],
    scale_floor: dict[str, float] | None = None,
    t80_quantile: float = 0.999,
    t80_margin: float = 1.15,
    t80_floor: float = 3.5,
    meta: dict | None = None,
) -> RobustZScoreModel:
    # Cette méthode permet d'apprendre le modèle à partir des vecteurs de variables du trafic NORMAL (par service).
    # numpy n'est importé qu'ici : le scoring en production reste en Python pur, sans dépendance.
    import numpy as np

    params: dict[str, dict] = {}
    for service, names in feature_order.items():
        samples = np.asarray(normal_vectors.get(service, []), dtype=float)
        if samples.ndim != 2 or samples.shape[0] == 0:
            raise ValueError(f"Aucune observation normale pour le service {service}")
        median = np.median(samples, axis=0)
        deviation = np.abs(samples - median)
        mad = np.median(deviation, axis=0)
        robust_scale = 1.4826 * mad
        # Échelle « consciente de la queue » : le 99e centile des écarts normaux vaut ~3 unités. Une variable
        # au bruit normal épisodique (ex. sessions expirées → quelques jetons invalides) n'écrase donc pas le
        # seuil du service entier, et une hausse légitime de charge reste dans la normale.
        tail_scale = np.quantile(deviation, 0.99, axis=0) / 3.0
        std = samples.std(axis=0)
        floors = (scale_floor or {})
        scale = np.empty_like(robust_scale)
        for i, name in enumerate(names):
            # Chaîne de repli : max(MAD robuste, queue/3), sinon écart-type, sinon un plancher absolu propre à la
            # variable (évite une division par zéro quand la variable est quasi constante dans le normal).
            candidate = max(robust_scale[i], tail_scale[i])
            if candidate <= 0:
                candidate = std[i]
            floor = floors.get(name, 1e-6)
            scale[i] = max(candidate, floor)

        # Sévérités sur le normal (écarts positifs uniquement) pour calibrer β.
        z = (samples - median) / scale
        positive = np.clip(z, 0.0, None)
        severities = np.sqrt((positive ** 2).sum(axis=1))
        t80 = max(float(np.quantile(severities, t80_quantile)) * t80_margin, t80_floor)
        beta = t80 / _THRESHOLD_FACTOR

        params[service] = {
            "features": list(names),
            "median": {name: float(median[i]) for i, name in enumerate(names)},
            "scale": {name: float(scale[i]) for i, name in enumerate(names)},
            "beta": float(beta),
            "t80": float(t80),
            "normal_samples": int(samples.shape[0]),
            "normal_severity_p50": float(np.quantile(severities, 0.5)),
            "normal_severity_p99": float(np.quantile(severities, 0.99)),
            "normal_severity_max": float(severities.max()),
        }
    return RobustZScoreModel(version, params, {**(meta or {}), "threshold": THRESHOLD})
