"""Modèle de détection : z-score robuste multivarié, calibré et sérialisé en JSON portable.

Approche (semi-supervisée) : on apprend le **comportement normal** service par service. Pour chaque
variable on retient la médiane et une échelle robuste (MAD × 1.4826). En production, l'écart d'une
observation à la normale s'exprime par un z-score robuste `z = (x - médiane) / échelle` ; on ne retient
que les écarts **positifs** (une hausse est suspecte), puis on agrège en une sévérité
`S = ||max(0, z)||₂` (distance de Mahalanobis à covariance diagonale, bornée à zéro vers le bas).

La sévérité est transformée en score 0..1 par `score = 1 - exp(-(S/β)²)`. β est calibré sur les données
normales pour que le **seuil 0,8 tombe juste au-dessus du bruit normal** : `score(T80) = 0,8`, où T80 est
un quantile haut des sévérités normales (avec un plancher de sécurité). Une période creuse (S≈0) donne un
score ≈ 0, et une charge ordinaire reste < 0,8 par construction.

Pourquoi ce choix plutôt qu'Isolation Forest : modèle minuscule, déterministe, interprétable (on sait quelle
variable porte l'anomalie), sérialisable en JSON lisible et versionnable, sans couplage de version entre
l'entraînement (Python 3.14) et le service (Python 3.12). Il n'exige aucune dépendance au moment du scoring.
"""

import json
import math
from pathlib import Path

# sqrt(ln 5) : facteur reliant β au seuil T80 tel que 1 - exp(-(T80/β)²) = 0,8.
_SQRT_LN5 = math.sqrt(math.log(5.0))


class RobustZScoreModel:
    """Modèle z-score robuste multivarié, un jeu de paramètres par service."""

    def __init__(self, version: str, params: dict, meta: dict | None = None):
        # Cette méthode permet de construire le modèle à partir des paramètres appris (médianes, échelles, β).
        self.version = version
        self.params = params  # {service: {"features": [...], "median": {...}, "scale": {...}, "beta": float, "t80": float}}
        self.meta = meta or {}

    # ---------------------------------------------------------------- inférence (pur Python, sans dépendance)
    def medians(self, service: str) -> dict[str, float]:
        # Cette méthode permet d'exposer les médianes apprises (utilisées pour remplir les variables manquantes).
        return self.params[service]["median"]

    def score_vector(self, service: str, vector: list[float]) -> dict:
        # Cette méthode permet de scorer un vecteur de variables déjà nettoyé et de renvoyer le détail du calcul.
        sp = self.params[service]
        names = sp["features"]
        contributions: dict[str, float] = {}
        total = 0.0
        for name, value in zip(names, vector):
            scale = sp["scale"][name]
            z = (value - sp["median"][name]) / scale if scale > 0 else 0.0
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
    def load(cls, path: str | Path) -> "RobustZScoreModel":
        # Cette méthode permet de recharger un modèle depuis son fichier JSON.
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data["version"], data["params"], data.get("meta", {}))

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
        beta = t80 / _SQRT_LN5

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
    return RobustZScoreModel(version, params, meta)
