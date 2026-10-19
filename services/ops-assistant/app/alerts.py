"""Lecture seule des alertes actives d'Alertmanager, pour contextualiser les réponses (jamais d'action)."""

import httpx

MAX_ALERTS = 10
MAX_FIELD = 200


def _clip(value: object) -> str:
    # Cette méthode permet de borner la taille d'un champ d'alerte avant de l'insérer dans le prompt.
    text = " ".join(str(value or "").split())
    return text[:MAX_FIELD]


def summarize(raw_alerts: list[dict]) -> list[dict]:
    # Cette méthode permet de ne garder que les champs utiles et non sensibles de chaque alerte active,
    # les plus graves en premier, avec un nombre d'alertes borné.
    alerts = []
    for item in raw_alerts:
        if not isinstance(item, dict):
            continue
        labels = item.get("labels") or {}
        annotations = item.get("annotations") or {}
        alerts.append({
            "name": _clip(labels.get("alertname")),
            "severity": _clip(labels.get("severity")),
            "domain": _clip(labels.get("domain")),
            "service": _clip(labels.get("service")),
            "summary": _clip(annotations.get("summary") or annotations.get("description")),
            "starts_at": _clip(item.get("startsAt")),
        })
    alerts.sort(key=lambda a: (a["severity"] != "critical", a["starts_at"]))
    return alerts[:MAX_ALERTS]


async def fetch_active_alerts(base_url: str, timeout: float = 2.0) -> list[dict]:
    # Cette méthode permet d'interroger l'API v2 d'Alertmanager en GET uniquement (alertes actives, non silencées) ;
    # une erreur réseau remonte à l'appelant, qui répond alors sans contexte d'alertes.
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(
            f"{base_url}/api/v2/alerts", params={"active": "true", "silenced": "false", "inhibited": "false"},
        )
        response.raise_for_status()
        payload = response.json()
    return summarize(payload if isinstance(payload, list) else [])


async def alertmanager_reachable(base_url: str, timeout: float = 2.0) -> bool:
    # Cette méthode permet de vérifier, pour /health, qu'Alertmanager répond sur sa sonde de vie.
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            return (await client.get(f"{base_url}/-/healthy")).status_code == 200
    except httpx.HTTPError:
        return False
