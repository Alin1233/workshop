"""Actions du moteur de remédiation : Docker (via docker-socket-proxy), blocage d'IP au WAF, restauration de la base.

Les modules frères s'importent entre eux en relatif (`from . import ActionError`, `from .docker_proxy import DockerProxy`) :
le paquet `app` est chargé sous un alias dans les tests unitaires (scripts/service_loader.py), un import absolu
`app.actions…` y viserait un autre service.
"""


class ActionError(RuntimeError):
    """Une action de remédiation a échoué ou a été refusée (proxy Docker, liste d'exclusion, pont de restauration…)."""
