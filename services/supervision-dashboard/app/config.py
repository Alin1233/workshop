"""Configuration du back-for-front, lue une fois au démarrage (les secrets, eux, sont relus à chaque usage)."""

from dataclasses import dataclass
from pathlib import Path

from resilience_common.settings import env


def read_secret(path: str | None) -> str:
    # Cette méthode permet de relire un secret monté en fichier (rotation sans redémarrage) ; vide s'il est absent.
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


@dataclass(frozen=True)
class Settings:
    service: str = "supervision-dashboard"
    log_level: str = "INFO"
    # Sources lues sur le réseau interne obs (jamais par le navigateur)
    engine_url: str = "http://remediation-engine:8000"
    prometheus_url: str = "http://prometheus:9090"
    prometheus_user: str = "admin"
    prometheus_password_file: str | None = None
    alertmanager_url: str = "http://alertmanager:9093"
    alertmanager_user: str = "admin"
    alertmanager_password_file: str | None = None
    loki_url: str = "http://loki:3100"
    # Accès à l'interface et à l'API : compte « admin », mot de passe dans le secret supervision_password
    auth_user: str = "admin"
    auth_password_file: str | None = None
    static_dir: str = "/app/static"
    # Délais courts : un panneau en panne ne doit jamais bloquer les autres plus de quelques secondes
    timeout_s: float = 2.0
    connect_timeout_s: float = 1.0
    # Cache serveur : plusieurs navigateurs ouverts ne multiplient pas les requêtes vers les sources
    cache_ttl_s: float = 1.5
    # Durée d'affichage de « Service rétabli » après la clôture d'un incident
    restored_window_s: float = 180.0
    # Fenêtre du fil d'événements (Loki)
    events_window_s: int = 1800

    @classmethod
    def from_env(cls) -> "Settings":
        # Cette méthode permet de construire la configuration depuis l'environnement du conteneur.
        d = cls()
        return cls(
            service=env("SERVICE_NAME", d.service),
            log_level=env("LOG_LEVEL", d.log_level),
            engine_url=env("ENGINE_URL", d.engine_url).rstrip("/"),
            prometheus_url=env("PROMETHEUS_URL", d.prometheus_url).rstrip("/"),
            prometheus_user=env("PROMETHEUS_USER", d.prometheus_user),
            prometheus_password_file=env("PROMETHEUS_PASSWORD_FILE", "") or None,
            alertmanager_url=env("ALERTMANAGER_URL", d.alertmanager_url).rstrip("/"),
            alertmanager_user=env("ALERTMANAGER_USER", d.alertmanager_user),
            alertmanager_password_file=env("ALERTMANAGER_PASSWORD_FILE", "") or None,
            loki_url=env("LOKI_URL", d.loki_url).rstrip("/"),
            auth_user=env("SUPERVISION_USER", d.auth_user),
            auth_password_file=env("SUPERVISION_PASSWORD_FILE", "") or None,
            static_dir=env("STATIC_DIR", d.static_dir),
            timeout_s=float(env("SOURCE_TIMEOUT_SECONDS", str(d.timeout_s))),
            cache_ttl_s=float(env("CACHE_TTL_SECONDS", str(d.cache_ttl_s))),
            restored_window_s=float(env("RESTORED_WINDOW_SECONDS", str(d.restored_window_s))),
            events_window_s=int(env("EVENTS_WINDOW_SECONDS", str(d.events_window_s))),
        )
