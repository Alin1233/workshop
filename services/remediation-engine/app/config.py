"""Configuration du moteur de remédiation (variables d'environnement, valeurs par défaut adaptées à la démonstration)."""

from dataclasses import dataclass, field
from pathlib import Path

from resilience_common.settings import env


def _int(name: str, default: int) -> int:
    # Cette méthode permet de lire un entier depuis l'environnement avec une valeur par défaut.
    return int(env(name, str(default)))


def _float(name: str, default: float) -> float:
    # Cette méthode permet de lire un nombre décimal depuis l'environnement avec une valeur par défaut.
    return float(env(name, str(default)))


@dataclass
class Limits:
    """Garde-fous anti-boucle d'un type d'action : tentatives max par fenêtre glissante et délai entre deux actions."""

    max_attempts: int
    window_s: float
    cooldown_s: float


@dataclass
class Settings:
    service_name: str = "remediation-engine"
    compose_project: str = "resilience-alpha"
    docker_proxy_url: str = "http://docker-socket-proxy:2375"
    prometheus_url: str = "http://prometheus:9090"
    prometheus_user: str = "admin"
    prometheus_password_file: str | None = None
    loki_url: str = "http://loki:3100"
    payment_api_url: str = "http://payment-api:8000"
    witness_base_url: str = "http://waf:8080"
    webhook_token_file: str | None = None
    state_file: Path | None = None
    waf_blocklist_path: Path = Path("/waf-blocklist/blocked-ips.conf")
    waf_block_ttl_s: int = 300           # court : au labo, tous les clients partagent l'IP NAT 172.16.255.252
    bridge_dir: Path | None = Path("/bridge")
    restore_timeout_s: float = 300.0
    # Anti-boucle par type d'action (clé de garde = cible : service, IP, base)
    limits: dict[str, Limits] = field(default_factory=lambda: {
        "restart": Limits(3, 600, 20),
        "detector": Limits(1, 1800, 0),
        "block": Limits(3, 600, 0),
        "restore": Limits(1, 900, 0),
    })
    security_min_events: int = 10          # échecs minimum pour attribuer une attaque à une IP (Loki, 2 min)
    latency_persist_s: float = 180.0       # HighLatencyP95 : observer d'abord, n'agir que si l'alerte persiste
    dedup_window_s: float = 120.0          # une action réussie sur une cible couvre les alertes corrélées pendant ce délai
    coalert_window_s: float = 300.0        # co-alerte du frontal : rattachée à un incident d'API ouvert ou récent
    healthy_timeout_s: float = 90.0        # attente d'un conteneur « healthy » après une action
    dependent_grace_s: float = 30.0        # dépendance réparée : délai laissé au service pour se rétablir seul
    verify_timeout_s: float = 60.0         # attente des sondes / de l'intégrité pendant la vérification
    symptom_grace_s: float = 15.0          # chaîne saine : délai pour constater la disparition du symptôme
    poll_s: float = 2.0                    # période de scrutation (santé, sondes)
    retry_backoff_s: float = 10.0          # pause entre deux tentatives d'un même incident
    refire_grace_s: float = 90.0           # alerte répétée longtemps après le rétablissement : on revérifie
    stale_close_s: float = 1800.0          # incident rétabli dont l'alerte ne retombe jamais : clos après ce délai
    history_limit: int = 200               # incidents clos conservés dans le fichier d'état
    background_period_s: float = 15.0      # santé des dépendances, expiration des blocages, ménage

    @classmethod
    def from_env(cls) -> "Settings":
        # Cette méthode permet de construire la configuration à partir des variables d'environnement du conteneur.
        state_file = env("STATE_FILE", "")
        bridge = env("REMEDIATION_BRIDGE_PATH", "/bridge")
        settings = cls(
            service_name=env("SERVICE_NAME", "remediation-engine"),
            compose_project=env("COMPOSE_PROJECT", "resilience-alpha"),
            docker_proxy_url=env("DOCKER_PROXY_URL", "http://docker-socket-proxy:2375"),
            prometheus_url=env("PROMETHEUS_URL", "http://prometheus:9090"),
            prometheus_user=env("PROMETHEUS_USER", "admin"),
            prometheus_password_file=env("PROMETHEUS_PASSWORD_FILE", "") or None,
            loki_url=env("LOKI_URL", "http://loki:3100"),
            payment_api_url=env("PAYMENT_API_URL", "http://payment-api:8000"),
            witness_base_url=env("WITNESS_BASE_URL", "http://waf:8080"),
            webhook_token_file=env("WEBHOOK_TOKEN_FILE", "") or None,
            state_file=Path(state_file) if state_file else None,
            waf_blocklist_path=Path(env("WAF_BLOCKLIST_PATH", "/waf-blocklist/blocked-ips.conf")),
            waf_block_ttl_s=_int("WAF_BLOCK_TTL_SECONDS", 300),
            bridge_dir=Path(bridge) if bridge else None,
            restore_timeout_s=_float("RESTORE_TIMEOUT_SECONDS", 300),
            security_min_events=_int("SECURITY_MIN_EVENTS", 10),
            latency_persist_s=_float("LATENCY_PERSIST_SECONDS", 180),
        )
        settings.limits["restart"] = Limits(_int("RESTART_MAX_ATTEMPTS", 3), _float("RESTART_WINDOW_SECONDS", 600),
                                            _float("RESTART_COOLDOWN_SECONDS", 20))
        return settings
