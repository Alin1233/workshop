"""Tests unitaires du blocage d'IP au WAF (services/remediation-engine/app/actions/waf_block.py).

Sans Docker ni WAF : un faux DockerProxy enregistre les SIGHUP et « charge » le fichier rendu au moment du signal,
comme nginx ; le faux contrôle interne du WAF (port 8081) répond d'après cette configuration chargée. On couvre la
validation des IP, la liste d'exclusion, l'écriture atomique et le format rendu, la persistance, l'expiration, l'absence
de rechargement inutile, la vérification, la reprise après incident et la concurrence. Valeurs de test générées.
"""

import importlib
import importlib.util
import ipaddress
import json
import os
import stat
import sys
import threading
import uuid
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
ACTIONS_DIR = REPO / "services" / "remediation-engine" / "app" / "actions"
_ALIAS = "remediation_actions_waf_tests"


def _load_actions():
    # Cette méthode permet de charger le paquet actions du moteur sous un alias propre aux tests : d'autres tests
    # importent un paquet `app` différent (détecteur d'anomalies), on ne passe donc pas par le nom `app`.
    if _ALIAS not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            _ALIAS, ACTIONS_DIR / "__init__.py", submodule_search_locations=[str(ACTIONS_DIR)])
        package = importlib.util.module_from_spec(spec)
        sys.modules[_ALIAS] = package
        spec.loader.exec_module(package)
    return sys.modules[_ALIAS], importlib.import_module(f"{_ALIAS}.waf_block")


actions, waf = _load_actions()
ActionError = actions.ActionError

# Adresses de documentation (RFC 5737 / RFC 3849) : jamais d'adresse réelle
ATTACKER = "203.0.113.7"
OTHER = "198.51.100.23"
ATTACKER_V6 = "2001:db8::7"
LAB_NAT = "172.16.255.252"


class FakeClock:
    """Horloge réglable (secondes epoch)."""

    def __init__(self, now: float = 1_800_000_000.0):
        # Cette méthode permet de fixer l'instant de départ.
        self.now = now

    def __call__(self) -> float:
        # Cette méthode permet de lire l'instant courant.
        return self.now


class FakeDocker:
    """Faux DockerProxy : SIGHUP = nginx relit le fichier rendu ; santé et inspect paramétrables."""

    def __init__(self, path: Path, health: str = "healthy", fail_signal: bool = False, inspect_info: dict | None = None):
        # Cette méthode permet de configurer le comportement du faux proxy.
        self.path = path
        self.health_value = health
        self.fail_signal = fail_signal
        self.inspect_info = inspect_info
        self.signals: list[tuple[str, str]] = []
        self.loaded: set[str] = set()
        self.lock = threading.Lock()

    def signal(self, service: str, sig: str) -> None:
        # Cette méthode permet de simuler `docker kill -s HUP waf` : la configuration chargée devient le fichier courant.
        if self.fail_signal:
            raise ActionError("docker-socket-proxy injoignable (simulé)")
        with self.lock:
            self.signals.append((service, sig))
            self.loaded = waf.parse_rendered(self.path.read_text()) if self.path.exists() else set()

    def health(self, service: str) -> str:
        # Cette méthode permet de renvoyer l'état de santé simulé du WAF.
        return self.health_value

    def fetch(self, url: str) -> dict:
        # Cette méthode permet de simuler GET http://waf:8081/remediation/blocklist?ip=... sur la config chargée.
        ip = url.split("ip=", 1)[1].replace("%3A", ":")
        return {"blocked": 1 if ip in self.loaded else 0}


@pytest.fixture
def clock():
    # Cette méthode permet de partager une horloge réglable.
    return FakeClock()


@pytest.fixture
def volume(tmp_path):
    # Cette méthode permet de simuler le volume partagé waf-blocklist.
    path = tmp_path / "waf-blocklist"
    path.mkdir()
    return path


@pytest.fixture
def docker(volume):
    # Cette méthode permet d'obtenir un faux proxy Docker branché sur le fichier rendu du volume.
    return FakeDocker(volume / "blocked-ips.conf")


def make(volume, docker, clock, **kwargs) -> "waf.WafBlocklist":
    # Cette méthode permet de construire une liste de blocage isolée (pas de découverte réseau sauf demande).
    kwargs.setdefault("discover", False)
    kwargs.setdefault("verify_timeout_s", 0)
    return waf.WafBlocklist(volume / "blocked-ips.conf", docker, "waf", clock=clock, fetch=docker.fetch,
                            sleep=lambda _s: None, **kwargs)


def incident() -> str:
    # Cette méthode permet de générer un identifiant d'incident.
    return uuid.uuid4().hex


# ─────────────────────────────── Validation et liste d'exclusion ───────────────────────────────

@pytest.mark.parametrize("raw, expected", [
    (ATTACKER, ATTACKER), (f"  {ATTACKER}\n", ATTACKER), ("2001:DB8:0:0::7", ATTACKER_V6),
    (f"::ffff:{ATTACKER}", ATTACKER), (LAB_NAT, LAB_NAT),
])
def test_normalize_ip_canonical_form(raw, expected):
    assert str(waf.normalize_ip(raw)) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", None, 42, "not-an-ip", "203.0.113.300", "203.0.113.0/24", "fe80::1%eth0", "0.0.0.0", "::",
    "224.0.0.1", "255.255.255.255", "240.0.0.1", '203.0.113.7" 1; include /etc/hosts', "203.0.113.7\n198.51.100.1",
])
def test_normalize_ip_rejects_invalid(raw):
    with pytest.raises(ActionError):
        waf.normalize_ip(raw)


def test_block_rejects_invalid_ip_without_touching_files(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    with pytest.raises(ActionError):
        blocklist.block("203.0.113.0/24", 60, "test", incident())
    assert not (volume / "blocked-ips.conf").exists() and docker.signals == []


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.8.9.10", "::1", "172.31.250.2", "172.31.255.40", "172.31.248.1"])
def test_default_allowlist_is_never_blocked(volume, docker, clock, ip):
    blocklist = make(volume, docker, clock)
    with pytest.raises(ActionError, match="exclu"):
        blocklist.block(ip, 60, "test", incident())
    assert docker.signals == [] and blocklist.active() == []


def test_lab_nat_ip_is_not_silently_allowlisted(volume, docker, clock):
    # Au labo tout le monde arrive par 172.16.255.252 : la bloquer coupe tous les clients (documenté), mais on ne la
    # protège pas en silence — et 172.16.0.0/12 n'est jamais exclu en bloc.
    blocklist = make(volume, docker, clock)
    assert blocklist.allowlisted(LAB_NAT) is None
    assert all(n.prefixlen >= 16 for n in blocklist.allowlist_networks() if n.version == 4 and not n.is_loopback)
    blocklist.block(LAB_NAT, 60, "test", incident())
    assert [e.ip for e in blocklist.active()] == [LAB_NAT]


def test_allowlist_from_env_extends_defaults():
    env = {"WAF_BLOCK_ALLOWLIST": "198.51.100.0/24, 2001:db8:1::/48  10.9.8.7"}
    networks = waf.allowlist_from_env(env)
    assert networks[: len(waf.DEFAULT_ALLOWLIST)] == list(waf.DEFAULT_ALLOWLIST)
    assert {"198.51.100.0/24", "2001:db8:1::/48", "10.9.8.7"} <= set(networks)
    assert waf.allowlist_from_env({}) == list(waf.DEFAULT_ALLOWLIST)
    with pytest.raises(ActionError):
        waf.allowlist_from_env({"WAF_BLOCK_ALLOWLIST": "198.51.100.0/33"})


def test_configured_allowlist_keeps_loopback(volume, docker, clock):
    blocklist = make(volume, docker, clock, allowlist=["198.51.100.0/24"])
    for ip in ("127.0.0.1", "198.51.100.23"):
        with pytest.raises(ActionError):
            blocklist.block(ip, 60, "test", incident())
    blocklist.block(ATTACKER, 60, "test", incident())


def test_discovered_networks_are_allowlisted(volume, clock, tmp_path):
    # Réseaux du moteur (/proc/net/route) et du WAF (inspect via le proxy : passerelle edge comprise).
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0100180A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"   # défaut : ignoré
        "eth0\t0000180A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"   # 10.24.0.0/16 (réseau obs du moteur)
        "eth1\t000000C0\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n")  # 192.0.0.0/8 : trop large, ignoré
    info = {"NetworkSettings": {"Networks": {
        "resilience-alpha_edge": {"Gateway": "10.25.0.1", "IPAddress": "10.25.0.2", "IPPrefixLen": 16},
        "resilience-alpha_dmz": {"Gateway": "172.31.250.1", "IPAddress": "172.31.250.3", "IPPrefixLen": 24},
    }}}
    docker = FakeDocker(volume / "blocked-ips.conf", inspect_info=info)
    docker.inspect = lambda service: info
    blocklist = make(volume, docker, clock, discover=True, route_file=route)
    assert blocklist.allowlisted("10.24.3.4") == "10.24.0.0/16"
    assert blocklist.allowlisted("10.25.0.1") == "10.25.0.1/32"
    assert blocklist.allowlisted("10.25.0.7") is None                  # autre conteneur d'edge : bloquable
    assert blocklist.allowlisted("192.1.2.3") is None
    with pytest.raises(ActionError):
        blocklist.block("10.25.0.1", 60, "tunnel SSH vu par le WAF", incident())
    blocklist.block(ATTACKER, 60, "test", incident())


def test_discovery_without_inspect_is_tolerated(volume, docker, clock, tmp_path):
    route = tmp_path / "route"
    route.write_text("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n")
    blocklist = make(volume, docker, clock, discover=True, route_file=route)
    assert [str(n) for n in blocklist.allowlist_networks()] == list(waf.DEFAULT_ALLOWLIST)
    blocklist.block(ATTACKER, 60, "test", incident())


def test_block_refused_while_waf_networks_unknown(volume, clock, tmp_path):
    # Proxy Docker injoignable pendant la découverte : on ne bloque pas à l'aveugle (passerelle edge inconnue).
    docker = FakeDocker(volume / "blocked-ips.conf")
    attempts = []

    def flaky_inspect(service):
        # Cette méthode permet de simuler un proxy injoignable au premier appel puis rétabli.
        attempts.append(service)
        if len(attempts) == 1:
            raise ActionError("docker-socket-proxy injoignable (simulé)")
        return {"NetworkSettings": {"Networks": {"edge": {"Gateway": "10.25.0.1"}}}}

    docker.inspect = flaky_inspect
    blocklist = make(volume, docker, clock, discover=True, route_file=tmp_path / "absent")
    with pytest.raises(ActionError, match="non découverts"):
        blocklist.block(ATTACKER, 60, "test", incident())
    assert docker.signals == []
    blocklist.block(ATTACKER, 60, "test", incident())
    with pytest.raises(ActionError, match="exclu"):
        blocklist.block("10.25.0.1", 60, "test", incident())
    assert attempts == ["waf", "waf"]


def test_container_networks_keeps_gateways_only():
    info = {"NetworkSettings": {"Networks": {
        "edge": {"Gateway": "172.20.0.1", "IPAddress": "172.20.0.5", "IPPrefixLen": 16},
        "b": {"Gateway": "", "IPAddress": "bad", "IPPrefixLen": 24, "IPv6Gateway": "fd00::1"},
        "c": "garbage", "d": {"Gateway": "not-an-ip"},
    }}}
    assert [str(n) for n in waf.container_networks(info)] == ["172.20.0.1/32", "fd00::1/128"]
    assert waf.container_networks({}) == []


def test_inspect_through_proxy_public_api(volume, clock, monkeypatch):
    # DockerProxy sans méthode inspect : GET {base_url}/containers/{id}/json avec ses seuls attributs publics.
    info = {"NetworkSettings": {"Networks": {"edge": {"Gateway": "10.25.0.1"}}}}
    seen = []

    class Response:
        def __init__(self, url):
            seen.append(url)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps(info).encode()

    docker = FakeDocker(volume / "blocked-ips.conf")
    docker.base_url, docker.timeout = "http://docker-socket-proxy:2375/", 3.0
    docker.container_id = lambda service: f"id-{service}"
    monkeypatch.setattr(waf.urllib.request, "urlopen", lambda url, timeout: Response(url))
    blocklist = make(volume, docker, clock, discover=True, route_file=volume / "absent")
    assert blocklist.allowlisted("10.25.0.1") == "10.25.0.1/32"
    assert seen == ["http://docker-socket-proxy:2375/containers/id-waf/json"]
    blocklist.block("10.25.0.9", 60, "client distant (même réseau, autre IP)", incident())


# ─────────────────────────────── Écriture, format, rechargement ───────────────────────────────

def test_block_renders_atomically_and_reloads(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    entry = blocklist.block(ATTACKER, 300, "AuthBruteForce", incident())
    assert entry.ip == ATTACKER and entry.expires_at == clock.now + 300
    content = (volume / "blocked-ips.conf").read_text()
    lines = [line for line in content.splitlines() if not line.startswith("#")]
    assert lines == [f'"{ATTACKER}" 1;']
    assert docker.signals == [("waf", "HUP")]
    assert stat.S_IMODE((volume / "blocked-ips.conf").stat().st_mode) == 0o644      # lisible par nginx (uid 101)
    assert stat.S_IMODE((volume / "blocked-ips.json").stat().st_mode) == 0o600
    assert not [p for p in volume.iterdir() if p.name.endswith(".tmp")]


def test_render_is_sorted_and_free_of_user_text(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    hostile = 'x";\n include /etc/hosts; }\n# '
    for ip in (OTHER, ATTACKER_V6, ATTACKER):
        blocklist.block(ip, 60, hostile, hostile)
    content = (volume / "blocked-ips.conf").read_text()
    entries = [line for line in content.splitlines() if not line.startswith("#")]
    assert entries == [f'"{OTHER}" 1;', f'"{ATTACKER}" 1;', f'"{ATTACKER_V6}" 1;']
    assert "/etc/hosts" not in content
    state = json.loads((volume / "blocked-ips.json").read_text())
    assert {e["reason"] for e in state["entries"]} == {hostile}


def test_failed_write_keeps_previous_file(volume, docker, clock, monkeypatch):
    blocklist = make(volume, docker, clock)
    blocklist.block(ATTACKER, 60, "test", incident())
    before = (volume / "blocked-ips.conf").read_text()

    def broken_replace(src, dst):
        # Cette méthode permet de simuler un échec au moment du renommage (disque plein, droits).
        raise OSError("simulé")

    monkeypatch.setattr(waf.os, "replace", broken_replace)
    with pytest.raises(ActionError):
        blocklist.block(OTHER, 60, "test", incident())
    monkeypatch.undo()
    assert (volume / "blocked-ips.conf").read_text() == before
    assert not [p for p in volume.iterdir() if p.name.endswith(".tmp")]


def test_reblocking_extends_without_reload(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    blocklist.block(ATTACKER, 300, "first", incident())
    clock.now += 100
    second = incident()
    entry = blocklist.block(ATTACKER, 600, "second", second)
    assert entry.expires_at == clock.now + 600 and entry.incident_id == second
    shorter = blocklist.block(ATTACKER, 10, "third", incident())
    assert shorter.expires_at == entry.expires_at                       # jamais raccourci
    assert docker.signals == [("waf", "HUP")]                           # liste inchangée : un seul rechargement


@pytest.mark.parametrize("ttl", [0, -5, waf.MAX_TTL_S + 1, "60", None, True])
def test_invalid_ttl_is_refused(volume, docker, clock, ttl):
    with pytest.raises(ActionError):
        make(volume, docker, clock).block(ATTACKER, ttl, "test", incident())


def test_max_entries(volume, docker, clock):
    blocklist = make(volume, docker, clock, max_entries=2)
    blocklist.block(ATTACKER, 60, "test", incident())
    blocklist.block(OTHER, 60, "test", incident())
    blocklist.block(OTHER, 60, "test", incident())                       # déjà présente : acceptée
    with pytest.raises(ActionError, match="pleine"):
        blocklist.block(ATTACKER_V6, 60, "test", incident())


def test_ttl_from_env():
    assert waf.ttl_from_env({}) == waf.DEFAULT_TTL_S == 300
    assert waf.ttl_from_env({"WAF_BLOCK_TTL_SECONDS": "120"}) == 120
    for bad in ("0", "abc", str(waf.MAX_TTL_S + 1)):
        with pytest.raises(ActionError):
            waf.ttl_from_env({"WAF_BLOCK_TTL_SECONDS": bad})


def test_unblock(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    blocklist.block(ATTACKER, 60, "test", incident())
    blocklist.block(OTHER, 60, "test", incident())
    assert blocklist.unblock(f" {ATTACKER} ") is True
    assert [e.ip for e in blocklist.active()] == [OTHER]
    assert len(docker.signals) == 3 and docker.loaded == {OTHER}
    assert blocklist.unblock(ATTACKER) is False
    assert len(docker.signals) == 3
    with pytest.raises(ActionError):
        blocklist.unblock("garbage")


# ─────────────────────────────── Persistance et expiration ───────────────────────────────

def test_state_survives_engine_restart(volume, docker, clock):
    first = make(volume, docker, clock)
    inc = incident()
    first.block(ATTACKER, 300, "AuthBruteForce", inc)
    first.block(ATTACKER_V6, 900, "WafAttackBlocked", incident())
    restarted = make(volume, docker, clock)
    active = restarted.active()
    assert [e.ip for e in active] == [ATTACKER, ATTACKER_V6]
    assert active[0] == waf.BlockEntry(ATTACKER, clock.now + 300, "AuthBruteForce", inc)
    assert restarted.expire() == [] and len(docker.signals) == 2       # rien à faire au redémarrage
    assert restarted.verify(ATTACKER) is True


def test_expire_drops_due_entries_and_reloads_once(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    blocklist.block(ATTACKER, 60, "test", incident())
    blocklist.block(OTHER, 600, "test", incident())
    assert blocklist.expire(clock.now + 59) == []
    assert len(docker.signals) == 2
    clock.now += 61
    assert blocklist.expire() == [ATTACKER]
    assert len(docker.signals) == 3 and docker.loaded == {OTHER}
    mtime = (volume / "blocked-ips.conf").stat().st_mtime_ns
    assert blocklist.expire() == []
    assert len(docker.signals) == 3                                     # rien n'a changé : ni réécriture ni rechargement
    assert (volume / "blocked-ips.conf").stat().st_mtime_ns == mtime
    assert [e.ip for e in blocklist.active()] == [OTHER]


def test_active_hides_due_entries_before_expire(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    blocklist.block(ATTACKER, 60, "test", incident())
    clock.now += 60
    assert blocklist.active() == []


def test_first_expire_creates_empty_default_without_reload(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    assert blocklist.expire() == []
    content = (volume / "blocked-ips.conf").read_text()
    assert content.startswith("#") and waf.parse_rendered(content) == set()
    assert docker.signals == []                                         # fichier absent = liste vide pour nginx (glob)
    assert json.loads((volume / "blocked-ips.json").read_text())["entries"] == []


def test_expire_resyncs_after_crash_between_writes(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    blocklist.block(ATTACKER, 300, "test", incident())
    (volume / "blocked-ips.conf").write_text(waf.render([]))          # arrêt brutal : fichier rendu en retard
    assert blocklist.expire() == []
    assert waf.parse_rendered((volume / "blocked-ips.conf").read_text()) == {ATTACKER}
    assert docker.loaded == {ATTACKER} and len(docker.signals) == 2


def test_failed_reload_is_retried_by_expire(volume, docker, clock):
    docker.fail_signal = True
    blocklist = make(volume, docker, clock)
    with pytest.raises(ActionError, match="rechargement"):
        blocklist.block(ATTACKER, 300, "test", incident())
    assert json.loads((volume / "blocked-ips.json").read_text())["reload_pending"] is True
    assert blocklist.verify(ATTACKER) is False                          # fichier à jour mais WAF pas rechargé
    docker.fail_signal = False
    restarted = make(volume, docker, clock)                              # même après un redémarrage du moteur
    assert restarted.expire() == []
    assert docker.signals == [("waf", "HUP")] and restarted.verify(ATTACKER) is True
    assert json.loads((volume / "blocked-ips.json").read_text())["reload_pending"] is False
    restarted.expire()
    assert len(docker.signals) == 1


def test_corrupt_state_is_rebuilt_from_rendered_file(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    blocklist.block(ATTACKER, 3600, "test", incident())
    (volume / "blocked-ips.json").write_text("{not json")
    active = make(volume, docker, clock).active()
    assert [e.ip for e in active] == [ATTACKER]
    assert active[0].expires_at == clock.now + waf.DEFAULT_TTL_S           # durée par défaut : jamais levé en silence
    assert list(volume.glob("blocked-ips.json.corrupt-*"))


# ─────────────────────────────── Vérification ───────────────────────────────

def test_verify_requires_file_health_and_loaded_config(volume, docker, clock):
    blocklist = make(volume, docker, clock)
    assert blocklist.verify(ATTACKER) is False                          # rien d'écrit
    blocklist.block(ATTACKER, 300, "test", incident())
    assert blocklist.verify(ATTACKER) is True
    assert blocklist.verify(OTHER) is False
    assert blocklist.verify("garbage") is False
    docker.health_value = "unhealthy"
    assert blocklist.verify(ATTACKER) is False
    docker.health_value = "running"                                     # pas de healthcheck : accepté
    assert blocklist.verify(ATTACKER) is True
    docker.loaded = set()                                               # rechargement refusé par nginx (ancienne config)
    assert blocklist.verify(ATTACKER) is False


def test_verify_without_check_endpoint(volume, docker, clock):
    blocklist = make(volume, docker, clock, check_url=None)
    blocklist.block(ATTACKER, 300, "test", incident())
    docker.loaded = set()
    assert blocklist.verify(ATTACKER) is True                           # fichier + santé seulement
    docker.health_value = "exited"
    assert blocklist.verify(ATTACKER) is False


def test_verify_waits_for_asynchronous_reload(volume, docker, clock):
    calls = []

    def slow_fetch(url):
        # Cette méthode permet de simuler des workers nginx qui ne prennent la nouvelle config qu'au 3e essai.
        calls.append(url)
        return {"blocked": 1 if len(calls) >= 3 else 0}

    blocklist = waf.WafBlocklist(volume / "blocked-ips.conf", docker, "waf", discover=False, clock=clock,
                                 fetch=slow_fetch, sleep=lambda _s: None, verify_timeout_s=5)
    blocklist.block(ATTACKER, 300, "test", incident())
    assert blocklist.verify(ATTACKER) is True and len(calls) == 3
    assert calls[0].endswith("/remediation/blocklist?ip=203.0.113.7")


def test_verify_unreachable_check_endpoint_fails(volume, docker, clock):
    def unreachable(url):
        # Cette méthode permet de simuler un port 8081 injoignable (réseau non partagé avec le WAF).
        raise OSError("connection refused")

    blocklist = waf.WafBlocklist(volume / "blocked-ips.conf", docker, "waf", discover=False, clock=clock,
                                 fetch=unreachable, sleep=lambda _s: None, verify_timeout_s=0)
    blocklist.block(ATTACKER, 300, "test", incident())
    assert blocklist.verify(ATTACKER) is False


# ─────────────────────────────── Concurrence ───────────────────────────────

def test_concurrent_blocks_from_threads_and_processes(volume, docker, clock):
    # Deux instances (comme deux processus : verrou fcntl) et plusieurs threads chacune (verrou de thread).
    instances = [make(volume, docker, clock), make(volume, docker, clock)]
    addresses = [str(ipaddress.ip_address("198.51.100.0") + i) for i in range(1, 81)]
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        # Cette méthode permet de bloquer une tranche d'adresses depuis un thread.
        try:
            for ip in addresses[index::8]:
                instances[index % 2].block(ip, 600, "concurrence", incident())
                instances[(index + 1) % 2].active()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert {e.ip for e in instances[0].active()} == set(addresses)
    assert waf.parse_rendered((volume / "blocked-ips.conf").read_text()) == set(addresses)
    assert docker.loaded == set(addresses) and len(docker.signals) == len(addresses)
    assert not [p for p in volume.iterdir() if p.name.endswith(".tmp")]


# ─────────────────────────────── Cohérence avec la configuration du WAF ───────────────────────────────

def test_waf_config_reads_the_rendered_file():
    template = (REPO / "infra" / "waf" / "00-remediation-blocklist.conf.template").read_text()
    guard = (REPO / "infra" / "waf" / "99-remediation-blocklist-guard.sh").read_text()
    path = waf.DEFAULT_PATH
    glob = f"{path.parent}/{path.name[:-1]}[{path.name[-1]}]"
    assert template.count(f"include {glob};") == 2
    assert f"LIST={path}\n" in guard
    assert os.access(REPO / "infra" / "waf" / "99-remediation-blocklist-guard.sh", os.X_OK)
    location = (REPO / "infra" / "waf" / "location_common.conf.template").read_text()
    assert "if ($remediation_blocked)" in location and "modsecurity off;" in location


def test_compose_mounts_blocklist_read_only_in_waf():
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    volumes = compose["services"]["waf"]["volumes"]
    assert f"waf-blocklist:{waf.DEFAULT_PATH.parent}:ro" in volumes
    assert "waf-blocklist" in compose["volumes"]
    targets = {v.split(":")[1] for v in volumes}
    assert {"/etc/nginx/templates/conf.d/00-remediation-blocklist.conf.template",
            "/etc/nginx/templates/includes/location_common.conf.template",
            "/docker-entrypoint.d/99-remediation-blocklist-guard.sh"} <= targets


def test_waf_block_queries_count_only_requests_interrupted_by_the_waf():
    # Le journal d'audit contient aussi les 403 renvoyés par les API (non-admin sur /admin/integrity) : la règle SOC
    # WafAttackBlocked, la variable waf_blocks_per_min du détecteur, l'attribution d'IP du moteur et les panneaux
    # Grafana ne comptent que les requêtes interrompues par le WAF (revue de durcissement, docs/securite/).
    rules = yaml.safe_load((REPO / "infra/loki/rules/fake/soc.yml").read_text(encoding="utf-8"))
    expr = next(r["expr"] for g in rules["groups"] for r in g["rules"] if r.get("alert") == "WafAttackBlocked")
    assert 'code="403" | interrupted="true"' in expr and '__error__=""' in expr
    sources = {
        "soc.yml": expr,
        "features.py": (REPO / "services/anomaly-detector/app/features.py").read_text(encoding="utf-8"),
        "decisions.py": (REPO / "services/remediation-engine/app/decisions.py").read_text(encoding="utf-8"),
        "generate_dashboards.py": (REPO / "infra/grafana/generate_dashboards.py").read_text(encoding="utf-8"),
    }
    for name, text in sources.items():
        assert 'interrupted="transaction.is_interrupted"' in text and 'interrupted="true"' in text, name
    # Tableau SOC régénéré : chaque requête sur le code de réponse du WAF filtre aussi les requêtes interrompues
    soc = json.loads((REPO / "infra/grafana/dashboards/soc.json").read_text(encoding="utf-8"))
    exprs = [e for e in _exprs(soc) if "transaction.response.http_code" in e]
    assert exprs and all('interrupted="true"' in e for e in exprs)


def _exprs(node):
    # Cette méthode permet de lister récursivement les requêtes (champ expr) d'un tableau Grafana.
    if isinstance(node, dict):
        return ([node["expr"]] if "expr" in node else []) + [e for v in node.values() for e in _exprs(v)]
    if isinstance(node, list):
        return [e for v in node for e in _exprs(v)]
    return []
