"""Tests du pont de restauration (EBIOS S5) : client du moteur (RestoreBridge) et runner de l'hôte, sans Docker.

Le runner réel (ansible/files/resilience-remediation-bridge.py) tourne dans un fil avec une restauration et un contrôle
d'intégrité factices : aller-retour du protocole, délais, exécution unique (« busy »), heartbeat périmé, refus des
demandes malformées ou piégées (lien symbolique, lien dur, FIFO, répertoire), garde-fous et lecture des résultats.
"""

import asyncio
import importlib.util
import json
import os
import secrets
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    # Cette méthode permet d'importer un module par son chemin (nom de fichier à tirets, paquet du moteur non chargé).
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


db_restore = _load("remediation_db_restore", REPO / "services/remediation-engine/app/actions/db_restore.py")
runner_mod = _load("resilience_remediation_bridge", REPO / "ansible/files/resilience-remediation-bridge.py")

UID = os.getuid()


def summary(**overrides) -> dict:
    # Cette méthode permet de fabriquer la ligne JSON finale de resilience-pg-restore.
    data = {"restored": f"20261020T0{secrets.randbelow(10)}0000Z-scheduled", "backup_created_at": "2026-10-20T08:00:00Z",
            "backup_age_seconds": 42, "restore_seconds": 10.6}
    data.update(overrides)
    return data


@pytest.fixture
def layout(tmp_path):
    # Cette méthode permet de créer un pont vide aux droits attendus (racine et outbox non inscriptibles par d'autres).
    bridge_dir = tmp_path / "bridge"
    state_dir = tmp_path / "state"
    for path, mode in ((bridge_dir, 0o755), (bridge_dir / "inbox", 0o770), (bridge_dir / "outbox", 0o755),
                       (state_dir, 0o700)):
        path.mkdir()
        os.chmod(path, mode)
    return bridge_dir, state_dir


class FakeHost:
    """Restauration et contrôle d'intégrité factices, pilotables depuis le test."""

    def __init__(self):
        # Cette méthode permet de préparer une restauration réussie et un registre incohérent (409).
        self.integrity = "409"
        self.outcome = runner_mod.Outcome(True, "restored", summary())
        self.calls = 0
        self.release = threading.Event()
        self.release.set()
        self.started = threading.Event()

    def restore(self):
        # Cette méthode permet de simuler resilience-pg-restore (bloquée tant que `release` n'est pas positionné).
        self.calls += 1
        self.started.set()
        self.release.wait(10)
        return self.outcome

    def probe(self) -> str:
        # Cette méthode permet de simuler /internal/integrity.
        return self.integrity


def make_runner(layout, host: FakeHost, **policy) -> "runner_mod.Runner":
    # Cette méthode permet d'assembler le vrai runner avec l'hôte factice et l'uid du test comme uid du moteur.
    bridge_dir, state_dir = layout
    options = {"allowed_uids": frozenset({UID}), "max_restores_per_hour": 0}
    options.update(policy)
    return runner_mod.Runner(bridge_dir, state_dir, runner_mod.Policy(**options), restore=host.restore,
                             probe=host.probe, name="test", docker_check=lambda: True, watch_interval_s=0.02)


@pytest.fixture
def running(layout):
    # Cette méthode permet de faire tourner le runner dans un fil (rôle de l'unité .path) le temps d'un test.
    host = FakeHost()
    runner = make_runner(layout, host)
    runner.heartbeat()
    stop = threading.Event()

    def loop():
        # Cette méthode permet de traiter les demandes en continu jusqu'à la fin du test.
        while not stop.is_set():
            runner.process_pending()
            time.sleep(0.01)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    yield runner, host
    host.release.set()
    stop.set()
    thread.join(5)


def client(layout, **kwargs) -> "db_restore.RestoreBridge":
    # Cette méthode permet de créer le client du moteur avec des délais courts.
    options = {"timeout_s": 5.0, "poll_interval_s": 0.02, "pickup_timeout_s": 2.0}
    options.update(kwargs)
    return db_restore.RestoreBridge(layout[0], **options)


def request_bytes(**overrides) -> bytes:
    # Cette méthode permet de fabriquer une demande valide (ou modifiée) au format du moteur.
    data = {"schema": 1, "action": "restore-latest-healthy", "request_id": uuid.uuid4().hex,
            "incident_id": f"inc-{uuid.uuid4().hex[:8]}", "created_at": time.time(), "requested_by": "remediation-engine"}
    data.update(overrides)
    return json.dumps(data).encode()


def drop_request(layout, raw: bytes) -> None:
    # Cette méthode permet de déposer une demande comme le moteur (temporaire puis renommage).
    inbox = layout[0] / "inbox"
    tmp = inbox / f".request-{uuid.uuid4().hex}.tmp"
    tmp.write_bytes(raw)
    tmp.rename(inbox / "request.json")


def result_of(layout, request_id: str, timeout: float = 5.0) -> dict:
    # Cette méthode permet d'attendre et de lire le résultat écrit par le runner.
    path = layout[0] / "outbox" / f"result-{request_id}.json"
    deadline = time.monotonic() + timeout
    while not path.exists():
        assert time.monotonic() < deadline, "pas de résultat"
        time.sleep(0.01)
    return json.loads(path.read_text())


def outbox_text(layout) -> str:
    # Cette méthode permet de relire tout ce que le runner a publié (pour vérifier qu'aucun contenu n'a fuité).
    return "".join(p.read_text() for p in (layout[0] / "outbox").iterdir())


# ───────────────────────────── Aller-retour du protocole ─────────────────────────────


def test_round_trip_restores_and_returns_script_summary(layout, running):
    runner, host = running
    bridge = client(layout)
    assert bridge.available()
    incident = f"inc-{uuid.uuid4().hex[:8]}"
    result = asyncio.run(bridge.request_restore(incident))
    assert result.ok is True
    assert host.calls == 1
    for key in ("restored", "backup_created_at", "backup_age_seconds", "restore_seconds"):
        assert result.detail[key] == host.outcome.detail[key]
    assert result.detail["status"] == "restored"
    assert result.duration_s > 0
    stored = result_of(layout, result.detail["request_id"])
    assert stored["incident_id"] == incident and stored["runner"] == "test"
    assert not (layout[0] / "inbox" / "request.json").exists()
    assert bridge.in_flight is None


def test_request_file_is_written_by_engine_with_strict_schema(layout):
    # Le runner valide exactement ce qu'écrit le moteur (même schéma des deux côtés)
    bridge = client(layout)
    request_id = uuid.uuid4().hex
    bridge._write_request(request_id, "inc-schema")
    path = layout[0] / "inbox" / "request.json"
    assert path.stat().st_mode & 0o777 == 0o640
    parsed = runner_mod.parse_request(path.read_bytes(), now=time.time())
    assert (parsed.request_id, parsed.incident_id) == (request_id, "inc-schema")
    assert list((layout[0] / "inbox").glob(".request-*")) == []


def test_runner_unavailable_without_heartbeat(layout):
    result = asyncio.run(client(layout).request_restore("inc-1"))
    assert result.ok is False and result.detail["error"] == "runner_unavailable"
    assert not (layout[0] / "inbox" / "request.json").exists()


# ───────────────────────────── Délais ─────────────────────────────


def test_request_not_picked_up_is_withdrawn(layout):
    runner = make_runner(layout, FakeHost())
    runner.heartbeat()  # heartbeat présent mais aucune boucle de traitement
    result = asyncio.run(client(layout, pickup_timeout_s=0.2).request_restore("inc-2"))
    assert result.detail["error"] == "not_picked_up"
    assert not (layout[0] / "inbox" / "request.json").exists()


def test_timeout_while_restore_runs(layout, running):
    _, host = running
    host.release.clear()
    result = asyncio.run(client(layout, timeout_s=0.5).request_restore("inc-3"))
    assert result.ok is False
    assert result.detail["error"] == "timeout" and result.detail["picked_up"] is True
    assert 0.5 <= result.duration_s < 3


# ───────────────────────────── Exécution unique ─────────────────────────────


def test_second_request_from_same_engine_is_busy(layout, running):
    _, host = running
    host.release.clear()
    bridge = client(layout)

    async def scenario():
        # Cette méthode permet de lancer deux demandes concurrentes depuis le même moteur.
        first = asyncio.create_task(bridge.request_restore("inc-a"))
        while not host.started.is_set():
            await asyncio.sleep(0.01)
        second = await bridge.request_restore("inc-b")
        host.release.set()
        return await first, second

    first, second = asyncio.run(scenario())
    assert first.ok is True
    assert second.ok is False and second.detail["error"] == "busy"
    assert second.detail["active_request_id"] == first.detail["request_id"]
    assert host.calls == 1


def test_runner_answers_busy_to_a_new_request_during_restore(layout, running):
    # Moteur redémarré pendant une restauration : sa nouvelle demande reçoit « busy » du runner, sans attendre la fin
    _, host = running
    host.release.clear()
    first = uuid.uuid4().hex
    drop_request(layout, request_bytes(request_id=first))
    assert host.started.wait(5)
    second = uuid.uuid4().hex
    drop_request(layout, request_bytes(request_id=second))
    busy = result_of(layout, second)
    assert busy["status"] == "busy" and busy["detail"]["active_request_id"] == first
    heartbeat = json.loads((layout[0] / "outbox" / "heartbeat.json").read_text())
    assert heartbeat["busy"] is True and heartbeat["active_request_id"] == first
    host.release.set()
    assert result_of(layout, first)["status"] == "restored"
    assert host.calls == 1


def test_lock_held_by_another_process_gives_busy(layout):
    host = FakeHost()
    runner = make_runner(layout, host)
    other = runner_mod.RunnerLock(layout[1] / "restore.lock")
    holder = runner_mod.Request(uuid.uuid4().hex, "inc-other", time.time())
    assert other.try_acquire(holder)
    try:
        request_id = uuid.uuid4().hex
        drop_request(layout, request_bytes(request_id=request_id))
        result = runner.process_pending()
        assert result["status"] == "busy" and result["detail"]["active_request_id"] == holder.request_id
        assert host.calls == 0
    finally:
        other.release()
    assert runner.lock.active() is None


def test_engine_reports_busy_from_heartbeat(layout):
    runner = make_runner(layout, FakeHost())
    runner.heartbeat()
    path = layout[0] / "outbox" / "heartbeat.json"
    data = json.loads(path.read_text())
    data.update(busy=True, active_request_id=uuid.uuid4().hex)
    path.write_text(json.dumps(data))
    result = asyncio.run(client(layout).request_restore("inc-4"))
    assert result.detail["error"] == "busy"
    assert not (layout[0] / "inbox" / "request.json").exists()


# ───────────────────────────── Heartbeat ─────────────────────────────


@pytest.mark.parametrize("age, docker_ok, expected", [
    (5, True, True), (119, None, True), (121, True, False), (3600, True, False), (-300, True, False), (5, False, False),
])
def test_heartbeat_staleness(layout, age, docker_ok, expected):
    heartbeat = {"schema": 1, "runner": "test", "written_at": time.time() - age, "busy": False}
    if docker_ok is not None:
        heartbeat["docker_ok"] = docker_ok
    (layout[0] / "outbox" / "heartbeat.json").write_text(json.dumps(heartbeat))
    assert client(layout).available() is expected


@pytest.mark.parametrize("content", [b"", b"{not json", b"[]", b'{"schema": 1, "written_at": "now"}',
                                     b'{"schema": 2, "written_at": 1e12}', b'{"schema": 1, "written_at": NaN}'])
def test_invalid_heartbeat_is_unavailable(layout, content):
    (layout[0] / "outbox" / "heartbeat.json").write_bytes(content)
    assert client(layout).available() is False


def test_symlinked_heartbeat_is_ignored(layout, tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"schema": 1, "written_at": time.time()}))
    (layout[0] / "outbox" / "heartbeat.json").symlink_to(target)
    assert client(layout).available() is False


def test_missing_bridge_directory_is_unavailable(tmp_path):
    assert db_restore.RestoreBridge(tmp_path / "absent").available() is False


# ───────────────────────────── Validation des demandes (runner) ─────────────────────────────


@pytest.mark.parametrize("raw, reason", [
    (b"\xff\xfe", "not_utf8"),
    (b"{not json", "malformed_json"),
    (b"[1, 2]", "schema"),
    (b"x" * 5000, "too_large"),
    (request_bytes(request_id="../../etc/cron.d/x"), "bad_request_id"),
    (request_bytes(request_id=uuid.uuid4().hex.upper()), "bad_request_id"),
    (request_bytes(request_id=12345), "bad_request_id"),
])
def test_parse_request_rejects_without_usable_id(raw, reason):
    with pytest.raises(runner_mod.RequestRejected) as err:
        runner_mod.parse_request(raw, now=time.time())
    assert err.value.reason == reason and err.value.request_id is None


@pytest.mark.parametrize("overrides, reason", [
    ({"action": "restore"}, "unsupported_action"),
    ({"action": "restore-latest-healthy; rm -rf /"}, "unsupported_action"),
    ({"schema": 2}, "unsupported_schema"),
    ({"schema": True}, "unsupported_schema"),
    ({"incident_id": "$(reboot)"}, "bad_incident_id"),
    ({"incident_id": "inc 1"}, "bad_incident_id"),
    ({"incident_id": "a" * 200}, "bad_incident_id"),
    ({"requested_by": "someone"}, "schema"),
    ({"created_at": "2026-10-20"}, "schema"),
    ({"created_at": True}, "schema"),
    ({"created_at": time.time() + 3600}, "future"),
    ({"created_at": time.time() - 600}, "expired"),
    ({"extra": "field"}, "schema"),
])
def test_parse_request_rejects_with_id(overrides, reason):
    raw = request_bytes(**overrides)
    with pytest.raises(runner_mod.RequestRejected) as err:
        runner_mod.parse_request(raw, now=time.time())
    assert err.value.reason == reason
    assert err.value.request_id == json.loads(raw)["request_id"]


def test_parse_request_rejects_duplicate_keys_and_nan():
    request_id = uuid.uuid4().hex
    duplicated = request_bytes(request_id=request_id)[:-1] + b', "action": "restore-latest-healthy"}'
    with pytest.raises(runner_mod.RequestRejected) as err:
        runner_mod.parse_request(duplicated, now=time.time())
    assert err.value.reason == "malformed_json"
    nan = request_bytes(request_id=request_id).replace(b'"created_at": ', b'"created_at": NaN, "x": ')
    with pytest.raises(runner_mod.RequestRejected):
        runner_mod.parse_request(nan, now=time.time())


def test_parse_request_accepts_engine_request():
    request_id = uuid.uuid4().hex
    parsed = runner_mod.parse_request(request_bytes(request_id=request_id, incident_id="inc-2026.10:a_b"),
                                      now=time.time())
    assert parsed.request_id == request_id and parsed.incident_id == "inc-2026.10:a_b"


def _inbox_fd(layout) -> int:
    # Cette méthode permet d'ouvrir inbox/ par descripteur, comme le runner.
    return os.open(layout[0] / "inbox", os.O_RDONLY | os.O_DIRECTORY)


def test_read_request_refuses_symlink(layout, tmp_path):
    secret_file = tmp_path / "host-secret"
    secret_file.write_text(secrets.token_hex(16))
    (layout[0] / "inbox" / "request.json").symlink_to(secret_file)
    fd = _inbox_fd(layout)
    try:
        with pytest.raises(runner_mod.RequestRejected) as err:
            runner_mod.read_request(fd, {UID})
        assert err.value.reason == "symlink"
    finally:
        os.close(fd)


def test_read_request_refuses_hardlink(layout, tmp_path):
    outside = tmp_path / "host-file"
    outside.write_bytes(request_bytes())
    os.link(outside, layout[0] / "inbox" / "request.json")
    fd = _inbox_fd(layout)
    try:
        with pytest.raises(runner_mod.RequestRejected) as err:
            runner_mod.read_request(fd, {UID})
        assert err.value.reason == "hardlinked"
    finally:
        os.close(fd)


def test_read_request_refuses_fifo_without_blocking(layout):
    os.mkfifo(layout[0] / "inbox" / "request.json")
    fd = _inbox_fd(layout)
    try:
        with pytest.raises(runner_mod.RequestRejected) as err:
            runner_mod.read_request(fd, {UID})
        assert err.value.reason == "not_regular_file"
    finally:
        os.close(fd)


def test_read_request_checks_owner_and_size(layout):
    drop_request(layout, request_bytes())
    fd = _inbox_fd(layout)
    try:
        with pytest.raises(runner_mod.RequestRejected) as err:
            runner_mod.read_request(fd, {UID + 1})
        assert err.value.reason == "wrong_owner"
        (layout[0] / "inbox" / "request.json").write_bytes(b" " * 5000)
        with pytest.raises(runner_mod.RequestRejected) as err:
            runner_mod.read_request(fd, {UID})
        assert err.value.reason == "too_large"
        assert runner_mod.read_request(fd, {UID}, name="absent.json") is None
    finally:
        os.close(fd)


def test_runner_rejects_symlinked_request_without_leaking_target(layout, tmp_path):
    host = FakeHost()
    marker = secrets.token_hex(16)
    secret_file = tmp_path / "host-secret"
    secret_file.write_text(json.dumps({"request_id": uuid.uuid4().hex, "marker": marker}))
    (layout[0] / "inbox" / "request.json").symlink_to(secret_file)
    assert make_runner(layout, host).process_pending() is None
    assert host.calls == 0
    assert not os.path.lexists(layout[0] / "inbox" / "request.json")
    assert secret_file.exists()
    rejected = json.loads((layout[0] / "outbox" / "rejected.json").read_text())
    assert rejected["reason"] == "symlink"
    assert marker not in outbox_text(layout)


def test_runner_quarantines_a_directory_request(layout):
    (layout[0] / "inbox" / "request.json").mkdir()
    make_runner(layout, FakeHost()).process_pending()
    assert not os.path.lexists(layout[0] / "inbox" / "request.json")
    assert [p.name.startswith(".rejected-") for p in (layout[0] / "inbox").iterdir()] == [True]


def test_runner_answers_malformed_request_with_id(layout):
    host = FakeHost()
    request_id = uuid.uuid4().hex
    drop_request(layout, request_bytes(request_id=request_id, action="drop-database"))
    result = make_runner(layout, host).process_pending()
    assert result is None and host.calls == 0
    stored = result_of(layout, request_id)
    assert stored["ok"] is False and stored["status"] == "rejected"
    assert stored["detail"] == {"error": "unsupported_action"}
    assert "drop-database" not in outbox_text(layout)


# ───────────────────────────── Garde-fous du runner ─────────────────────────────


@pytest.mark.parametrize("code", ["200", "503", "unreachable", "<script>"])
def test_restore_requires_a_corrupted_ledger(layout, code):
    host = FakeHost()
    host.integrity = code
    drop_request(layout, request_bytes())
    result = make_runner(layout, host).process_pending()
    assert result["status"] == "precondition_failed" and host.calls == 0
    assert result["detail"]["integrity_http"] == (code if code.isalnum() else "unexpected")


def test_restores_are_rate_limited(layout):
    host = FakeHost()
    runner = make_runner(layout, host, max_restores_per_hour=1)
    drop_request(layout, request_bytes())
    assert runner.process_pending()["status"] == "restored"
    drop_request(layout, request_bytes())
    limited = runner.process_pending()
    assert limited["status"] == "rate_limited" and limited["detail"]["restores_last_hour"] == 1
    assert host.calls == 1


def test_cleanup_expires_stale_request_and_old_files(layout):
    host = FakeHost()
    runner = make_runner(layout, host)
    request_id = uuid.uuid4().hex
    drop_request(layout, request_bytes(request_id=request_id, created_at=time.time() - 30))
    inbox, outbox = layout[0] / "inbox", layout[0] / "outbox"
    old = time.time() - 7200
    os.utime(inbox / "request.json", (old, old))
    tmp = inbox / f".request-{uuid.uuid4().hex}.tmp"
    tmp.write_text("{}")
    os.utime(tmp, (old, old))
    stale_result = outbox / f"result-{uuid.uuid4().hex}.json"
    stale_result.write_text("{}")
    os.utime(stale_result, (old - 86400, old - 86400))
    runner.cleanup()
    assert host.calls == 0
    assert result_of(layout, request_id)["status"] == "expired"
    assert not tmp.exists() and not stale_result.exists()


def test_layout_writable_by_others_is_refused(layout):
    os.chmod(layout[0] / "outbox", 0o777)
    with pytest.raises(runner_mod.LayoutError):
        make_runner(layout, FakeHost()).heartbeat()


def test_atomic_write_replaces_a_planted_symlink(layout, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("intact")
    outbox = layout[0] / "outbox"
    (outbox / "heartbeat.json").symlink_to(victim)
    make_runner(layout, FakeHost()).heartbeat()
    assert victim.read_text() == "intact"
    assert not (outbox / "heartbeat.json").is_symlink()
    assert json.loads((outbox / "heartbeat.json").read_text())["docker_ok"] is True


# ───────────────────────────── Lecture des résultats ─────────────────────────────


def test_parse_restore_summary_from_script_output():
    expected = summary()
    lines = ["08:00:01 sauvegarde choisie : x", "08:00:02 registre cohérent après restauration", json.dumps(expected), ""]
    assert runner_mod.parse_restore_summary(lines) == expected
    assert runner_mod.parse_restore_summary(["08:00:01 erreur"]) is None
    assert runner_mod.parse_restore_summary([json.dumps(summary(restore_seconds="vite"))]) is None
    assert runner_mod.parse_restore_summary([]) is None


def _script(tmp_path: Path, body: str) -> list[str]:
    # Cette méthode permet de fabriquer une fausse commande de restauration (Python, sans shell).
    path = tmp_path / f"restore-{uuid.uuid4().hex[:6]}.py"
    path.write_text(body)
    return [sys.executable, str(path)]


def test_command_restorer_interprets_exit_codes(tmp_path):
    expected = summary()
    ok = runner_mod.command_restorer(_script(tmp_path, f"print('08:00 étape')\nprint({json.dumps(json.dumps(expected))})"), 10)()
    assert ok.ok is True and ok.detail == expected
    busy = runner_mod.command_restorer(_script(tmp_path, "raise SystemExit(75)"), 10)()
    assert busy.status == "busy"
    failed = runner_mod.command_restorer(_script(tmp_path, "print('pg_restore: erreur')\nraise SystemExit(1)"), 10)()
    assert failed.status == "failed" and failed.detail["exit_code"] == 1
    assert failed.detail["output_tail"] == ["pg_restore: erreur"]
    slow = runner_mod.command_restorer(_script(tmp_path, "import time\nprint('début', flush=True)\ntime.sleep(30)"), 0.5)()
    assert slow.status == "timeout" and slow.detail["output_tail"] == ["début"]


@pytest.mark.parametrize("data, error", [
    ({"request_id": "autre", "ok": True}, "result_mismatch"),
    ({"ok": True, "status": "restored", "detail": {"restored": "x"}}, "invalid_result"),
    ({"ok": False, "status": "failed", "detail": {"error": "restore_failed", "exit_code": 1}}, "restore_failed"),
    ({"ok": "yes", "status": "restored", "detail": summary()}, "restored"),
])
def test_engine_result_parsing(data, error):
    request_id = uuid.uuid4().hex
    data = {"request_id": request_id, "incident_id": "inc-9", **data}
    if data["request_id"] == "autre":
        data["request_id"] = uuid.uuid4().hex
    ok, detail = db_restore.RestoreBridge._parse_result(data, request_id, "inc-9")
    assert ok is False and detail["error"] == error


def test_engine_rejects_invalid_incident_id(layout, running):
    result = asyncio.run(client(layout).request_restore("inc; reboot"))
    assert result.ok is False and result.detail["error"] == "invalid_incident_id"
