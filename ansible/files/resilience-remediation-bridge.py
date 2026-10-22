#!/usr/bin/python3 -I
# Installé par Ansible (tasks/remediation_bridge_install.yml) dans /usr/local/sbin/resilience-remediation-bridge.
"""Pont de remédiation, côté hôte : exécute la restauration PostgreSQL demandée par le moteur de remédiation.

Le moteur (conteneur non privilégié, uid 10001, sans socket Docker brut) ne peut que déposer une demande dans le
répertoire du pont. Ce programme, lancé en root par systemd (unité .path sur la demande, timer pour le heartbeat),
la valide puis lance `resilience-pg-restore latest-healthy`. Le contenu de la demande ne sert jamais à construire une
commande : la seule action possible est « restaurer la dernière sauvegarde saine », une seule à la fois, au plus
N par heure, et seulement si le registre est réellement incohérent (HTTP 409 sur /internal/integrity).

Répertoire du pont (monté en /bridge dans le moteur) :
  inbox/request.json               demande du moteur (écrite dans inbox/.request-<id>.tmp puis renommée)
  outbox/result-<request_id>.json  résultat écrit par le runner (fichier temporaire puis renommage)
  outbox/heartbeat.json            présence du runner (rafraîchi toutes les 30 s, périmé au-delà de 120 s)
  outbox/rejected.json             dernière demande refusée sans identifiant exploitable (motif seulement)
Protocole et modèle de sécurité : docs/runbooks/restauration-base.md, « Restauration automatique ».

Bibliothèque standard uniquement (Python ≥ 3.11) : ce fichier est aussi importé par scripts/remediation_bridge_dev.py
(runner de développement) et par tests/unit/test_db_restore.py.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import math
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Collection, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

PROTOCOL_VERSION = 1
ACTION_RESTORE = "restore-latest-healthy"
REQUESTED_BY = "remediation-engine"

INBOX = "inbox"
OUTBOX = "outbox"
REQUEST_NAME = "request.json"
HEARTBEAT_NAME = "heartbeat.json"
REJECTED_NAME = "rejected.json"
RESULT_PREFIX = "result-"
ENGINE_TMP_PREFIX = ".request-"
QUARANTINE_PREFIX = ".rejected-"

REQUEST_KEYS = frozenset({"schema", "action", "request_id", "incident_id", "created_at", "requested_by"})
REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}")
INCIDENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
MAX_REQUEST_BYTES = 4096
REQUEST_MAX_AGE_S = 120.0       # une demande plus ancienne n'est jamais exécutée (runner revenu après une panne)
CLOCK_SKEW_S = 30.0
BUSY_HEARTBEAT_S = 10.0         # heartbeat rafraîchi pendant une restauration
STALE_TMP_S = 600.0
RESULT_MAX_AGE_S = 86400.0
RESULTS_KEPT = 100
OUTPUT_TAIL_LINES = 20
OUTPUT_LINE_CHARS = 300
EX_TEMPFAIL = 75                # resilience-pg-restore : une restauration tient déjà le verrou
SUMMARY_KEYS = {"restored": str, "backup_created_at": str, "backup_age_seconds": (int, float), "restore_seconds": (int, float)}

# Contrôle d'intégrité du registre depuis le conteneur payment-api (endpoint interne, non publié) : même code que les scripts.
INTEGRITY_PROBE = """
import urllib.error, urllib.request
try:
    print(urllib.request.urlopen("http://127.0.0.1:8000/internal/integrity", timeout=10).status)
except urllib.error.HTTPError as err:
    print(err.code)
except Exception:
    print("unreachable")
"""


class RequestRejected(Exception):
    """Demande refusée ; `reason` est un code fixe, jamais un extrait du contenu reçu (qui pourrait être un secret lié)."""

    def __init__(self, reason: str, request_id: str | None = None):
        # Cette méthode permet de garder le motif du refus et, s'il est sûr, l'identifiant à qui répondre.
        super().__init__(reason)
        self.reason = reason
        self.request_id = request_id


class LayoutError(RuntimeError):
    """Répertoire du pont absent ou aux droits dangereux : le runner refuse de travailler."""


@dataclass(frozen=True)
class Request:
    request_id: str
    incident_id: str
    created_at: float


@dataclass
class Outcome:
    ok: bool
    status: str      # restored | failed | busy | timeout | rejected | expired | precondition_failed | rate_limited
    detail: dict


@dataclass
class Policy:
    allowed_uids: frozenset[int]          # propriétaires acceptés pour inbox/request.json (le moteur : 10001)
    max_age_s: float = REQUEST_MAX_AGE_S
    max_restores_per_hour: int = 3        # 0 = sans limite (tests)
    require_corruption: bool = True       # ne restaurer que si /internal/integrity répond 409


def log(event: str, **fields) -> None:
    # Cette méthode permet d'écrire un événement JSON sur une ligne (journalctl -u resilience-remediation-bridge).
    print(json.dumps({"event_type": f"remediation_bridge_{event}", **fields}, ensure_ascii=False, default=str), flush=True)


# ───────────────────────────────────────── Validation ─────────────────────────────────────────


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    # Cette méthode permet de refuser un objet JSON dont une clé est répétée (deux lecteurs pourraient lire deux valeurs).
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("clé répétée")
    return dict(pairs)


def _no_constant(_: str) -> float:
    # Cette méthode permet de refuser NaN et Infinity, que le module json accepte par défaut.
    raise ValueError("nombre non fini")


def parse_request(raw: bytes, *, now: float, max_age_s: float = REQUEST_MAX_AGE_S) -> Request:
    # Cette méthode permet de valider une demande selon un schéma strict (clés exactes, types, formats, fraîcheur) ;
    # l'identifiant n'est rendu au refus que s'il est bien formé, pour nommer le fichier de résultat sans risque.
    if len(raw) > MAX_REQUEST_BYTES:
        raise RequestRejected("too_large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise RequestRejected("not_utf8") from None
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
    except (ValueError, RecursionError):
        raise RequestRejected("malformed_json") from None
    if not isinstance(data, dict):
        raise RequestRejected("schema")
    request_id = data.get("request_id")
    request_id = request_id if isinstance(request_id, str) and REQUEST_ID_RE.fullmatch(request_id) else None
    if request_id is None:
        raise RequestRejected("bad_request_id")
    if set(data) != REQUEST_KEYS:
        raise RequestRejected("schema", request_id)
    if type(data["schema"]) is not int or data["schema"] != PROTOCOL_VERSION:
        raise RequestRejected("unsupported_schema", request_id)
    if data["action"] != ACTION_RESTORE:
        raise RequestRejected("unsupported_action", request_id)
    if data["requested_by"] != REQUESTED_BY:
        raise RequestRejected("schema", request_id)
    incident_id = data["incident_id"]
    if not isinstance(incident_id, str) or not INCIDENT_ID_RE.fullmatch(incident_id):
        raise RequestRejected("bad_incident_id", request_id)
    created_at = data["created_at"]
    if type(created_at) not in (int, float) or not math.isfinite(created_at):
        raise RequestRejected("schema", request_id)
    if created_at > now + CLOCK_SKEW_S:
        raise RequestRejected("future", request_id)
    if now - created_at > max_age_s:
        raise RequestRejected("expired", request_id)
    return Request(request_id, incident_id, float(created_at))


def read_request(inbox_fd: int, allowed_uids: Collection[int], *, name: str = REQUEST_NAME,
                 max_bytes: int = MAX_REQUEST_BYTES) -> bytes | None:
    # Cette méthode permet de lire la demande sans se laisser piéger par le moteur, qui contrôle inbox/ :
    # pas de lien symbolique suivi (O_NOFOLLOW), pas de FIFO bloquante (O_NONBLOCK), fichier ordinaire à un seul lien
    # (un lien dur vers un fichier de l'hôte est refusé), propriétaire attendu, taille bornée ; None si aucune demande.
    try:
        before = os.stat(name, dir_fd=inbox_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(before.st_mode):
        raise RequestRejected("symlink")
    if not stat.S_ISREG(before.st_mode):
        raise RequestRejected("not_regular_file")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=inbox_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RequestRejected("symlink" if exc.errno == errno.ELOOP else "unreadable") from None
    try:
        # Contrôles refaits sur le fichier réellement ouvert : il a pu être remplacé entre stat() et open()
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RequestRejected("not_regular_file")
        if st.st_nlink != 1:
            raise RequestRejected("hardlinked")
        if st.st_uid not in allowed_uids:
            raise RequestRejected("wrong_owner")
        if st.st_size > max_bytes:
            raise RequestRejected("too_large")
        chunks, total = [], 0
        while chunk := os.read(fd, max_bytes + 1 - total):
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise RequestRejected("too_large")
        return b"".join(chunks)
    finally:
        os.close(fd)


def discard_request(inbox_fd: int, name: str = REQUEST_NAME) -> None:
    # Cette méthode permet de consommer la demande avant toute action : jamais exécutée deux fois, et l'unité .path
    # (PathExists) n'est pas relancée en boucle. unlinkat ne suit pas les liens ; un répertoire est seulement renommé
    # (pas de suppression récursive par root dans un répertoire contrôlé par le moteur).
    try:
        st = os.stat(name, dir_fd=inbox_fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            quarantine = f"{QUARANTINE_PREFIX}{int(time.time())}-{secrets.token_hex(4)}"
            os.rename(name, quarantine, src_dir_fd=inbox_fd, dst_dir_fd=inbox_fd)
        else:
            os.unlink(name, dir_fd=inbox_fd)
    except FileNotFoundError:
        pass


def parse_restore_summary(lines: list[str]) -> dict | None:
    # Cette méthode permet d'extraire la ligne JSON finale de resilience-pg-restore (sauvegarde restaurée, âge, durée),
    # précédée de ses lignes de journal ; None si elle manque ou n'a pas la forme attendue.
    for line in reversed(lines):
        if line.strip():
            try:
                data = json.loads(line, parse_constant=_no_constant)
            except ValueError:
                return None
            break
    else:
        return None
    if not isinstance(data, dict):
        return None
    summary = {}
    for key, kind in SUMMARY_KEYS.items():
        value = data.get(key)
        if not isinstance(value, kind) or isinstance(value, bool):
            return None
        summary[key] = value
    return summary


def output_tail(text: str) -> list[str]:
    # Cette méthode permet de joindre au résultat la fin de la sortie d'une commande, bornée en lignes et en longueur.
    lines = [line[:OUTPUT_LINE_CHARS] for line in text.splitlines() if line.strip()]
    return lines[-OUTPUT_TAIL_LINES:]


# ───────────────────────────────────────── Fichiers ─────────────────────────────────────────


def write_json_atomic(dir_fd: int, name: str, payload: dict, mode: int = 0o644) -> None:
    # Cette méthode permet d'écrire un fichier complet ou rien : nom temporaire aléatoire créé en O_EXCL|O_NOFOLLOW
    # (jamais d'écriture à travers un lien posé d'avance), fsync, puis rename(), qui remplace l'entrée sans la suivre.
    data = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode()
    tmp = f".{name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(tmp, dir_fd=dir_fd)
        raise
    os.close(fd)
    os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)


def read_json_file(dir_fd: int, name: str, max_bytes: int = 65536) -> dict | None:
    # Cette méthode permet de relire un fichier JSON écrit par le runner (état, historique) ; None s'il est absent ou invalide.
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(data) if len(data) <= max_bytes else None
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _open_dir(name: str | os.PathLike, dir_fd: int | None = None) -> int:
    # Cette méthode permet d'ouvrir un répertoire sans suivre de lien symbolique ; les accès suivants passent par ce fd.
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError as exc:
        raise LayoutError(f"répertoire du pont inutilisable : {os.fspath(name)} ({exc.strerror})") from None


def _check_private_dir(fd: int, label: str) -> None:
    # Cette méthode permet de vérifier qu'un répertoire où le runner écrit lui appartient et n'est inscriptible par personne
    # d'autre : le moteur ne peut ni y poser de piège ni remplacer inbox/ ou outbox/.
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise LayoutError(f"{label} doit appartenir à l'uid {os.geteuid()} et n'être inscriptible que par lui")


@contextmanager
def bridge_dirs(bridge_dir: Path) -> Iterator[tuple[int, int]]:
    # Cette méthode permet d'ouvrir inbox/ et outbox/ par descripteurs, après contrôle des droits du pont.
    fds: list[int] = []
    try:
        fds.append(_open_dir(bridge_dir))
        _check_private_dir(fds[0], str(bridge_dir))
        fds.append(_open_dir(INBOX, fds[0]))
        fds.append(_open_dir(OUTBOX, fds[0]))
        _check_private_dir(fds[2], f"{bridge_dir}/{OUTBOX}")
        yield fds[1], fds[2]
    finally:
        for fd in fds:
            os.close(fd)


class RunnerLock:
    """Verrou d'exécution unique (flock), dans le répertoire d'état du runner, hors du pont : le moteur ne peut ni
    l'ouvrir ni donc le bloquer. Son contenu décrit la demande en cours (lu par le heartbeat)."""

    def __init__(self, path: Path):
        # Cette méthode permet de désigner le fichier de verrou (créé à la première utilisation).
        self.path = Path(path)
        self._fd: int | None = None

    def _open(self) -> int:
        # Cette méthode permet d'ouvrir le fichier de verrou sans le tronquer ni suivre de lien.
        return os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)

    def try_acquire(self, request: Request) -> bool:
        # Cette méthode permet de prendre le verrou sans attendre ; False si une restauration est déjà en cours.
        fd = self._open()
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        os.ftruncate(fd, 0)
        os.pwrite(fd, json.dumps({"request_id": request.request_id, "incident_id": request.incident_id,
                                  "started_at": time.time()}).encode(), 0)
        self._fd = fd
        return True

    def release(self) -> None:
        # Cette méthode permet de libérer le verrou après la restauration.
        if self._fd is not None:
            os.ftruncate(self._fd, 0)
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None

    def active(self) -> dict | None:
        # Cette méthode permet de savoir si une restauration est en cours (dans ce processus ou un autre) et laquelle.
        fd = self._open()
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                try:
                    info = json.loads(os.pread(fd, 4096, 0) or b"{}")
                except ValueError:
                    info = {}
                return info if isinstance(info, dict) else {}
            fcntl.flock(fd, fcntl.LOCK_UN)
            return None
        finally:
            os.close(fd)


# ───────────────────────────────────────── Runner ─────────────────────────────────────────


class Runner:
    """Traite les demandes du pont : validation, exécution unique, garde-fous, résultat, heartbeat, ménage."""

    def __init__(self, bridge_dir: Path, state_dir: Path, policy: Policy, restore: Callable[[], Outcome],
                 probe: Callable[[], str], *, name: str = "systemd", docker_check: Callable[[], bool] | None = None,
                 clock: Callable[[], float] = time.time, watch_interval_s: float = 0.5):
        # Cette méthode permet d'assembler le runner : la restauration et le contrôle d'intégrité sont injectés
        # (commande de l'hôte en production, équivalent Python en développement, faux dans les tests).
        self.bridge_dir = Path(bridge_dir)
        self.state_dir = Path(state_dir)
        self.policy = policy
        self.restore = restore
        self.probe = probe
        self.name = name
        self.docker_check = docker_check
        self.clock = clock
        self.watch_interval_s = watch_interval_s
        self.lock = RunnerLock(self.state_dir / "restore.lock")
        self._docker_ok: bool | None = None

    # ── Demandes ──

    def process_pending(self) -> dict | None:
        # Cette méthode permet de traiter la demande déposée, s'il y en a une, et de rendre le résultat écrit.
        with bridge_dirs(self.bridge_dir) as (inbox_fd, outbox_fd):
            request = self._take_request(inbox_fd, outbox_fd)
            if request is None:
                return None
            if not self.lock.try_acquire(request):
                return self._answer_busy(outbox_fd, request)
            try:
                self._write_heartbeat(outbox_fd, check_docker=False)
                return self._execute(inbox_fd, outbox_fd, request)
            except Exception as exc:  # le moteur doit toujours recevoir une réponse
                log("internal_error", request_id=request.request_id, error=type(exc).__name__)
                return self._write_result(outbox_fd, request.request_id, request.incident_id,
                                          Outcome(False, "failed", {"error": "runner_exception",
                                                                    "message": type(exc).__name__}))
            finally:
                self.lock.release()
                self._write_heartbeat(outbox_fd, check_docker=False)

    def _take_request(self, inbox_fd: int, outbox_fd: int, *, expire_only: bool = False) -> Request | None:
        # Cette méthode permet de lire, consommer et valider la demande ; un refus reçoit un résultat (ou rejected.json).
        try:
            raw = read_request(inbox_fd, self.policy.allowed_uids)
        except RequestRejected as exc:
            discard_request(inbox_fd)
            self._reject(outbox_fd, exc)
            return None
        if raw is None:
            return None
        discard_request(inbox_fd)
        try:
            request = parse_request(raw, now=self.clock(), max_age_s=self.policy.max_age_s)
        except RequestRejected as exc:
            self._reject(outbox_fd, exc)
            return None
        if expire_only:
            self._reject(outbox_fd, RequestRejected("expired", request.request_id), request.incident_id)
            return None
        return request

    def _reject(self, outbox_fd: int, exc: RequestRejected, incident_id: str | None = None) -> None:
        # Cette méthode permet de répondre à une demande refusée sans jamais recopier son contenu.
        log("request_rejected", reason=exc.reason, request_id=exc.request_id)
        status = "expired" if exc.reason == "expired" else "rejected"
        if exc.request_id:
            self._write_result(outbox_fd, exc.request_id, incident_id, Outcome(False, status, {"error": exc.reason}))
        else:
            write_json_atomic(outbox_fd, REJECTED_NAME, {"schema": PROTOCOL_VERSION, "reason": exc.reason,
                                                         "at": self.clock()})

    def _answer_busy(self, outbox_fd: int, request: Request) -> dict:
        # Cette méthode permet de refuser une seconde demande pendant une restauration (exécution unique).
        active = self.lock.active() or {}
        log("request_busy", request_id=request.request_id, active_request_id=active.get("request_id"))
        return self._write_result(outbox_fd, request.request_id, request.incident_id,
                                  Outcome(False, "busy", {"error": "busy",
                                                          "active_request_id": active.get("request_id")}))

    def _execute(self, inbox_fd: int, outbox_fd: int, request: Request) -> dict:
        # Cette méthode permet d'appliquer les garde-fous (fréquence, registre réellement incohérent) puis de restaurer.
        now = self.clock()
        history = [t for t in self._history() if now - t < 3600]
        limit = self.policy.max_restores_per_hour
        if limit and len(history) >= limit:
            outcome = Outcome(False, "rate_limited", {"error": "rate_limited", "restores_last_hour": len(history),
                                                      "max_restores_per_hour": limit})
            return self._write_result(outbox_fd, request.request_id, request.incident_id, outcome)
        if self.policy.require_corruption:
            code = self.probe()
            code = code if re.fullmatch(r"[0-9a-z]{1,16}", code or "") else "unexpected"
            if code != "409":
                outcome = Outcome(False, "precondition_failed", {
                    "error": "precondition_failed", "integrity_http": code,
                    "message": "registre non incohérent (409 attendu) : aucune restauration"})
                return self._write_result(outbox_fd, request.request_id, request.incident_id, outcome)
        self._save_history(history + [now])
        log("restore_started", request_id=request.request_id, incident_id=request.incident_id)
        outcome = self._run_watching(inbox_fd, outbox_fd)
        log("restore_finished", request_id=request.request_id, status=outcome.status, ok=outcome.ok)
        return self._write_result(outbox_fd, request.request_id, request.incident_id, outcome)

    def _run_watching(self, inbox_fd: int, outbox_fd: int) -> Outcome:
        # Cette méthode permet de restaurer dans un fil séparé tout en répondant « busy » aux nouvelles demandes
        # et en gardant le heartbeat frais (une restauration peut dépasser la durée de validité du heartbeat).
        box: dict[str, Outcome] = {}

        def target() -> None:
            # Cette méthode permet d'exécuter la restauration et de convertir toute exception en échec.
            try:
                box["outcome"] = self.restore()
            except Exception as exc:
                box["outcome"] = Outcome(False, "failed", {"error": "runner_exception", "message": type(exc).__name__})

        worker = threading.Thread(target=target, name="restore", daemon=True)
        worker.start()
        last_heartbeat = self.clock()
        while worker.is_alive():
            worker.join(self.watch_interval_s)
            other = self._take_request(inbox_fd, outbox_fd)
            if other is not None:
                self._answer_busy(outbox_fd, other)
            if self.clock() - last_heartbeat >= BUSY_HEARTBEAT_S:
                self._write_heartbeat(outbox_fd, check_docker=False)
                last_heartbeat = self.clock()
        return box["outcome"]

    def _write_result(self, outbox_fd: int, request_id: str, incident_id: str | None, outcome: Outcome) -> dict:
        # Cette méthode permet de publier le résultat d'une demande, nommé par son identifiant (validé).
        payload = {"schema": PROTOCOL_VERSION, "request_id": request_id, "incident_id": incident_id,
                   "ok": outcome.ok, "status": outcome.status, "detail": outcome.detail,
                   "runner": self.name, "finished_at": self.clock()}
        write_json_atomic(outbox_fd, f"{RESULT_PREFIX}{request_id}.json", payload)
        return payload

    # ── Historique (limite de fréquence), dans le répertoire d'état ──

    def _history(self) -> list[float]:
        # Cette méthode permet de relire les heures de début des dernières restaurations.
        fd = _open_dir(self.state_dir)
        try:
            data = read_json_file(fd, "restores.json") or {}
        finally:
            os.close(fd)
        starts = data.get("starts", [])
        return [t for t in starts if type(t) in (int, float) and math.isfinite(t)] if isinstance(starts, list) else []

    def _save_history(self, starts: list[float]) -> None:
        # Cette méthode permet d'enregistrer le début d'une restauration (fichier root 0600).
        fd = _open_dir(self.state_dir)
        try:
            write_json_atomic(fd, "restores.json", {"starts": starts[-50:]}, mode=0o600)
        finally:
            os.close(fd)

    # ── Heartbeat et ménage ──

    def heartbeat(self, check_docker: bool = True) -> dict:
        # Cette méthode permet de signaler au moteur que le runner est là (et s'il restaure en ce moment).
        with bridge_dirs(self.bridge_dir) as (_, outbox_fd):
            return self._write_heartbeat(outbox_fd, check_docker)

    def _write_heartbeat(self, outbox_fd: int, check_docker: bool) -> dict:
        # Cette méthode permet d'écrire heartbeat.json ; docker_ok n'est recalculé qu'à la demande (timer), sinon la
        # dernière valeur connue de ce processus est reprise (absente pendant une restauration lancée par l'unité .path).
        active = self.lock.active()
        if check_docker and self.docker_check is not None:
            self._docker_ok = bool(self.docker_check())
        payload = {"schema": PROTOCOL_VERSION, "runner": self.name, "pid": os.getpid(), "written_at": self.clock(),
                   "busy": active is not None, "active_request_id": (active or {}).get("request_id"),
                   "max_restores_per_hour": self.policy.max_restores_per_hour}
        if self._docker_ok is not None:
            payload["docker_ok"] = self._docker_ok
        write_json_atomic(outbox_fd, HEARTBEAT_NAME, payload)
        return payload

    def cleanup(self) -> None:
        # Cette méthode permet de faire le ménage : demande jamais prise en charge (expirée, jamais exécutée en retard),
        # fichiers temporaires abandonnés par le moteur, anciens résultats.
        with bridge_dirs(self.bridge_dir) as (inbox_fd, outbox_fd):
            now = self.clock()
            try:
                pending = os.stat(REQUEST_NAME, dir_fd=inbox_fd, follow_symlinks=False)
            except FileNotFoundError:
                pending = None
            if pending is not None and now - pending.st_mtime > self.policy.max_age_s:
                self._take_request(inbox_fd, outbox_fd, expire_only=True)
            for name in os.listdir(inbox_fd):
                if name.startswith((ENGINE_TMP_PREFIX, QUARANTINE_PREFIX)):
                    self._unlink_if_old(inbox_fd, name, now, STALE_TMP_S)
            results = []
            for name in os.listdir(outbox_fd):
                if name.startswith(".") and name.endswith(".tmp"):
                    self._unlink_if_old(outbox_fd, name, now, STALE_TMP_S)
                elif name.startswith(RESULT_PREFIX) and name.endswith(".json"):
                    try:
                        results.append((os.stat(name, dir_fd=outbox_fd, follow_symlinks=False).st_mtime, name))
                    except FileNotFoundError:
                        continue
            results.sort(reverse=True)
            for index, (mtime, name) in enumerate(results):
                if index >= RESULTS_KEPT or now - mtime > RESULT_MAX_AGE_S:
                    self._unlink_if_old(outbox_fd, name, now, 0)

    @staticmethod
    def _unlink_if_old(dir_fd: int, name: str, now: float, max_age_s: float) -> None:
        # Cette méthode permet de supprimer une entrée (jamais un répertoire) plus ancienne que max_age_s.
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if not stat.S_ISDIR(st.st_mode) and now - st.st_mtime > max_age_s:
                os.unlink(name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass


# ───────────────────────────────── Exécution sur l'hôte (production) ─────────────────────────────────


def command_restorer(command: list[str], timeout_s: float) -> Callable[[], Outcome]:
    # Cette méthode permet de lancer la commande de restauration fixe (argv, sans shell) et d'interpréter sa sortie :
    # code 0 + JSON final = restaurée, 75 = verrou déjà pris, autre = échec avec la fin de la sortie.
    def restore() -> Outcome:
        # Cette méthode permet d'exécuter une restauration et d'en rendre le résultat ; le groupe est tué au délai dépassé.
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors="replace", start_new_session=True, cwd="/")
        try:
            output, _ = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            output, _ = proc.communicate()
            return Outcome(False, "timeout", {"error": "timeout", "timeout_s": timeout_s,
                                              "output_tail": output_tail(output)})
        if proc.returncode == 0:
            summary = parse_restore_summary(output.splitlines())
            if summary is not None:
                return Outcome(True, "restored", summary)
            return Outcome(False, "failed", {"error": "unparsable_output", "output_tail": output_tail(output)})
        if proc.returncode == EX_TEMPFAIL:
            return Outcome(False, "busy", {"error": "busy", "message": "restauration déjà en cours (verrou du script)"})
        return Outcome(False, "failed", {"error": "restore_failed", "exit_code": proc.returncode,
                                         "output_tail": output_tail(output)})

    return restore


def compose_probe(app_dir: Path, timeout_s: float = 60.0) -> Callable[[], str]:
    # Cette méthode permet d'interroger /internal/integrity depuis le conteneur payment-api (200, 409, unreachable…).
    def probe() -> str:
        # Cette méthode permet de rendre le code HTTP du contrôle d'intégrité, ou « unreachable ».
        try:
            proc = subprocess.run(["docker", "compose", "exec", "-T", "payment-api", "python", "-c", INTEGRITY_PROBE],
                                  cwd=os.path.realpath(app_dir), stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, timeout=timeout_s)
        except (OSError, subprocess.TimeoutExpired):
            return "unreachable"
        lines = proc.stdout.split()
        return lines[-1] if lines else "unreachable"

    return probe


def compose_docker_check(app_dir: Path, timeout_s: float = 30.0) -> Callable[[], bool]:
    # Cette méthode permet de vérifier, depuis l'unité durcie, que Docker et la stack répondent (conteneur postgres listé).
    def check() -> bool:
        # Cette méthode permet de rendre True si `docker compose ps` voit le conteneur postgres.
        try:
            proc = subprocess.run(["docker", "compose", "ps", "-q", "postgres"], cwd=os.path.realpath(app_dir),
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout_s)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0 and bool(proc.stdout.strip())

    return check


def main(argv: list[str] | None = None) -> int:
    # Cette méthode permet de lancer le runner depuis systemd : `process` (unité .path) ou `heartbeat` (timer).
    parser = argparse.ArgumentParser(description="Pont de remédiation : restauration PostgreSQL demandée par le moteur")
    parser.add_argument("command", choices=["process", "heartbeat"])
    parser.add_argument("--bridge-dir", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--engine-uid", type=int, action="append", required=True)
    parser.add_argument("--app-dir", type=Path, required=True, help="version active de la stack (…/current)")
    parser.add_argument("--restore-command", default="/usr/local/sbin/resilience-pg-restore")
    parser.add_argument("--restore-timeout", type=float, default=900.0)
    parser.add_argument("--max-restores-per-hour", type=int, default=3)
    args = parser.parse_args(argv)
    os.umask(0o077)
    runner = Runner(
        args.bridge_dir, args.state_dir,
        Policy(allowed_uids=frozenset(args.engine_uid), max_restores_per_hour=args.max_restores_per_hour),
        # Commande fixe : rien de la demande n'y entre
        restore=command_restorer([args.restore_command, "latest-healthy"], args.restore_timeout),
        probe=compose_probe(args.app_dir), docker_check=compose_docker_check(args.app_dir), name="systemd",
    )
    try:
        if args.command == "process":
            while runner.process_pending() is not None:
                pass
            runner.cleanup()
        else:
            runner.cleanup()
            runner.heartbeat(check_docker=True)
    except LayoutError as exc:
        log("layout_error", error=str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
