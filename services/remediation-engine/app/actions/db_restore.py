"""Restauration de la base demandée à l'hôte par un pont de fichiers (EBIOS S5, registre de paiement incohérent).

Le moteur tourne dans un conteneur non privilégié (uid 10001), sans socket Docker brut : il n'exécute rien lui-même.
Il dépose une demande dans le répertoire du pont (monté en /bridge) ; un runner de l'hôte (unité systemd .path sur la
VM, scripts/remediation_bridge_dev.py en développement) la valide, lance `resilience-pg-restore latest-healthy`
(une seule à la fois, seulement si /internal/integrity répond 409) et écrit le résultat.

  inbox/request.json               demande (écrite dans inbox/.request-<id>.tmp, 0640, puis renommée)
  outbox/result-<request_id>.json  résultat écrit par le runner
  outbox/heartbeat.json            présence du runner, rafraîchi toutes les 30 s ; périmé au-delà de 120 s

Côté hôte : ansible/files/resilience-remediation-bridge.py. Protocole et modèle de sécurité :
docs/runbooks/restauration-base.md, « Restauration automatique ». Bibliothèque standard uniquement.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

PROTOCOL_VERSION = 1
ACTION_RESTORE = "restore-latest-healthy"
REQUESTED_BY = "remediation-engine"
INBOX = "inbox"
OUTBOX = "outbox"
REQUEST_NAME = "request.json"
HEARTBEAT_NAME = "heartbeat.json"
HEARTBEAT_MAX_AGE_S = 120.0
CLOCK_SKEW_S = 30.0
MAX_FILE_BYTES = 64 * 1024
# Même contrainte que le runner : l'identifiant d'incident voyage dans du JSON, jamais dans une commande
INCIDENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
SUMMARY_KEYS = ("restored", "backup_created_at", "backup_age_seconds", "restore_seconds")

logger = logging.getLogger(__name__)


@dataclass
class RestoreResult:
    ok: bool
    detail: dict        # succès : JSON de resilience-pg-restore (+ request_id, status) ; échec : {"error": <code>, …}
    duration_s: float   # mesuré par le moteur, du dépôt de la demande à la lecture du résultat


def _read_json(path: Path, max_bytes: int = MAX_FILE_BYTES) -> dict | None:
    # Cette méthode permet de lire un fichier JSON du pont sans suivre de lien ni bloquer sur une FIFO, taille bornée ;
    # None s'il est absent, illisible ou invalide.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        chunks, total = [], 0
        while chunk := os.read(fd, max_bytes + 1 - total):
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                return None
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        value = json.loads(b"".join(chunks))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _number(value: object) -> float | None:
    # Cette méthode permet de n'accepter qu'un nombre fini (pas un booléen, pas NaN).
    if type(value) in (int, float) and math.isfinite(value):
        return float(value)
    return None


class RestoreBridge:
    """Client du pont de restauration : écrit la demande, attend le résultat, n'exécute jamais rien lui-même."""

    def __init__(self, bridge_dir: Path, timeout_s: float = 300.0, *, poll_interval_s: float = 0.5,
                 pickup_timeout_s: float = 30.0, heartbeat_max_age_s: float = HEARTBEAT_MAX_AGE_S):
        # Cette méthode permet de configurer le pont : répertoire monté (/bridge), délai total d'une restauration,
        # délai de prise en charge (au-delà, la demande est retirée pour ne jamais être exécutée en retard).
        self.bridge_dir = Path(bridge_dir)
        self.timeout_s = timeout_s
        self.poll_interval_s = poll_interval_s
        self.pickup_timeout_s = pickup_timeout_s
        self.heartbeat_max_age_s = heartbeat_max_age_s
        self._in_flight: str | None = None

    @property
    def in_flight(self) -> str | None:
        # Cette méthode permet au moteur de savoir qu'une restauration est en cours (identifiant de la demande) :
        # auth-service et payment-api sont alors volontairement arrêtés, il ne faut pas les « réparer ».
        return self._in_flight

    def heartbeat(self) -> dict | None:
        # Cette méthode permet de lire le dernier heartbeat du runner de l'hôte (None s'il manque ou est invalide).
        value = _read_json(self.bridge_dir / OUTBOX / HEARTBEAT_NAME)
        return value if value is not None and value.get("schema") == PROTOCOL_VERSION else None

    def _heartbeat_age(self, heartbeat: dict | None) -> float | None:
        # Cette méthode permet de calculer l'âge du heartbeat (horloge de l'hôte, partagée par les conteneurs).
        written_at = _number((heartbeat or {}).get("written_at"))
        return None if written_at is None else time.time() - written_at

    def _is_available(self, heartbeat: dict | None) -> bool:
        # Cette méthode permet de juger un heartbeat : frais (< 120 s) et Docker joignable si le runner l'a vérifié.
        age = self._heartbeat_age(heartbeat)
        return (age is not None and -CLOCK_SKEW_S <= age < self.heartbeat_max_age_s
                and heartbeat.get("docker_ok", True) is not False)

    def available(self) -> bool:
        # Cette méthode permet de savoir si un runner de l'hôte est présent (heartbeat frais de moins de 120 s).
        return self._is_available(self.heartbeat())

    def status(self) -> dict:
        # Cette méthode permet d'exposer l'état du pont à l'API d'état du moteur (tableau de supervision).
        heartbeat = self.heartbeat()
        age = self._heartbeat_age(heartbeat)
        heartbeat = heartbeat or {}
        return {
            "available": self._is_available(heartbeat or None),
            "runner": heartbeat.get("runner"),
            "heartbeat_age_s": None if age is None else round(age, 1),
            "busy": bool(heartbeat.get("busy")) or self._in_flight is not None,
            "active_request_id": heartbeat.get("active_request_id"),
            "in_flight_request_id": self._in_flight,
        }

    async def request_restore(self, incident_id: str) -> RestoreResult:
        # Cette méthode permet de demander la restauration de la dernière sauvegarde saine et d'en attendre le résultat ;
        # une seule demande à la fois (« busy » sinon), jamais d'exécution locale.
        start = time.monotonic()

        def finish(ok: bool, detail: dict) -> RestoreResult:
            # Cette méthode permet de construire le résultat avec la durée mesurée par le moteur.
            return RestoreResult(ok, detail, round(time.monotonic() - start, 3))

        if self._in_flight is not None:
            return finish(False, {"error": "busy", "active_request_id": self._in_flight})
        if not isinstance(incident_id, str) or not INCIDENT_ID_RE.fullmatch(incident_id):
            return finish(False, {"error": "invalid_incident_id"})
        heartbeat = self.heartbeat()
        if not self._is_available(heartbeat):
            age = self._heartbeat_age(heartbeat)
            return finish(False, {"error": "runner_unavailable",
                                  "heartbeat_age_s": None if age is None else round(age, 1)})
        if heartbeat.get("busy"):
            return finish(False, {"error": "busy", "active_request_id": heartbeat.get("active_request_id")})

        request_id = uuid.uuid4().hex
        self._in_flight = request_id
        try:
            try:
                inode = self._write_request(request_id, incident_id)
            except FileExistsError:
                return finish(False, {"error": "busy", "message": "une demande attend déjà dans inbox/"})
            except OSError as exc:
                return finish(False, {"error": "bridge_write_failed", "message": exc.strerror or type(exc).__name__})
            logger.info("restore_requested", extra={"event_type": "remediation_restore_requested",
                                                    "incident_id": incident_id, "request_id": request_id})
            ok, detail = await self._wait_result(request_id, incident_id, inode, start)
            result = finish(ok, detail)
            logger.info("restore_result", extra={"event_type": "remediation_restore_result", "incident_id": incident_id,
                                                 "request_id": request_id, "ok": ok, "error": detail.get("error"),
                                                 "duration_s": result.duration_s})
            return result
        finally:
            self._in_flight = None

    def _write_request(self, request_id: str, incident_id: str) -> int:
        # Cette méthode permet de déposer la demande atomiquement (temporaire puis renommage) et d'en rendre l'inode,
        # pour reconnaître plus tard notre fichier ; FileExistsError si une demande attend déjà.
        inbox = self.bridge_dir / INBOX
        final = inbox / REQUEST_NAME
        if os.path.lexists(final):
            raise FileExistsError(final)
        payload = {"schema": PROTOCOL_VERSION, "action": ACTION_RESTORE, "request_id": request_id,
                   "incident_id": incident_id, "created_at": time.time(), "requested_by": REQUESTED_BY}
        tmp = inbox / f".request-{request_id}.tmp"
        # 0640 : le répertoire inbox/ (setgid, groupe root) rend la demande lisible par le runner sans CAP_DAC_OVERRIDE
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        try:
            os.fchmod(fd, 0o640)
            os.write(fd, json.dumps(payload).encode())
            os.fsync(fd)
            inode = os.fstat(fd).st_ino
        finally:
            os.close(fd)
        try:
            os.rename(tmp, final)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        return inode

    def _pending(self, inode: int) -> bool:
        # Cette méthode permet de savoir si notre demande attend encore dans inbox/ (pas encore prise en charge).
        try:
            return os.stat(self.bridge_dir / INBOX / REQUEST_NAME, follow_symlinks=False).st_ino == inode
        except OSError:
            return False

    def _withdraw(self, inode: int) -> bool:
        # Cette méthode permet de retirer une demande jamais prise en charge ; False si le runner l'a prise entre-temps.
        if not self._pending(inode):
            return False
        try:
            (self.bridge_dir / INBOX / REQUEST_NAME).unlink()
        except FileNotFoundError:
            return False
        return True

    async def _wait_result(self, request_id: str, incident_id: str, inode: int, start: float) -> tuple[bool, dict]:
        # Cette méthode permet d'attendre le fichier de résultat sans bloquer la boucle asyncio.
        result_path = self.bridge_dir / OUTBOX / f"result-{request_id}.json"
        picked_up = False
        while True:
            data = _read_json(result_path)
            if data is not None:
                return self._parse_result(data, request_id, incident_id)
            elapsed = time.monotonic() - start
            if not picked_up:
                if not self._pending(inode):
                    picked_up = True
                elif elapsed >= self.pickup_timeout_s and self._withdraw(inode):
                    # Lue par le runner à l'instant même du retrait : il l'annonce dans son heartbeat ou y répond
                    await asyncio.sleep(self.poll_interval_s)
                    taken = (self.heartbeat() or {}).get("active_request_id") == request_id
                    if not taken and _read_json(result_path) is None:
                        return False, {"error": "not_picked_up", "request_id": request_id,
                                       "message": "aucun runner n'a pris la demande : retirée, jamais exécutée"}
                    picked_up = True
            if elapsed >= self.timeout_s:
                return False, {"error": "timeout", "request_id": request_id, "picked_up": picked_up,
                               "timeout_s": self.timeout_s}
            await asyncio.sleep(self.poll_interval_s)

    @staticmethod
    def _parse_result(data: dict, request_id: str, incident_id: str) -> tuple[bool, dict]:
        # Cette méthode permet de valider le résultat écrit par le runner et d'en extraire le détail utile.
        if data.get("request_id") != request_id or data.get("incident_id") not in (incident_id, None):
            return False, {"error": "result_mismatch", "request_id": request_id}
        raw = data.get("detail")
        detail = dict(raw) if isinstance(raw, dict) else {}
        status = data.get("status") if isinstance(data.get("status"), str) else "unknown"
        detail.update(request_id=request_id, status=status)
        if data.get("ok") is not True:
            detail.setdefault("error", status)
            return False, detail
        if not all(key in detail for key in SUMMARY_KEYS) or _number(detail.get("restore_seconds")) is None:
            return False, {"error": "invalid_result", "request_id": request_id, "status": status}
        return True, detail
