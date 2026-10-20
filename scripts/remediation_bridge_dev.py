#!/usr/bin/env python3
"""DÉVELOPPEMENT UNIQUEMENT — runner local du pont de remédiation (jamais installé ni lancé sur la VM PC Hôte).

Sur un poste de développement, il n'y a ni unités systemd ni scripts /usr/local/sbin : ce script les remplace pour
tester de bout en bout la restauration automatique (EBIOS S5, registre incohérent). Il réutilise le code du runner de
l'hôte (ansible/files/resilience-remediation-bridge.py : protocole, validation, garde-fous) et remplace seulement
la restauration par un équivalent Python de resilience-pg-restore (docker compose exec pg_dump / pg_restore).

  python3 scripts/remediation_bridge_dev.py init      # crée .remediation-bridge/ — AVANT `docker compose up`
  python3 scripts/remediation_bridge_dev.py backup    # sauvegarde maintenant (.dev-backups/<horodatage>-manual)
  python3 scripts/remediation_bridge_dev.py run       # boucle : heartbeat, demandes du moteur, ménage (Ctrl-C)
  python3 scripts/remediation_bridge_dev.py restore   # restauration manuelle de la dernière sauvegarde saine
  python3 scripts/remediation_bridge_dev.py status    # sauvegardes locales et heartbeat

Sauvegardes dans .dev-backups/ (ignoré par git : les bases contiennent des empreintes de mots de passe).
Bibliothèque standard uniquement.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUNNER_FILE = REPO / "ansible" / "files" / "resilience-remediation-bridge.py"
DATABASES = ("authdb", "paydb")
BACKUPS_KEPT = 20


def _load_bridge():
    # Cette méthode permet d'importer le runner de l'hôte (nom de fichier à tirets) pour partager protocole et validation.
    spec = importlib.util.spec_from_file_location("resilience_remediation_bridge", RUNNER_FILE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bridge = _load_bridge()


class RestoreError(RuntimeError):
    """Échec d'une étape de la restauration locale."""


class Busy(RuntimeError):
    """Une restauration locale tient déjà le verrou."""


def say(message: str) -> None:
    # Cette méthode permet d'afficher une étape horodatée, comme le script de l'hôte.
    print(f"{time.strftime('%H:%M:%S', time.gmtime())} {message}", flush=True)


class DevStack:
    """Opérations Docker Compose sur la stack locale, équivalentes à resilience-pg-backup / resilience-pg-restore."""

    def __init__(self, project_dir: Path, backup_dir: Path):
        # Cette méthode permet de désigner le projet Compose et le répertoire des sauvegardes locales.
        self.project_dir = project_dir
        self.backup_dir = backup_dir

    def compose(self, *args: str, stdin=None, stdout=None, check: bool = True, timeout: float = 300):
        # Cette méthode permet de lancer `docker compose …` (argv fixe, jamais de shell) dans le projet.
        proc = subprocess.run(["docker", "compose", *args], cwd=self.project_dir, stdin=stdin,
                              stdout=stdout if stdout is not None else subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout)
        if check and proc.returncode != 0:
            err = proc.stderr.decode(errors="replace").strip().splitlines()[-3:]
            raise RestoreError(f"docker compose {' '.join(args[:2])} : code {proc.returncode} {' / '.join(err)}")
        return proc

    def integrity(self) -> str:
        # Cette méthode permet de rendre le code HTTP de /internal/integrity (200, 409) ou « unreachable ».
        try:
            proc = self.compose("exec", "-T", "payment-api", "python", "-c", bridge.INTEGRITY_PROBE,
                                stdin=subprocess.DEVNULL, check=False, timeout=60)
        except subprocess.TimeoutExpired:
            return "unreachable"
        out = proc.stdout.decode(errors="replace").split()
        return out[-1] if proc.returncode == 0 and out else "unreachable"

    def docker_ok(self) -> bool:
        # Cette méthode permet de vérifier que Docker répond et que le conteneur postgres existe.
        try:
            proc = self.compose("ps", "-q", "postgres", check=False, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0 and bool(proc.stdout.strip())

    # ── Sauvegarde ──

    def backup(self, kind: str = "manual") -> dict:
        # Cette méthode permet de sauvegarder authdb et paydb (pg_dump format custom) avec l'état d'intégrité du registre
        # relevé avant et après, les empreintes SHA-256 et meta.json : même format que resilience-pg-backup.
        self.backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        name = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{kind}"
        tmp = self.backup_dir / f".tmp-{name}"
        tmp.mkdir(mode=0o700)
        try:
            before = self.integrity()
            for db in DATABASES:
                with open(tmp / f"{db}.dump", "wb") as fh:
                    self.compose("exec", "-T", "-u", "postgres", "postgres", "pg_dump", "--format=custom",
                                 f"--dbname={db}", stdin=subprocess.DEVNULL, stdout=fh)
            after = self.integrity()
            if before == after == "200":
                status = "ok"
            elif "409" in (before, after):
                status = "corrupted"
            else:
                status = "unknown"
            sums = "".join(f"{_sha256(tmp / f'{db}.dump')}  {db}.dump\n" for db in DATABASES)
            (tmp / "SHA256SUMS").write_text(sums)
            meta = {"name": name, "kind": kind, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "release": "dev", "integrity": status,
                    "authdb_bytes": (tmp / "authdb.dump").stat().st_size,
                    "paydb_bytes": (tmp / "paydb.dump").stat().st_size}
            (tmp / "meta.json").write_text(json.dumps(meta) + "\n")
            tmp.rename(self.backup_dir / name)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self._retention()
        return meta

    def backups(self) -> list[tuple[Path, dict]]:
        # Cette méthode permet de lister les sauvegardes complètes, de la plus ancienne à la plus récente.
        found = []
        for meta_file in sorted(self.backup_dir.glob("2*/meta.json")):
            try:
                found.append((meta_file.parent, json.loads(meta_file.read_text())))
            except (OSError, ValueError):
                continue
        return found

    def latest_healthy(self) -> Path | None:
        # Cette méthode permet de choisir la plus récente sauvegarde dont le registre était cohérent, hors pre-restore.
        healthy = [path for path, meta in self.backups()
                   if meta.get("integrity") == "ok" and not path.name.endswith("-pre-restore")]
        return healthy[-1] if healthy else None

    def _retention(self) -> None:
        # Cette méthode permet de garder les BACKUPS_KEPT plus récentes, plus toujours la dernière saine.
        keep = self.latest_healthy()
        for path, _ in self.backups()[:-BACKUPS_KEPT]:
            if path != keep:
                shutil.rmtree(path, ignore_errors=True)

    # ── Restauration ──

    def restore(self, target: str = "latest-healthy") -> dict:
        # Cette méthode permet de restaurer comme resilience-pg-restore : empreintes vérifiées, état courant conservé
        # (pre-restore), API arrêtées, bases recréées (pg_restore --create), API relancées, registre contrôlé (200).
        self.backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        with open(self.backup_dir / ".restore.lock", "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy("restauration déjà en cours") from None
            return self._restore_locked(target)

    def _restore_locked(self, target: str) -> dict:
        # Cette méthode permet d'enchaîner les étapes de la restauration, verrou pris.
        if target == "latest-healthy":
            src = self.latest_healthy()
            if src is None:
                raise RestoreError(f"aucune sauvegarde saine dans {self.backup_dir}")
        else:
            if "/" in target or target.startswith("."):
                raise RestoreError(f"nom de sauvegarde invalide : {target}")
            src = self.backup_dir / target
            if not (src / "meta.json").is_file():
                raise RestoreError(f"sauvegarde introuvable : {target}")
        start = time.monotonic()
        say(f"sauvegarde choisie : {src.name}")
        for line in (src / "SHA256SUMS").read_text().splitlines():
            digest, _, filename = line.partition("  ")
            if filename not in {f"{db}.dump" for db in DATABASES} or _sha256(src / filename) != digest:
                raise RestoreError(f"empreinte SHA-256 incorrecte : {filename}")
        say("empreintes SHA-256 vérifiées")

        self.compose("up", "-d", "--wait", "--wait-timeout", "120", "postgres")
        try:
            say(f"état courant conservé : {self.backup('pre-restore')['name']}")
        except (RestoreError, OSError, subprocess.SubprocessError):
            say("état courant non sauvegardé (base illisible ?), restauration poursuivie")

        say("arrêt de auth-service et payment-api")
        self.compose("stop", "auth-service", "payment-api")
        for db in DATABASES:
            self.compose("exec", "-T", "-u", "postgres", "postgres", "dropdb", "--if-exists", "--force", db,
                         stdin=subprocess.DEVNULL)
            # --create recrée la base avec son propriétaire et ses droits (REVOKE … FROM PUBLIC compris)
            with open(src / f"{db}.dump", "rb") as dump:
                self.compose("exec", "-T", "-u", "postgres", "postgres", "pg_restore", "--create", "--exit-on-error",
                             "--dbname=postgres", stdin=dump)
            say(f"{db} restaurée")

        say("redémarrage de auth-service et payment-api")
        self.compose("up", "-d", "--wait", "--wait-timeout", "120", "auth-service", "payment-api")
        code = self.integrity()
        if code != "200":
            raise RestoreError(f"registre incohérent après restauration (HTTP {code})")
        say("registre cohérent après restauration")

        meta = json.loads((src / "meta.json").read_text())
        created = meta["created_at"]
        age = int(time.time() - dt.datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp())
        return {"restored": src.name, "backup_created_at": created, "backup_age_seconds": age,
                "restore_seconds": round(time.monotonic() - start, 1)}

    def restorer(self):
        # Cette méthode permet de fournir au runner partagé la restauration locale, convertie en Outcome.
        def restore() -> bridge.Outcome:
            # Cette méthode permet d'exécuter la restauration locale et d'en rendre le résultat pour le moteur.
            try:
                return bridge.Outcome(True, "restored", self.restore())
            except Busy:
                return bridge.Outcome(False, "busy", {"error": "busy", "message": "restauration locale déjà en cours"})
            except (RestoreError, OSError, subprocess.SubprocessError) as exc:
                say(f"échec de la restauration : {exc}")
                return bridge.Outcome(False, "failed", {"error": "restore_failed", "message": str(exc)[:300]})

        return restore


def _sha256(path: Path) -> str:
    # Cette méthode permet de calculer l'empreinte SHA-256 d'un fichier, par blocs.
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def init_bridge(bridge_dir: Path) -> None:
    # Cette méthode permet de créer le répertoire du pont avec les droits attendus, avant que Docker ne le crée (root).
    # inbox/ : 3773 = le moteur (uid 10001, « autres ») crée sa demande sans pouvoir lister ; sticky : personne ne
    # supprime le fichier d'un autre ; setgid : la demande prend notre groupe, donc reste lisible par ce runner.
    bridge_dir.mkdir(mode=0o755, exist_ok=True)
    st = bridge_dir.stat()
    if st.st_uid != os.getuid():
        sys.exit(f"{bridge_dir} appartient à l'uid {st.st_uid} (créé par Docker au montage ?). Corriger avec :\n"
                 f"  sudo chown {os.getuid()}:{os.getgid()} {bridge_dir}\n"
                 f"puis relancer `init` et recréer le moteur (docker compose up -d --force-recreate remediation-engine).")
    os.chmod(bridge_dir, 0o755)
    for name, mode in ((bridge.INBOX, 0o3773), (bridge.OUTBOX, 0o755)):
        path = bridge_dir / name
        path.mkdir(exist_ok=True)
        os.chmod(path, mode)


def build_runner(args: argparse.Namespace, stack: DevStack):
    # Cette méthode permet d'assembler le runner partagé avec la restauration locale.
    state_dir = args.backup_dir / "runner-state"
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    policy = bridge.Policy(allowed_uids=frozenset({args.engine_uid, os.getuid()}),
                           max_restores_per_hour=args.max_restores_per_hour)
    return bridge.Runner(args.bridge_dir, state_dir, policy, restore=stack.restorer(), probe=stack.integrity,
                         name="dev", docker_check=stack.docker_ok)


def run_loop(args: argparse.Namespace, stack: DevStack) -> None:
    # Cette méthode permet de jouer le rôle de l'unité .path et du timer : demandes toutes les 0,5 s, heartbeat
    # toutes les 10 s (Docker vérifié toutes les 30 s), ménage toutes les minutes.
    init_bridge(args.bridge_dir)
    runner = build_runner(args, stack)
    say(f"runner de développement prêt : {args.bridge_dir} (uid moteur accepté : {args.engine_uid}, Ctrl-C pour arrêter)")
    last_beat = last_docker = last_cleanup = 0.0
    while True:
        while (result := runner.process_pending()) is not None:
            say(f"demande {result['request_id']} : {result['status']} {json.dumps(result['detail'], ensure_ascii=False)}")
        now = time.monotonic()
        if now - last_beat >= 10:
            check = now - last_docker >= 30
            runner.heartbeat(check_docker=check)
            last_beat, last_docker = now, (now if check else last_docker)
        if now - last_cleanup >= 60:
            runner.cleanup()
            last_cleanup = now
        if args.once:
            return
        time.sleep(0.5)


def main() -> int:
    # Cette méthode permet de lancer une sous-commande du runner de développement.
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["init", "backup", "run", "restore", "status"])
    parser.add_argument("target", nargs="?", default="latest-healthy", help="restore : nom de sauvegarde")
    parser.add_argument("--bridge-dir", type=Path,
                        default=Path(os.environ.get("REMEDIATION_BRIDGE_DIR") or REPO / ".remediation-bridge"))
    parser.add_argument("--backup-dir", type=Path, default=REPO / ".dev-backups")
    parser.add_argument("--project-dir", type=Path, default=REPO)
    parser.add_argument("--engine-uid", type=int, default=int(os.environ.get("REMEDIATION_ENGINE_UID", "10001")))
    parser.add_argument("--max-restores-per-hour", type=int, default=6, help="0 = sans limite")
    parser.add_argument("--once", action="store_true", help="run : un seul passage (tests)")
    args = parser.parse_args()
    args.bridge_dir = (REPO / args.bridge_dir).resolve() if not args.bridge_dir.is_absolute() else args.bridge_dir
    os.umask(0o077)
    stack = DevStack(args.project_dir, args.backup_dir)

    if args.command == "init":
        init_bridge(args.bridge_dir)
        print(f"pont prêt : {args.bridge_dir}")
    elif args.command == "backup":
        print(json.dumps(stack.backup("manual")))
    elif args.command == "restore":
        try:
            print(json.dumps(stack.restore(args.target)))
        except (RestoreError, Busy) as exc:
            print(f"échec : {exc}", file=sys.stderr)
            return 1
    elif args.command == "status":
        for path, meta in stack.backups():
            print(f"{path.name}  registre {meta.get('integrity')}")
        heartbeat = args.bridge_dir / bridge.OUTBOX / bridge.HEARTBEAT_NAME
        print(f"heartbeat : {heartbeat.read_text().strip() if heartbeat.is_file() else 'absent'}")
    else:
        try:
            run_loop(args, stack)
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
