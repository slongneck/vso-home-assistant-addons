#!/usr/bin/env python3
"""Independent, on-demand SMB fallback for completed HA backup archives."""

from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import logging
import os
import pathlib
import shutil
import subprocess
import threading
import time
from urllib.parse import urlparse


DATA = pathlib.Path("/data")
SOURCE = pathlib.Path("/backup")
MANIFEST = DATA / "manifest.json"
STATUS = DATA / "status.json"
CONFIG = pathlib.Path("/data/options.json")
SECRETS = pathlib.Path(
    os.environ.get("HA_CONFIG_DIR", "/homeassistant")
) / "secrets.yaml"


def read_options() -> dict:
    with CONFIG.open(encoding="utf-8") as handle:
        return json.load(handle)


def read_secret(name: str) -> str:
    """Read one simple secrets.yaml scalar without exposing it in logs."""
    prefix = f"{name}:"
    for line in SECRETS.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            value = line[len(prefix):].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            return value
    raise RuntimeError(f"Secret key not found: {name}")


def load_json(path: pathlib.Path, default):
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: pathlib.Path, value) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class TransferService:
    def __init__(self) -> None:
        self.options = read_options()
        self.lock = threading.Lock()
        self.manifest = load_json(MANIFEST, {})
        self.status = load_json(STATUS, {"state": "idle", "last_error": None})
        self.logger = logging.getLogger("vso-fallback")
        self._configure_logging()

    def _configure_logging(self) -> None:
        logging.basicConfig(
            level=getattr(logging, str(self.options.get("log_level", "INFO"))),
            format="%(asctime)s %(levelname)s %(message)s",
        )

    def _set_status(self, **values) -> None:
        self.status.update(values)
        save_json(STATUS, self.status)

    def _smb_context(self) -> tuple[pathlib.Path, list[str], pathlib.PurePosixPath]:
        username = read_secret(self.options["username_secret"])
        password = read_secret(self.options["password_secret"])
        credentials = DATA / "credentials"
        credentials.write_text(
            f"username={username}\npassword={password}\n", encoding="utf-8"
        )
        os.chmod(credentials, 0o600)
        remote = f"//{self.options['vault_host']}/{self.options['vault_share']}"
        subpath = pathlib.PurePosixPath(self.options["vault_subpath"])
        if subpath.is_absolute() or ".." in subpath.parts:
            raise RuntimeError("vault_subpath must remain inside the SMB share")
        return credentials, ["smbclient", remote, "-A", str(credentials), "-m", "SMB3", "-D", str(subpath)], subpath

    def copy_latest(self) -> dict:
        with self.lock:
            candidates = sorted(
                (
                    path
                    for path in SOURCE.glob("*.tar")
                    if not path.name.startswith("vso_vault_backup_fallback_")
                ),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            if not candidates:
                raise RuntimeError("No completed .tar backup exists in /backup")
            source = candidates[0]
            source_hash = sha256(source)
            key = source.name
            if self.manifest.get(key, {}).get("sha256") == source_hash:
                self._set_status(state="already_present", backup=key, last_error=None)
                return self.status

            self._set_status(state="connecting", backup=key, last_error=None)
            _, smb_command, subpath = self._smb_context()
            temporary_name = f".{source.name}.partial"
            target = subpath.joinpath(source.name)
            self._set_status(state="copying", backup=key, target=str(target))
            existing = subprocess.run(
                smb_command + ["-c", f'dir "{source.name}"'],
                check=False,
                capture_output=True,
                text=True,
            )
            if existing.returncode == 0:
                self.manifest[key] = {
                    "sha256": source_hash,
                    "size": source.stat().st_size,
                    "target": str(target),
                    "copied_at": int(time.time()),
                }
                self._prune()
                save_json(MANIFEST, self.manifest)
                self._set_status(state="already_present", backup=key, target=str(target), last_error=None)
                return self.status
            subprocess.run(
                smb_command + ["-c", f'del "{temporary_name}"'],
                check=False,
                capture_output=True,
                text=True,
            )
            put = subprocess.run(
                smb_command + ["-c", f'put "{source}" "{temporary_name}"'],
                check=False,
                capture_output=True,
                text=True,
            )
            if put.returncode != 0:
                detail = put.stderr.strip() or put.stdout.strip() or "no SMB diagnostic"
                raise RuntimeError(f"SMB copy failed ({put.returncode}): {detail}")
            rename = subprocess.run(
                smb_command + ["-c", f'rename "{temporary_name}" "{source.name}"'],
                check=False,
                capture_output=True,
                text=True,
            )
            if rename.returncode != 0:
                detail = rename.stderr.strip() or rename.stdout.strip() or "no SMB diagnostic"
                raise RuntimeError(f"SMB publish failed ({rename.returncode}): {detail}")
            self.manifest[key] = {
                "sha256": source_hash,
                "size": source.stat().st_size,
                "target": str(target),
                "copied_at": int(time.time()),
            }
            self._prune()
            save_json(MANIFEST, self.manifest)
            self._set_status(state="copied", backup=key, target=str(target), last_error=None)
            return self.status

    def _prune(self) -> None:
        retention = max(1, int(self.options.get("retention", 12)))
        entries = sorted(
            self.manifest.items(), key=lambda item: item[1].get("copied_at", 0), reverse=True
        )
        stale_entries = [
            (name, entry)
            for name, entry in entries
            if name.startswith("vso_vault_backup_fallback_")
        ]
        for name, entry in stale_entries + entries[retention:]:
            target = pathlib.Path(entry["target"])
            try:
                target.unlink(missing_ok=True)
            except OSError as error:
                self.logger.warning("Could not remove old Vault backup %s: %s", name, error)
            self.manifest.pop(name, None)

    def trigger(self) -> dict:
        try:
            return self.copy_latest()
        except Exception as error:  # noqa: BLE001 - status API must survive transfer errors
            self.logger.error("Fallback transfer failed: %s", error)
            self._set_status(state="failed", last_error=str(error))
            raise

    def authorized(self, supplied: str | None) -> bool:
        if not supplied:
            return False
        expected = read_secret(self.options["api_token_secret"])
        return hmac.compare_digest(supplied, expected)


service: TransferService | None = None


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        assert service is not None
        parsed = urlparse(self.path)
        if parsed.path == "/status":
            self._json(200, service.status)
            return
        if parsed.path == "/trigger":
            if not service.authorized(self.headers.get("X-VSO-Token")):
                self._json(401, {"error": "unauthorized"})
                return
            if service.status.get("state") in {"mounting", "copying"}:
                self._json(409, {"state": "already_running"})
                return
            threading.Thread(target=service.trigger, daemon=True).start()
            self._json(202, {"state": "queued"})
            return
        self._json(404, {"error": "not found"})

    def _json(self, status: int, value: dict) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    global service
    service = TransferService()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8124), Handler)
    logging.getLogger("vso-fallback").info("VSO fallback API listening on port 8124")
    server.serve_forever()


if __name__ == "__main__":
    main()
