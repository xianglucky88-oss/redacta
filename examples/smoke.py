import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from redacta import KeyRing, Publisher

project = Path(__file__).resolve().parents[1]
key = secrets.token_hex(32)
env = dict(os.environ, PYTHONPATH=str(project / "src"),
           REDACTA_KEY=key, REDACTA_KEY_ID="smoke-k1")


def cli(root, *args):
    completed = subprocess.run(
        [sys.executable, "-m", "redacta.cli", "--root", str(root), *map(str, args)],
        env=env, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory) / "releases"
    request_id = "smoke-request-0001"
    result = cli(root, "publish",
                 project / "examples" / "tables.json",
                 project / "examples" / "policy.json",
                 "--request-id", request_id)
    assert result["request_id"] == request_id
    release_id = result["id"]

    # Retrying the same request id returns the original release, not a new one.
    retry = cli(root, "publish",
                project / "examples" / "tables.json",
                project / "examples" / "policy.json",
                "--request-id", request_id)
    assert retry["id"] == release_id, "request id must be idempotent"

    publisher = Publisher(root, key_ring=KeyRing.single("smoke-k1", key.encode()))
    try:
        people = publisher.read(request_id, "people")
        visits = publisher.read(release_id, "visits")
        if len(people) != 2 or len(visits) != 1:
            raise RuntimeError("suppression fixed point failed")
        if visits[0]["person_id"] != people[0]["id"]:
            raise RuntimeError("cross-table link broken")
        package = " ".join(path.read_text()
                           for path in (root / release_id).glob("*"))
        if "alice@example.test" in package or "bob@example.test" in package:
            raise RuntimeError("raw email leaked")
        if key.encode() in (root / "audit.sqlite").read_bytes():
            raise RuntimeError("raw key material persisted")

        # Key rotation keeps the old release's identity and readability.
        rotated = Publisher(
            root, key_ring=KeyRing(
                {"smoke-k1": key.encode(),
                 "smoke-k2": secrets.token_hex(32).encode()},
                active_key_id="smoke-k2"))
        rotated.close()

        status = cli(root, "status", request_id)
        assert status["key_id"] == "smoke-k1"

        cli(root, "revoke", request_id)
        try:
            publisher.read(request_id, "people")
        except Exception:
            pass
        else:
            raise RuntimeError("revoked release still readable")
        if (root / release_id).exists():
            raise RuntimeError("revoked files still present")
        # Recovery must not resurrect a tombstone.
        report = publisher.recover()
        assert report["revoked_dirs_removed"] == []
        assert publisher.status(request_id)["status"] == "revoked"
    finally:
        publisher.close()
    print(json.dumps({
        "ok": True, "people": 2, "visits": 1, "tokens_join": True,
        "idempotent_retry": True, "authenticated_manifest": True,
        "revoked": True, "cli_processes": 3,
    }))
