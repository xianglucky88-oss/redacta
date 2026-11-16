import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from redacta import Publisher

project = Path(__file__).resolve().parents[1]
key = secrets.token_hex(32)
env = dict(os.environ, PYTHONPATH=str(project / "src"), REDACTA_KEY=key)


def cli(root, *args):
    completed = subprocess.run([sys.executable, "-m", "redacta.cli", "--root", str(root), *map(str, args)],
                               env=env, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory) / "releases"
    result = cli(root, "publish", project / "examples" / "tables.json", project / "examples" / "policy.json")
    publisher = Publisher(root, key.encode())
    try:
        people = publisher.read(result["id"], "people")
        visits = publisher.read(result["id"], "visits")
        if len(people) != 2 or len(visits) != 1: raise RuntimeError("suppression failed")
        if visits[0]["person_id"] != people[0]["id"]: raise RuntimeError("cross-table link broken")
        package = " ".join(path.read_text() for path in (root / result["id"]).glob("*"))
        if "alice@example.test" in package or "bob@example.test" in package: raise RuntimeError("raw email leaked")
        cli(root, "revoke", result["id"])
        try: publisher.read(result["id"], "people")
        except ValueError: pass
        else: raise RuntimeError("revoked release still readable")
        if (root / result["id"]).exists(): raise RuntimeError("revoked files still present")
    finally:
        publisher.close()
    print(json.dumps({"ok": True, "people": 2, "visits": 1, "tokens_join": True, "revoked": True, "cli_processes": 2}))
