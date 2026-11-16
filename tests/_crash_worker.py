"""Crash-injection worker used by the recovery test suite.

Runs in a *separate process* so ``os._exit`` simulates a real SIGKILL-style
termination without ``finally`` blocks or SQLite cleanup.  Key material is
passed through the environment only, never via argv or disk.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from redacta import Policy, Publisher  # noqa: E402


def main():
    root = sys.argv[1]
    request_id = sys.argv[2]
    crash_at = sys.argv[3] if len(sys.argv) > 3 else ""
    fixtures = Path(__file__).resolve().parents[1] / "examples"
    tables = json.loads((fixtures / "tables.json").read_text())
    policy_doc = json.loads((fixtures / "policy.json").read_text())
    key = os.environ["REDACTA_KEY"].encode()
    key_id = os.environ.get("REDACTA_KEY_ID", "k1")

    def kill(event, _release_id):
        if event == crash_at:
            sys.stderr.write(f"INJECTED CRASH at {event}\n")
            sys.stderr.flush()
            os._exit(99)

    publisher = Publisher(root, key, key_id=key_id)
    try:
        manifest = publisher.publish(
            tables, policy_doc, request_id,
            on_event=kill if crash_at else None)
        print(json.dumps({"id": manifest["id"]}))
    finally:
        publisher.close()


if __name__ == "__main__":
    main()
