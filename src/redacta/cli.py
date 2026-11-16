"""Command line interface.

Key material is injected through the environment only; the key id is an
explicit non-secret label.  Neither the key nor any token-to-value mapping is
ever written into the audit database or a release package.
"""
import argparse
import json
import os

from .identity import PublicationError
from .release import Publisher
from .transforms import classify


def _load_key():
    material = os.environ.get("REDACTA_KEY", "").encode()
    key_id = os.environ.get("REDACTA_KEY_ID", "")
    if not material or not key_id:
        raise PublicationError(
            "set REDACTA_KEY (>=32 bytes) and REDACTA_KEY_ID via controlled injection")
    return key_id, material


def main():
    parser = argparse.ArgumentParser(description="Policy-controlled dataset publishing")
    parser.add_argument("--root", default="releases")
    parser.add_argument("--compat", choices=["legacy-v1"],
                        help="explicit compatibility policy for old unsigned releases")
    sub = parser.add_subparsers(dest="command", required=True)

    publish = sub.add_parser("publish", help="publish under a caller request id")
    publish.add_argument("input")
    publish.add_argument("policy")
    publish.add_argument("--request-id", required=True,
                         help="caller-supplied idempotency key")

    revoke = sub.add_parser("revoke", help="tombstone a release (terminal)")
    revoke.add_argument("release")

    read = sub.add_parser("read", help="read one table of an active release")
    read.add_argument("release")
    read.add_argument("table")

    sub.add_parser("recover", help="resolve interrupted releases after a crash")
    status = sub.add_parser("status", help="show release state and identity")
    status.add_argument("release")

    inspect = sub.add_parser("classify")
    inspect.add_argument("input")

    args = parser.parse_args()
    publisher = None
    try:
        if args.command == "classify":
            with open(args.input, encoding="utf-8") as stream:
                tables = json.load(stream)
            result = {name: [classify(row) for row in rows]
                      for name, rows in tables.items()}
        else:
            key_id, material = _load_key()
            publisher = Publisher(
                args.root, material, key_id=key_id,
                legacy_compat=(args.compat == "legacy-v1"))
            if args.command == "publish":
                with open(args.input, encoding="utf-8") as stream:
                    tables = json.load(stream)
                with open(args.policy, encoding="utf-8") as stream:
                    policy = json.load(stream)
                result = publisher.publish(tables, policy, args.request_id)
            elif args.command == "revoke":
                result = publisher.revoke(args.release)
            elif args.command == "read":
                if args.compat == "legacy-v1":
                    rows = publisher.read_legacy(args.release, args.table)
                else:
                    rows = publisher.read(args.release, args.table)
                result = {"table": args.table, "rows": rows}
            elif args.command == "recover":
                result = publisher.recover()
            else:
                result = publisher.status(args.release)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(2, f"error: {exc}\n")
    finally:
        if publisher:
            publisher.close()


if __name__ == "__main__":
    main()
