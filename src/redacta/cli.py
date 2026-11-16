import argparse
import json
import os
from .release import Publisher
from .transforms import classify


def main():
    parser = argparse.ArgumentParser(description="Policy-controlled dataset publishing")
    parser.add_argument("--root", default="releases")
    sub = parser.add_subparsers(dest="command", required=True)
    publish = sub.add_parser("publish")
    publish.add_argument("input")
    publish.add_argument("policy")
    revoke = sub.add_parser("revoke")
    revoke.add_argument("release")
    inspect = sub.add_parser("classify")
    inspect.add_argument("input")
    args = parser.parse_args()
    publisher = None
    try:
        if args.command == "classify":
            with open(args.input, encoding="utf-8") as stream:
                tables = json.load(stream)
            result = {name: [classify(row) for row in rows] for name, rows in tables.items()}
        else:
            publisher = Publisher(args.root, os.environ.get("REDACTA_KEY", "").encode())
            if args.command == "publish":
                with open(args.input, encoding="utf-8") as stream:
                    tables = json.load(stream)
                with open(args.policy, encoding="utf-8") as stream:
                    policy = json.load(stream)
                result = publisher.publish(tables, policy)
            else:
                publisher.revoke(args.release)
                result = {"revoked": args.release}
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(2, f"error: {exc}\n")
    finally:
        if publisher:
            publisher.close()


if __name__ == "__main__":
    main()
