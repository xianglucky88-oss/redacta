"""Black-box publish/read/revoke smoke test against an *installed* Redacta.

Run with the isolated venv's interpreter and ``-I``.  The source tree is never
on sys.path: the import origin is asserted to be the venv's site-packages.
The REDACTA_KEY comes from the scrubbed subprocess environment only.
"""
import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    fixtures = Path(sys.argv[1])
    work = Path(sys.argv[2])
    work.mkdir(parents=True, exist_ok=True)
    root = work / "releases"

    import redacta
    origin = Path(redacta.__file__)
    if "site-packages" not in origin.parts:
        raise RuntimeError(f"redacta imported from non-install location: {origin}")
    if str(Path(fixtures).resolve()).startswith(str(origin.resolve().parents[0])):
        raise RuntimeError("install root overlaps the fixture/source tree")
    from redacta import Publisher

    key = os.environ.get("REDACTA_KEY", "")
    if len(key.encode()) < 32:
        raise RuntimeError("REDACTA_KEY missing or shorter than 32 bytes")

    def cli(*args):
        completed = subprocess.run(
            [sys.executable, "-I", "-m", "redacta.cli", "--root", str(root), *map(str, args)],
            check=True, capture_output=True, text=True,
            env={k: os.environ[k] for k in ("PATH", "LANG", "REDACTA_KEY",
                                            "SETUPTOOLS_USE_DISTUTILS",
                                            "PYTHONDONTWRITEBYTECODE")
                 if k in os.environ},
        )
        return json.loads(completed.stdout), completed

    result, publish_proc = cli("publish", fixtures / "tables.json", fixtures / "policy.json")
    publisher = Publisher(root, key.encode())
    try:
        people = publisher.read(result["id"], "people")
        visits = publisher.read(result["id"], "visits")
        if (len(people), len(visits)) != (2, 1):
            raise RuntimeError("suppression semantics changed")
        if visits[0]["person_id"] != people[0]["id"]:
            raise RuntimeError("cross-table token join broken")
        package = " ".join(p.read_text() for p in (root / result["id"]).glob("*"))
        if "alice@example.test" in package or "bob@example.test" in package:
            raise RuntimeError("raw email leaked into release package")
        _, revoke_proc = cli("revoke", result["id"])
        try:
            publisher.read(result["id"], "people")
        except ValueError:
            pass
        else:
            raise RuntimeError("revoked release still readable")
        if (root / result["id"]).exists():
            raise RuntimeError("revoked files still present")
    finally:
        publisher.close()

    out = {
        "ok": True,
        "import_origin": str(origin),
        "release_id": result["id"],
        "people": 2,
        "visits": 1,
        "tokens_join": True,
        "revoked": True,
        "cli_exit_codes": {"publish": publish_proc.returncode,
                           "revoke": revoke_proc.returncode},
        "key_was_env_only": True,
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
