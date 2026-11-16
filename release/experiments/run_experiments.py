#!/usr/bin/env python3
"""Contamination experiments for the offline release gate.

Each experiment copies the *clean* repository into an isolated sandbox,
injects a non-sensitive canary through a specific evasion channel, runs the
gate and asserts:

* negative cases  -> the gate exits non-zero at the documented stage, no
                     canary byte reaches any artifact, log, report or the
                     accepted/ directory;
* positive control -> a clean tree passes and canaries planted only in the
                      environment or in non-source residue never leak.

Re-running this script always performs fresh builds; reports are keyed by
artifact hashes and run ids, so a previous "pass" can never satisfy a run.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

EXPERIMENTS_DIR = Path(__file__).resolve().parent
GATE_DIR = EXPERIMENTS_DIR.parent / "gate"
PROJECT_ROOT = GATE_DIR.parents[1]
sys.path.insert(0, str(GATE_DIR))
from gate_lib import CANARIES_PATH, MANIFEST_PATH  # noqa: E402

CANARIES = json.loads(CANARIES_PATH.read_text(encoding="utf-8"))["canaries"]
SECRET = next(c for c in CANARIES if c["kind"] == "secret")
RECORD = next(c for c in CANARIES if c["kind"] == "data")
TOKENS = [c["value"] for c in CANARIES]
CANARY_FILES = set()
for item in CANARIES:
    CANARY_FILES.update(item.get("scan_filenames", []))

RECORDS_DIR = PROJECT_ROOT / "release" / "experiments" / "records"


def clean_sandbox(base: Path) -> Path:
    """Materialise a clean, gate-executable repository copy without .git."""
    src = base / "repo"
    # Only VCS data and Python caches are skipped; the whole release/ tree
    # (including the gate and its wheelhouse) must travel with the sandbox.
    # __pycache__ removal is mandatory: stale bytecode from the host must
    # never reach the sandbox's admission stage.
    ignore = shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "*.pyo",
                                    "dist", "build", "*.egg-info")
    shutil.copytree(PROJECT_ROOT, src, ignore=ignore)
    for leftover in src.rglob("__pycache__"):
        shutil.rmtree(leftover, ignore_errors=True)
    # Every sandbox starts without previous gate outputs, so a stale accept
    # can never satisfy the current run.
    for relative in ("release/gate/runs", "release/gate/accepted",
                     "release/gate/quarantine", "release/gate/reports",
                     "release/experiments/records"):
        shutil.rmtree(src / relative, ignore_errors=True)
    return src


def run_gate(repo: Path, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    gate = repo / "release" / "gate" / "gate_run.py"
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("REDACTA_") and "CANARY" not in k}
    env.update(extra_env or {})
    return subprocess.run([sys.executable, gate], cwd=repo, env=env,
                          capture_output=True, text=True, timeout=900)


def scan_tree(root: Path) -> list[str]:
    """Return canary hits (token bytes or canary filenames) under ``root``."""
    hits: list[str] = []
    for current, dirs, files in os.walk(root):
        for name in files:
            path = Path(current) / name
            if name in CANARY_FILES:
                hits.append(f"canary-filename:{path.relative_to(root)}")
            try:
                blob = path.read_bytes()
            except OSError:
                continue
            for token in TOKENS:
                if token.encode() in blob:
                    hits.append(f"canary-token:{path.relative_to(root)}")
    return hits


def expect_block(result: subprocess.CompletedProcess, stage_tokens: tuple[str, ...],
                 repo: Path, case_id: str) -> dict:
    """Accept rejection at any of the documented admission/audit rule ids."""
    detail = {"exit_code": result.returncode}
    if result.returncode == 0:
        detail["problem"] = "gate unexpectedly accepted contaminated tree"
        return detail
    combined = result.stdout + result.stderr
    if not any(token in combined for token in stage_tokens):
        detail["problem"] = (f"gate failed but at none of the expected rules "
                             f"{stage_tokens!r}")
        detail["tail"] = combined[-400:]
        return detail
    accepted = repo / "release" / "gate" / "accepted"
    if accepted.exists() and any(accepted.rglob("*")):
        detail["problem"] = "accepted/ populated despite rejection"
        return detail
    # Quarantine + reports exist for forensics but must not contain canaries.
    for area in ("quarantine", "reports", "runs"):
        root = repo / "release" / "gate" / area
        if root.exists():
            hits = scan_tree(root)
            if hits:
                detail["problem"] = f"canary reached {area}: {hits[:5]}"
                return detail
    matched = next(token for token in stage_tokens if token in combined)
    detail["blocked_at"] = matched
    return detail


def expect_accept(result: subprocess.CompletedProcess, repo: Path) -> dict:
    detail = {"exit_code": result.returncode}
    if result.returncode != 0:
        detail["problem"] = "clean control run failed"
        detail["tail"] = (result.stdout + result.stderr)[-400:]
        return detail
    accepted = repo / "release" / "gate" / "accepted"
    hits = scan_tree(accepted) if accepted.exists() else ["accepted/ missing"]
    if hits:
        detail["problem"] = f"canary reached accepted artifacts: {hits[:5]}"
        return detail
    detail["accepted"] = sorted(p.name for p in accepted.iterdir())
    return detail


# -- contamination scenarios -------------------------------------------------
def case_env_secret(repo: Path) -> tuple[str, subprocess.CompletedProcess]:
    env = {SECRET["also_env"]: SECRET["value"], RECORD["also_env"]: RECORD["value"]}
    return "env-only", run_gate(repo, extra_env=env)


def case_dotenv_root(repo: Path):
    (repo / ".env").write_text(f"REDACTA_KEY={SECRET['value']}\n", encoding="utf-8")
    return "dotenv-root", run_gate(repo)


def case_dotenv_renamed(repo: Path):
    (repo / ".env.production.bak").write_text(SECRET["value"], encoding="utf-8")
    return "dotenv-renamed", run_gate(repo)


def case_dotenv_nested_rename(repo: Path):
    target = repo / "src" / "redacta" / "config"
    target.mkdir(parents=True)
    (target / "env.local").write_text(SECRET["value"], encoding="utf-8")
    return "dotenv-nested", run_gate(repo)


def case_sqlite_in_tree(repo: Path):
    db = repo / "audit.sqlite"
    db.write_bytes(b"SQLite format 3\x00" + RECORD["value"].encode())
    return "sqlite-root", run_gate(repo)


def case_sqlite_nested(repo: Path):
    target = repo / "src" / "redacta"
    (target / "audit.sqlite-wal").write_bytes(RECORD["value"].encode())
    return "sqlite-wal-nested", run_gate(repo)


def case_release_dir(repo: Path):
    target = repo / "releases" / "deadbeef"
    target.mkdir(parents=True)
    (target / "canary-release.jsonl").write_text(RECORD["value"] + "\n", encoding="utf-8")
    return "release-dir", run_gate(repo)


def case_temp_jsonl(repo: Path):
    (repo / "scratch.jsonl.tmp").write_text(RECORD["value"] + "\n", encoding="utf-8")
    return "temp-jsonl", run_gate(repo)


def case_unlisted_json(repo: Path):
    (repo / "src" / "redacta" / "secrets_dump.json").write_text(
        json.dumps({"key": SECRET["value"]}), encoding="utf-8")
    return "unlisted-json", run_gate(repo)


def case_canary_inside_sample(repo: Path):
    sample = repo / "examples" / "tables.json"
    text = sample.read_text(encoding="utf-8").replace(
        "alice@example.test", f"alice@example.test {RECORD['value']}")
    sample.write_text(text, encoding="utf-8")
    # Re-approve the poisoned sample in the sandbox manifest: this proves the
    # canary scan is independent of, and stronger than, hash admission.
    sys.path.insert(0, str(repo / "release" / "gate"))
    from gate_lib import refresh_manifest
    refresh_manifest(repo, output=repo / "release" / "gate" / "source-manifest.json")
    return "canary-in-approved-sample", run_gate(repo)


def case_hash_drift(repo: Path):
    code = repo / "src" / "redacta" / "transforms.py"
    code.write_text(code.read_text(encoding="utf-8") + f"# {SECRET['value']}\n",
                    encoding="utf-8")
    return "hash-drift", run_gate(repo)


def case_symlink_escape(repo: Path):
    outside = repo.parent / "outside-secret.env"
    outside.write_text(SECRET["value"], encoding="utf-8")
    link = repo / "src" / "redacta" / "settings.env"
    link.symlink_to(outside)
    return "symlink-outside-manifest", run_gate(repo)


def case_symlink_renamed_env(repo: Path):
    outside = repo.parent / "env-store"
    outside.mkdir(exist_ok=True)
    (outside / ".env").write_text(SECRET["value"], encoding="utf-8")
    link = repo / "src" / "redacta" / "config.env"
    link.symlink_to(outside / ".env")
    return "symlink-renamed-env", run_gate(repo)


def case_stale_dist(repo: Path):
    dist = repo / "dist"
    dist.mkdir()
    stale = dist / "redacta-0.0.1-py3-none-any.whl"
    # A plausible stale wheel carrying the canary.
    import zipfile
    with zipfile.ZipFile(stale, "w") as zf:
        zf.writestr("redacta/polluted.py", f"SECRET = {SECRET['value']!r}\n")
        zf.writestr("redacta-0.0.1.dist-info/RECORD", "redacta/polluted.py,,\n")
    return "stale-dist-residue", run_gate(repo)


def case_dotdot_path(repo: Path):
    # A path-traversal style name inside the source tree: neither the
    # manifest refresh nor admission may normalise it away.
    target = repo / "src" / "redacta"
    target.mkdir(parents=True, exist_ok=True)
    (target / "..env").write_text(SECRET["value"], encoding="utf-8")
    return "dotdot-env-variant", run_gate(repo)


def case_pyc_residue(repo: Path):
    target = repo / "src" / "redacta" / "__pycache__"
    target.mkdir(parents=True)
    (target / "policy.cpython-311.pyc").write_bytes(b"\x00" + SECRET["value"].encode())
    return "pyc-cache-residue", run_gate(repo)


NEGATIVE_CASES = [
    (case_dotenv_root, ("path-denylist", "canary-filename")),
    (case_dotenv_renamed, ("path-denylist",)),
    (case_dotenv_nested_rename, ("path-denylist",)),
    (case_sqlite_in_tree, ("path-denylist", "canary-filename")),
    (case_sqlite_nested, ("path-denylist", "canary-filename")),
    (case_release_dir, ("path-denylist", "canary-filename")),
    (case_temp_jsonl, ("path-denylist",)),
    (case_unlisted_json, ("unlisted-file",)),
    (case_canary_inside_sample, ("canary-content",)),
    (case_hash_drift, ("hash-drift",)),
    (case_symlink_escape, ("symlink-refused",)),
    (case_symlink_renamed_env, ("symlink-refused",)),
    (case_stale_dist, ("path-denylist",)),
    (case_dotdot_path, ("path-denylist", "unlisted-file", "canary-filename")),
    (case_pyc_residue, ("path-denylist", "unlisted-file")),
]


def main() -> int:
    RECORDS_DIR.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%dT%H%M%S")
    results = []

    with tempfile.TemporaryDirectory(prefix="gate-exp-") as tmp_base:
        base = Path(tmp_base)

        # 0. positive control on a pristine copy.
        control_repo = clean_sandbox(base / "control")
        result = run_gate(control_repo)
        control = expect_accept(result, control_repo)
        results.append({"case": "clean-control", "expectation": "accept", **control})

        # 1. canary environment variables on an otherwise clean tree: must
        #    still pass, and never be echoed into artifacts or logs.
        env_repo = clean_sandbox(base / "env")
        result = case_env_secret(env_repo)[1]
        env_detail = expect_accept(result, env_repo)
        runs = env_repo / "release" / "gate" / "runs"
        if runs.exists() and scan_tree(runs):
            env_detail["problem"] = f"env canary leaked into run logs: {scan_tree(runs)[:5]}"
        results.append({"case": "canary-env-vars-only", "expectation": "accept", **env_detail})

        # 2. every injection/evasion channel must be blocked.
        for index, (scenario, stages) in enumerate(NEGATIVE_CASES, start=1):
            repo = clean_sandbox(base / f"case-{index}")
            case_id, completed = scenario(repo)
            detail = expect_block(completed, stages, repo, case_id)
            results.append({"case": case_id, "expectation": f"block:{'/'.join(stages)}",
                            **detail})

    summary = {
        "schema": "redacta-contamination-experiments/v1",
        "run_id": run_id,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "canary_ids": [c["id"] for c in CANARIES],
        "canary_values_redacted_in_record": True,
        "total": len(results),
        "passed": sum(1 for r in results if "problem" not in r),
        "failed": [r for r in results if "problem" in r],
        "results": results,
    }
    out = RECORDS_DIR / f"contamination-{run_id}.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    print(json.dumps({"record": str(out), "total": summary["total"],
                      "passed": summary["passed"], "failed": len(summary["failed"])},
                     indent=2))
    return 0 if not summary["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
