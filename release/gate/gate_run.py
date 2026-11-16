#!/usr/bin/env python3
"""Redacta offline release gate entry point.

Pipeline (each stage gates the next; any failure quarantines the run and
exits non-zero so an old dist/ can never be reinstalled):

  0. verify the offline wheelhouse hash lock
  1. admit source files from the approved allowlist (manifest + hashes)
  2. PEP 517 build of an sdist inside a pristine, source-only tree
  3. audit sdist members, links, setuptools SOURCES.txt closure
  4. rebuild a wheel *from that sdist* in a second isolated build env
  5. audit wheel members and dist-info/RECORD
  6. install the rebuilt wheel into a clean venv (offline) and audit the tree
  7. black-box publish/read/revoke smoke test with a throwaway key
  8. bind artifact SHA-256s into a run report; only success reaches accepted/
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gate_lib import (  # noqa: E402
    CANARIES_PATH, DEFAULT_WHEELHOUSE, GATE_DIR, MANIFEST_PATH, GateContext,
    GateFailure, admit_sources, load_json, make_venv, offline_env,
    refresh_manifest, run_logged,
)
from pep517_driver import run_backend_hook  # noqa: E402
from audit import audit_install, audit_sdist, audit_wheel  # noqa: E402

PROJECT_ROOT = GATE_DIR.parents[1]
ACCEPTED_DIR = GATE_DIR / "accepted"
QUARANTINE_DIR = GATE_DIR / "quarantine"
REPORTS_DIR = GATE_DIR / "reports"
RUNS_DIR = GATE_DIR / "runs"


def verify_wheelhouse(ctx: GateContext) -> None:
    lock = ctx.wheelhouse / "SHA256SUMS"
    if not lock.is_file():
        ctx.fail("wheelhouse", "lock-missing", f"{lock} missing; run bootstrap_wheelhouse.sh")
    lock_lines = [line for line in lock.read_text(encoding="utf-8").splitlines() if line.strip()]
    locked_names = set()
    for line in lock_lines:
        expected, _, name = line.partition("  ")
        locked_names.add(name)
        wheel = ctx.wheelhouse / name
        if not wheel.is_file():
            ctx.fail("wheelhouse", "wheel-missing", str(wheel))
        actual = hashlib.sha256(wheel.read_bytes()).hexdigest()
        if actual != expected:
            ctx.fail("wheelhouse", "hash-lock",
                     f"{name} tampered (lock={expected[:12]}, actual={actual[:12]})")
    extras = sorted(p.name for p in ctx.wheelhouse.iterdir()
                    if p.is_file() and p.name != "SHA256SUMS" and p.name not in locked_names)
    if extras:
        ctx.fail("wheelhouse", "unlisted-wheels", f"wheels not covered by the lock: {extras}")
    ctx.report["wheelhouse"] = {
        "path": str(ctx.wheelhouse),
        "wheels": sorted(p.name for p in ctx.wheelhouse.glob("*.whl")),
        "lock_verified": True,
    }


def stage_build_sdist(ctx: GateContext) -> Path:
    env = offline_env(ctx)
    build_venv = make_venv(ctx, "build-venv", with_pip=True)
    out = ctx.workdir / "build-out"
    out.mkdir()
    try:
        name = run_backend_hook(
            project=ctx.workdir / "pristine",
            wheelhouse=ctx.wheelhouse, out_dir=out,
            hook="build_sdist", env=env,
        )
    except RuntimeError as exc:
        ctx.fail("build", "sdist-hook", str(exc))
    sdist = out / name
    if not sdist.is_file():
        ctx.fail("build", "sdist-missing", f"backend reported {name} but file is absent")
    return sdist


def stage_rebuild_wheel(ctx: GateContext, sdist: Path) -> Path:
    """Rebuild the wheel from the audited sdist, not from the source tree."""
    env = offline_env(ctx)
    extract = ctx.workdir / "sdist-extract"
    extract.mkdir()
    shutil.unpack_archive(sdist, extract, format="gztar")
    roots = [p for p in extract.iterdir() if p.is_dir()]
    if len(roots) != 1:
        ctx.fail("rebuild", "sdist-layout", f"expected one root dir, got {roots}")
    sdist_project = roots[0]
    out = ctx.workdir / "wheel-out"
    out.mkdir()
    try:
        name = run_backend_hook(
            project=sdist_project, wheelhouse=ctx.wheelhouse,
            out_dir=out, hook="build_wheel", env=env,
        )
    except RuntimeError as exc:
        ctx.fail("rebuild", "wheel-hook", str(exc))
    wheel = out / name
    if not wheel.is_file():
        ctx.fail("rebuild", "wheel-missing", f"backend reported {name} but file is absent")
    ctx.report["rebuild"] = {"from_sdist": sdist.name, "wheel": name}
    return wheel


def stage_install_and_smoke(ctx: GateContext, wheel: Path, admitted: dict) -> None:
    env = offline_env(ctx)
    app_venv = make_venv(ctx, "app-venv", with_pip=True)
    python = app_venv / "bin" / "python"
    run_logged(ctx, "install", "wheel-install.log",
               [str(python), "-m", "pip", "install", "--no-index",
                "--find-links", str(ctx.wheelhouse), str(wheel)],
               cwd=ctx.workdir, env=env)

    site_packages = next((app_venv / "lib").glob("python*/site-packages"))
    audit_install(ctx, site_packages, wheel, admitted)

    # The console-script entry point declared in pyproject must exist and run.
    console = app_venv / "bin" / "redacta"
    if not console.is_file():
        ctx.fail("install", "entry-point", "redacta console script not installed")
    run_logged(ctx, "install", "entry-point-version.log",
               [str(console), "--help"], cwd=ctx.workdir, env=env)

    # Smoke gets a fresh throwaway key; nothing else REDACTA_* survives.
    smoke_key = secrets.token_hex(32)
    smoke_env = offline_env(ctx, smoke_key=smoke_key)
    fixtures = ctx.workdir / "pristine" / "examples"
    run_logged(ctx, "smoke", "smoke.log",
               [str(python), "-I", str(GATE_DIR / "smoke_installed.py"),
                str(fixtures), str(ctx.workdir / "smoke-work")],
               cwd=ctx.workdir, env=smoke_env)
    smoke_output = (ctx.workdir / "logs" / "smoke.log").read_bytes()
    try:
        payload = json.loads(smoke_output[smoke_output.index(b"{"):])
    except ValueError:
        ctx.fail("smoke", "report-parse", "smoke did not emit JSON")
    if not payload.get("ok") or payload["cli_exit_codes"] != {"publish": 0, "revoke": 0}:
        ctx.fail("smoke", "assertions", f"smoke payload failed: {payload}")
    if smoke_key.encode() in smoke_output:
        ctx.fail("smoke", "key-echo", "throwaway key echoed into the smoke log")
    ctx.report["smoke"] = {
        "ok": True,
        "import_origin": payload["import_origin"],
        "release_id": payload["release_id"],
        "cli_exit_codes": payload["cli_exit_codes"],
        "key_source": "ephemeral env var, generated per run, never written to reports",
    }


def write_report(ctx: GateContext, run_id: str, status: str,
                 artifacts: dict[str, Path] | None) -> Path:
    artifacts = artifacts or {}
    artifact_hashes = {
        label: {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for label, path in artifacts.items()
    }
    ctx.report.update({
        "schema": "redacta-gate-report/v1",
        "run_id": run_id,
        "status": status,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version.split()[0],
        "project_root": str(PROJECT_ROOT),
        "canary_ids": [c["id"] for c in ctx.canaries["canaries"]],
        "canary_values_redacted": True,
        "artifacts": artifact_hashes,
        "findings": [f.__dict__ for f in ctx.findings],
    })
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if status == "accepted":
        # Report name is bound to the accepted hashes, so two runs can never
        # share a report even if the source version is unchanged.
        digest = hashlib.sha256(
            json.dumps(artifact_hashes, sort_keys=True).encode()).hexdigest()[:16]
        path = REPORTS_DIR / f"accept-{run_id}-{digest}.json"
    else:
        path = REPORTS_DIR / f"reject-{run_id}.json"
    payload = json.dumps(ctx.report, indent=2, ensure_ascii=False) + "\n"
    path.write_text(payload, encoding="utf-8")
    # A report is itself a gate output: it must not carry a canary either.
    # Only check after the rejection path has recorded its findings.
    if status == "accepted":
        ctx.scan_bytes(f"report-{status}", path.name, payload.encode("utf-8"))
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline release gate for Redacta")
    parser.add_argument("--refresh-manifest", action="store_true",
                        help="regenerate source-manifest.json from the tree, then exit")
    parser.add_argument("--keep-work", action="store_true",
                        help="keep the scratch run directory for forensics")
    parser.add_argument("--wheelhouse", type=Path, default=DEFAULT_WHEELHOUSE)
    args = parser.parse_args()

    if args.refresh_manifest:
        try:
            manifest = refresh_manifest(PROJECT_ROOT)
        except GateFailure as exc:
            print(f"manifest refresh FAILED: {exc}", file=sys.stderr)
            return 1
        print(f"wrote {MANIFEST_PATH} with {len(manifest['entries'])} entries")
        return 0

    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"gate-{run_id}-", dir=RUNS_DIR))

    ctx = GateContext(
        project_root=PROJECT_ROOT, workdir=work, wheelhouse=args.wheelhouse,
        manifest=load_json(MANIFEST_PATH), canaries=load_json(CANARIES_PATH),
    )
    artifacts: dict[str, Path] = {}
    try:
        verify_wheelhouse(ctx)
        admit_sources(ctx)
        sdist = stage_build_sdist(ctx)
        artifacts["sdist"] = sdist
        audit_sdist(ctx, sdist, _admitted(ctx))
        wheel = stage_rebuild_wheel(ctx, sdist)
        artifacts["wheel"] = wheel
        audit_wheel(ctx, wheel, _admitted(ctx))
        stage_install_and_smoke(ctx, wheel, _admitted(ctx))
    except GateFailure as exc:
        report = write_report(ctx, run_id, "rejected", artifacts)
        quarantine = QUARANTINE_DIR / run_id
        quarantine.mkdir(parents=True, exist_ok=True)
        for label, path in artifacts.items():
            shutil.copy2(path, quarantine / f"{label}-{path.name}")
        shutil.copy2(report, quarantine / report.name)
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"scratch retained at {work}", file=sys.stderr)
        print(f"GATE REJECTED: {exc}", file=sys.stderr)
        print(f"report: {report} | quarantine: {quarantine}", file=sys.stderr)
        return 1

    # Success path: publish artifacts under canonical PEP-compliant names
    # plus a SHA256SUMS sidecar. Wheel filenames must keep the PEP 427 form
    # (hashes must not be embedded in the name); hash binding lives in the
    # sidecar and in the hash-named acceptance report.
    ACCEPTED_DIR.mkdir(parents=True, exist_ok=True)
    published: dict[str, Path] = {}
    for label, path in artifacts.items():
        target = ACCEPTED_DIR / path.name
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != \
                    hashlib.sha256(path.read_bytes()).hexdigest():
                ctx.fail("accept", "name-collision",
                         f"{target} exists with different bytes; refusing overwrite")
        else:
            shutil.copy2(path, target)
        published[label] = target
    sidecar = ACCEPTED_DIR / "SHA256SUMS"
    lines = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in published.values()
    )
    if sidecar.exists() and sidecar.read_text(encoding="utf-8") != lines:
        ctx.fail("accept", "sidecar-drift",
                 "accepted/SHA256SUMS exists with different content")
    sidecar.write_text(lines, encoding="utf-8")
    report = write_report(ctx, run_id, "accepted", published)
    if not args.keep_work:
        shutil.rmtree(work, ignore_errors=True)
    print("GATE ACCEPTED")
    for label, path in published.items():
        print(f"  {label}: {path} sha256={hashlib.sha256(path.read_bytes()).hexdigest()}")
    print(f"  sidecar: {sidecar}")
    print(f"  report: {report}")
    return 0


def _admitted(ctx: GateContext) -> dict[str, dict]:
    return {entry["path"]: entry for entry in ctx.manifest["entries"]}


if __name__ == "__main__":
    raise SystemExit(main())
