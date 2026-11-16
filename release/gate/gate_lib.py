"""Library support for the Redacta offline release gate.

Design contract (see release/README.md for the full rationale):

1. Admission is allowlist-driven.  ``source-manifest.json`` enumerates every
   file that may leave the source tree, with role + SHA-256.  Nothing is
   collected implicitly from the working tree.
2. Builds happen from a *pristine* copy containing only admitted files, via a
   PEP 517 frontend with network isolation.  The developer's working tree is
   never handed to a build backend.
3. Artifacts are audited after the build: tar/zip members, link targets, wheel
   RECORD and the installed import location are all checked against the
   admitted hashes and the injected canaries.
4. A run only publishes artifacts into ``accepted/`` when every stage passes;
   reports are content-addressed by artifact SHA-256, so a retry cannot reuse a
   previous "pass".

This module intentionally has no third-party dependencies: the gate audits
third-party tooling, it must not depend on it.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

GATE_DIR = Path(__file__).resolve().parent
DEFAULT_WHEELHOUSE = GATE_DIR / "wheelhouse"
MANIFEST_PATH = GATE_DIR / "source-manifest.json"
CANARIES_PATH = GATE_DIR / "canaries.json"

# Directories the hygiene scan never descends into: gate outputs, caches and
# VCS data. Gate scripts/config under release/ ARE tracked by the manifest,
# only the runtime output directories are excluded.
EXCLUDED_REL_DIRS = {
    ".git",
    "release/gate/wheelhouse",
    "release/gate/runs",
    "release/gate/accepted",
    "release/gate/quarantine",
    "release/gate/reports",
    "release/experiments/records",
}
# Gate-owned files that cannot self-reference (the manifest cannot hash
# itself) or are regenerated per run.
GATE_EXTRA_EXCLUDES = {"__pycache__"}
# Files that are part of the gate itself rather than the released source set.
GATE_OWN_FILES = {"source-manifest.json"}

# Roles whose bytes may appear inside the released artifacts.  Per-role
# shipping targets are enforced by the audit:
#   package-source     -> sdist + wheel (+ installed tree)
#   approved-sample    -> sdist only (synthetic fixtures, hash-pinned)
#   packaging-metadata -> sdist only
#   project-doc        -> sdist only, via explicit MANIFEST.in
PACKAGED_ROLES = {"package-source", "approved-sample", "packaging-metadata", "project-doc"}
SDIST_ONLY_ROLES = {"approved-sample", "packaging-metadata", "project-doc"}
# Roles that stay in the repository but must never be collected into a build.
NON_PACKAGED_ROLES = {"test", "gate-script", "gate-doc", "dev-automation", "gate-config"}
KNOWN_ROLES = PACKAGED_ROLES | NON_PACKAGED_ROLES

# Patterns that are never admitted anywhere in a release artifact.  Matching is
# done against every path component, so renaming a file into a new directory
# cannot evade the rule (e.g. ``nested/.env`` still contains a ``.env`` part).
DENY_PARTS = {
    ".env",
    ".env.local",
}
DENY_SUFFIXES = (".sqlite", ".sqlite-wal", ".sqlite-shm", ".db", ".jsonl.tmp")
DENY_DIR_PARTS = {"releases", "release-data", ".stage", "dist", "build", ".venv", "venv",
                  "egg-info", "__pycache__"}
DENY_NAME_REGEXES = (
    re.compile(r".*\.egg-info$"),
    re.compile(r"^.*\.py[co]$"),
    # Environment files under any naming: .env, .env.local, .env.production.bak,
    # env.local ... a renamed environment file is still an environment file.
    re.compile(r"^\.?env(\.[^/]+)?$"),
)


class GateFailure(Exception):
    """Raised for any gate policy violation; the CLI maps this to exit code 1."""


@dataclass
class Finding:
    stage: str
    rule: str
    detail: str


@dataclass
class GateContext:
    project_root: Path
    workdir: Path
    wheelhouse: Path
    manifest: dict
    canaries: list[dict]
    findings: list[Finding] = field(default_factory=list)
    report: dict = field(default_factory=dict)

    def fail(self, stage: str, rule: str, detail: str) -> None:
        self.findings.append(Finding(stage, rule, detail))
        raise GateFailure(f"[{stage}] {rule}: {detail}")

    # -- canary helpers -----------------------------------------------------
    def canary_tokens(self) -> list[str]:
        return [item["value"] for item in self.canaries["canaries"]]

    def canary_filenames(self) -> set[str]:
        names: set[str] = set()
        for item in self.canaries["canaries"]:
            names.update(item.get("scan_filenames", []))
        return names

    def scan_bytes(self, stage: str, label: str, blob: bytes) -> None:
        """Fail if any canary *token* appears in ``blob``.

        Canary filenames are enforced as full path-component matches by the
        admission/audit code (see ``scan_path_name``), not byte substring
        matches: a documented deny rule such as ``.env`` inside .gitignore
        must not itself count as leakage.
        """
        for token in self.canary_tokens():
            if token.encode() in blob:
                self.fail(stage, "canary-content", f"canary token present in {label}")

    def scan_path_name(self, stage: str, path_parts: tuple[str, ...]) -> None:
        """Fail if a full path component equals a planted canary filename."""
        for name in self.canary_filenames():
            if name in path_parts:
                self.fail(stage, "canary-filename",
                          f"canary filename {name!r} present as path component")


# --------------------------------------------------------------------------- #
# manifest loading + source admission
# --------------------------------------------------------------------------- #
def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateFailure(f"cannot read {path}: {exc}")


def _posix_str(path: Path) -> str:
    return path.as_posix()


def _is_denied(rel_posix: str) -> str | None:
    parts = PurePosixPath(rel_posix).parts
    for part in parts:
        if part in DENY_PARTS:
            return f"forbidden component {part!r}"
        if part in DENY_DIR_PARTS:
            return f"forbidden directory/component {part!r}"
        for pattern in DENY_NAME_REGEXES:
            if pattern.fullmatch(part):
                return f"forbidden name pattern {part!r}"
    lowered = rel_posix.lower()
    for suffix in DENY_SUFFIXES:
        if lowered.endswith(suffix):
            return f"forbidden suffix {suffix!r}"
    return None


def _walk_files(root: Path) -> list[Path]:
    """Walk every file under ``root``.

    Only gate output directories (matched by full relative path) are skipped.
    Python caches are not skipped: a ``__pycache__`` or ``*.pyc`` under the
    source tree is an admission failure surfaced via the deny rules, not a
    directory the walk may hide.
    """
    collected: list[Path] = []
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        rel_dir = "." if current_path == root else current_path.relative_to(root).as_posix()
        kept: list[str] = []
        for d in dirs:
            rel = d if rel_dir == "." else f"{rel_dir}/{d}"
            if rel not in EXCLUDED_REL_DIRS:
                kept.append(d)
        dirs[:] = kept
        for name in files:
            collected.append(current_path / name)
    return sorted(collected)


def refresh_manifest(project_root: Path, output: Path | None = None) -> dict:
    """Rebuild source-manifest.json from the on-disk tree.

    Roles are derived deterministically from path.  A file that matches a deny
    rule or cannot be assigned a role aborts the refresh: admission rules are
    authored explicitly, never guessed from a broad glob.
    """
    output = output or MANIFEST_PATH
    role_map = [
        (re.compile(r"^src/redacta/.*\.py$"), "package-source"),
        (re.compile(r"^examples/.*\.json$"), "approved-sample"),
        (re.compile(r"^examples/smoke\.py$"), "test"),
        (re.compile(r"^tests/.*\.py$"), "test"),
        (re.compile(r"^release/gate/gate_lib\.py$"), "gate-script"),
        (re.compile(r"^release/gate/pep517_driver\.py$"), "gate-script"),
        (re.compile(r"^release/gate/audit\.py$"), "gate-script"),
        (re.compile(r"^release/gate/gate_run\.py$"), "gate-script"),
        (re.compile(r"^release/gate/smoke_installed\.py$"), "gate-script"),
        (re.compile(r"^release/gate/.*\.sh$"), "gate-script"),
        (re.compile(r"^release/experiments/.*\.py$"), "gate-script"),
        (re.compile(r"^release/gate/canaries\.json$"), "gate-config"),
        (re.compile(r"^release/.*\.md$"), "gate-doc"),
        (re.compile(r"^README\.md$"), "project-doc"),
        (re.compile(r"^MANIFEST\.in$"), "packaging-metadata"),
        (re.compile(r"^Makefile$"), "dev-automation"),
        (re.compile(r"^\.gitignore$"), "dev-automation"),
        (re.compile(r"^pyproject\.toml$"), "packaging-metadata"),
    ]
    entries: list[dict] = []
    for path in _walk_files(project_root):
        rel = path.relative_to(project_root).as_posix()
        if Path(rel).name in GATE_OWN_FILES:
            continue
        denied = _is_denied(rel)
        if denied:
            raise GateFailure(f"manifest refresh refuses {rel}: {denied}")
        role = next((candidate for pattern, candidate in role_map if pattern.fullmatch(rel)), None)
        if role is None:
            raise GateFailure(f"manifest refresh has no role rule for {rel}; add an explicit rule")
        entries.append({
            "path": rel,
            "role": role,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        })
    manifest = {
        "schema": "redacta-source-manifest/v1",
        "comment": "Allowlist of every file the release gate may collect. "
                   "Packaged roles define the PEP 517 source closure; other roles "
                   "stay in the repository and are refused at artifact audit.",
        "entries": sorted(entries, key=lambda item: item["path"]),
    }
    output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    return manifest


def _admitted_map(manifest: dict) -> dict[str, dict]:
    entries = manifest.get("entries", [])
    if not isinstance(entries, list) or not entries:
        raise GateFailure("source manifest has no entries")
    result: dict[str, dict] = {}
    for entry in entries:
        for key in ("path", "role", "sha256"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise GateFailure(f"manifest entry missing {key}: {entry!r}")
        if entry["role"] not in KNOWN_ROLES:
            raise GateFailure(f"unknown role {entry['role']!r} for {entry['path']}")
        if PurePosixPath(entry["path"]).is_absolute() or ".." in PurePosixPath(entry["path"]).parts:
            raise GateFailure(f"manifest path escapes repository: {entry['path']}")
        if entry["path"] in result:
            raise GateFailure(f"duplicate manifest entry: {entry['path']}")
        result[entry["path"]] = entry
    return result


def admit_sources(ctx: GateContext) -> dict[str, Path]:
    """Stage 1: hygiene + allowlist admission of the working tree.

    Returns a mapping ``rel-path -> absolute staged path`` for packaged files.
    Raises GateFailure on symlinks, deny-pattern hits, unlisted files, hash
    drift or canary content inside admitted files.
    """
    admitted = _admitted_map(ctx.manifest)
    on_disk = _walk_files(ctx.project_root)
    seen: set[str] = set()
    staged_packaged: dict[str, Path] = {}
    pristine = ctx.workdir / "pristine"
    pristine.mkdir()

    for path in on_disk:
        rel = path.relative_to(ctx.project_root).as_posix()
        # The manifest cannot hash itself; every other gate file is admitted
        # and hash-checked like any other repository input.
        if Path(rel).name in GATE_OWN_FILES:
            continue
        seen.add(rel)
        if path.is_symlink():
            ctx.fail("admission", "symlink-refused",
                     f"{rel} -> {os.readlink(path)!r} (symlinks are never admitted)")
        if not path.is_file():
            ctx.fail("admission", "non-regular-file", f"{rel} is not a regular file")
        ctx.scan_path_name("admission", PurePosixPath(rel).parts)
        denied = _is_denied(rel)
        if denied:
            ctx.fail("admission", "path-denylist", f"{rel}: {denied}")
        entry = admitted.get(rel)
        if entry is None:
            ctx.fail("admission", "unlisted-file",
                     f"{rel} is not on the approved source manifest")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            ctx.fail("admission", "hash-drift",
                     f"{rel} changed since manifest approval "
                     f"(manifest={entry['sha256'][:12]}, actual={digest[:12]})")
        # The canary definition file by design contains the canary values;
        # it is hash-pinned, gate-config role, and never copied into a build.
        if entry["role"] != "gate-config":
            ctx.scan_bytes("admission", rel, path.read_bytes())
        if entry["role"] in PACKAGED_ROLES:
            target = pristine / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)  # copy2 follows symlinks; symlinks already refused
            staged_packaged[rel] = target

    missing = sorted(set(admitted) - seen)
    if missing:
        ctx.fail("admission", "missing-files", f"manifest entries absent on disk: {missing}")

    # The pristine tree must contain exactly the packaged closure.
    staged = {p.relative_to(pristine).as_posix() for p in pristine.rglob("*") if p.is_file()}
    expected = {rel for rel, entry in admitted.items() if entry["role"] in PACKAGED_ROLES}
    if staged != expected:
        ctx.fail("admission", "closure-mismatch",
                 f"pristine closure mismatch extra={sorted(staged - expected)} "
                 f"missing={sorted(expected - staged)}")
    ctx.report["admission"] = {
        "files_on_disk": len(seen),
        "packaged_files": len(expected),
        "non_packaged_files": len(seen) - len(expected),
        "pristine_dir": str(pristine),
    }
    return staged_packaged


# --------------------------------------------------------------------------- #
# subprocess + offline environment
# --------------------------------------------------------------------------- #
def offline_env(ctx: GateContext, *, smoke_key: str | None = None) -> dict[str, str]:
    """Build a scrubbed environment for build/install/smoke subprocesses.

    All REDACTA_* and canary-named variables from the developer environment are
    dropped.  The smoke key is the only secret injected and it is generated per
    run, never written to the report.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(ctx.workdir / "home"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONDONTWRITEBYTECODE": "1",
        # Debian's python3-distutils otherwise trips setuptools' _distutils_hack
        # assertion inside --without-pip venvs.
        "SETUPTOOLS_USE_DISTUTILS": "stdlib",
        "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_CACHE_DIR": "1",
        # Point proxies at an unroutable discard target as belt-and-braces:
        # PIP_NO_INDEX already removes every index lookup.
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "",
    }
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    if smoke_key is not None:
        env["REDACTA_KEY"] = smoke_key
    return env


def run_logged(ctx: GateContext, stage: str, log_name: str, cmd: list[str],
               cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    log_dir = ctx.workdir / "logs"
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / log_name
    with log_path.open("wb") as log:
        log.write(("$ " + " ".join(cmd) + "\n").encode())
        log.flush()
        completed = subprocess.run(cmd, cwd=cwd, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, timeout=600)
    blob = log_path.read_bytes()
    # Logs must never echo the injected key or a planted canary.
    ctx.scan_bytes(stage, f"log {log_name}", blob)
    if completed.returncode != 0:
        ctx.fail(stage, "subprocess-failed",
                 f"{cmd[0]} exited {completed.returncode}; see {log_path}")
    return completed


def make_venv(ctx: GateContext, name: str, *, with_pip: bool) -> Path:
    venv_path = ctx.workdir / name
    cmd = [sys.executable, "-m", "venv"]
    if with_pip:
        # Install pip from the local wheelhouse instead of ensurepip (which may
        # be absent, as on this Debian image).
        cmd += ["--without-pip"]
    subprocess.run(cmd + [str(venv_path)], check=True,
                   env=offline_env(ctx), capture_output=True, timeout=300)
    if with_pip:
        pip_wheel = next(ctx.wheelhouse.glob("pip-*.whl"))
        pip_env = dict(offline_env(ctx))
        pip_env["PYTHONPATH"] = str(pip_wheel)
        run_logged(ctx, "venv", f"{name}-pip-bootstrap.log",
                   [str(venv_path / "bin" / "python"), "-m", "pip", "install",
                    "--no-index", "--find-links", str(ctx.wheelhouse),
                    "pip", "setuptools", "wheel"],
                   cwd=ctx.workdir, env=pip_env)
    return venv_path
