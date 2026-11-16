"""Minimal, dependency-free PEP 517 frontend used by the release gate.

Only the two hooks the gate needs are implemented:

* ``prepare_metadata_for_build_wheel``
* ``build_wheel`` / ``build_sdist``

The backend (setuptools.build_meta) is imported *inside a fresh subprocess*
whose sys.path contains just the backend wheels from the offline wheelhouse.
This mirrors what pip/build do closely enough to exercise the real PEP 517
source collection, while keeping the gate itself free of third-party imports.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_DRIVER = r"""
import contextlib, io, json, os, sys, warnings
warnings.simplefilter("ignore")
spec = json.loads(sys.stdin.read())
sys.path[:0] = spec["backend_paths"]
backend = __import__(spec["backend"])
for part in spec["backend"].split(".")[1:]:
    backend = getattr(backend, part)
out = spec["out"]
os.makedirs(out, exist_ok=True)
hook = getattr(backend, spec["hook"])
kwargs = spec.get("kwargs", {}) or {}
# setuptools prints build progress to stdout/stderr; capture both so the
# only thing written to stdout is our result JSON.
captured = io.StringIO()
with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
    if spec["hook"] == "prepare_metadata_for_build_wheel":
        result = hook(out)
    elif spec["hook"] == "build_wheel":
        result = hook(out, None)
    elif spec["hook"] == "build_sdist":
        result = hook(out)
    else:
        raise SystemExit("unsupported hook " + spec["hook"])
print(json.dumps({"result": result, "backend_output": captured.getvalue()}))
"""


def run_backend_hook(*, project: Path, wheelhouse: Path, out_dir: Path,
                     hook: str, env: dict[str, str],
                     backend: str = "setuptools.build_meta",
                     extra_wheels: list[Path] | None = None) -> str:
    """Invoke a PEP 517 backend hook offline; return the hook's string result."""
    backend_paths = [str(p) for p in wheelhouse.glob("*.whl")]
    if extra_wheels:
        backend_paths.extend(str(p) for p in extra_wheels)
    payload = json.dumps({
        "backend": backend,
        "backend_paths": sorted(backend_paths),
        "hook": hook,
        "out": str(out_dir),
    })
    completed = subprocess.run(
        [sys.executable, "-I", "-c", _DRIVER],
        input=payload, cwd=project, env=env,
        capture_output=True, text=True, timeout=600,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"PEP 517 hook {hook} failed (exit {completed.returncode})\n"
            f"--- stdout ---\n{completed.stdout}\n--- stderr ---\n{completed.stderr}"
        )
    return json.loads(completed.stdout)["result"]
