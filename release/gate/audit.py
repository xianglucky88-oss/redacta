"""Artifact audits for the offline release gate.

Every check here works on *built* artifacts (sdist tarball, rebuilt wheel,
unpacked install tree), never on the source tree.  The mapping back to the
approved source manifest is what proves each shipped byte came from an
admitted input; generated metadata is identified by narrow, explicit rules
and only ever scanned for canaries.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from gate_lib import GateContext, GateFailure, PACKAGED_ROLES, SDIST_ONLY_ROLES

# Metadata that setuptools legitimately generates during a PEP 517 build.
# Anything else in an artifact must map byte-for-byte to a manifest entry.
EGG_INFO_RE = re.compile(r"^(?:[^/]+/)*[^/]+\.egg-info/(PKG-INFO|SOURCES.txt|"
                         r"dependency_links.txt|top_level.txt|requires.txt|entry_points.txt)$")
# setuptools 70 emits this exact setup.cfg skeleton into the sdist even for
# pyproject-only projects. Its bytes are validated, not just its name.
SETUP_CFG_SKELETON = "[egg_info]\ntag_build = \ntag_date = 0\n\n"
DIST_INFO_RE = re.compile(r"^redacta-[^/]+\.dist-info/(RECORD|METADATA|WHEEL|top_level.txt|"
                          r"entry_points.txt)$")
# setuptools installs this .pth to select its distutils shim. It lives at
# site-packages root and is therefore absent from the wheel's RECORD; the
# gate accepts it only with these exact bytes.
DISTUTILS_PTH = (
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = "
    "os.environ.get(var, 'local') == 'local'; enabled and "
    "__import__('_distutils_hack').add_shim(); \n"
)
SDIST_PREFIX_RE = re.compile(r"^redacta-[^/]+/")


def _safe_member_name(name: str) -> None:
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or name.startswith(("/", "\\")) or "\\" in name:
        raise GateFailure(f"unsafe archive member path: {name!r}")
    if not name or name in (".", "/"):
        raise GateFailure(f"unsafe archive member path: {name!r}")


def _hash64(blob: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode()


def _hash_hex(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


# --------------------------------------------------------------------------- #
# sdist
# --------------------------------------------------------------------------- #
def audit_sdist(ctx: GateContext, sdist: Path, admitted: dict[str, dict]) -> dict:
    """Audit the raw sdist produced by the PEP 517 backend.

    Closure rule: every admitted packaged-role file must be present with its
    approved hash; every archive member is either such a file or a narrowly
    defined generated metadata file.  Links/devices/absolute paths are
    refused outright.
    """
    packaged = {rel: entry for rel, entry in admitted.items() if entry["role"] in PACKAGED_ROLES}
    found_admitted: set[str] = set()
    generated: list[str] = []
    member_names: list[str] = []

    with tarfile.open(sdist, mode="r:gz") as tar:
        for member in tar.getmembers():
            _safe_member_name(member.name)
            member_names.append(member.name)
            if member.issym() or member.islnk():
                ctx.fail("sdist", "link-member",
                         f"{member.name} is a {('symlink' if member.issym() else 'hardlink')} "
                         f"-> {member.linkname!r}; links outside the closure are refused")
            if not (member.isreg() or member.isdir()):
                ctx.fail("sdist", "special-member",
                         f"{member.name} has non-regular type {member.type!r}")
            if not member.isreg():
                continue
            inner = SDIST_PREFIX_RE.sub("", member.name, count=1)
            if inner == member.name:
                ctx.fail("sdist", "unexpected-prefix",
                         f"{member.name} is not under the canonical sdist root")
            ctx.scan_path_name("sdist", PurePosixPath(inner).parts)
            blob = tar.extractfile(member).read()
            # Canary rules apply to generated metadata too.
            ctx.scan_bytes("sdist", member.name, blob)
            if EGG_INFO_RE.fullmatch(inner) or inner == "PKG-INFO":
                generated.append(inner)
                continue
            if inner == "setup.cfg":
                # Name alone is not enough: the bytes must be the documented
                # skeleton, so a planted setup.cfg cannot ride this rule.
                if blob.decode("utf-8", errors="replace") != SETUP_CFG_SKELETON:
                    ctx.fail("sdist", "setup-cfg-content",
                             "setup.cfg differs from the documented setuptools skeleton")
                generated.append(inner)
                continue
            entry = packaged.get(inner)
            if entry is None:
                ctx.fail("sdist", "unlisted-member",
                         f"{inner} is neither an approved manifest entry nor recognised "
                         f"generated metadata")
            digest = _hash_hex(blob)
            if digest != entry["sha256"]:
                ctx.fail("sdist", "byte-drift",
                         f"{inner} bytes do not match approved hash "
                         f"(approved={entry['sha256'][:12]}, actual={digest[:12]})")
            found_admitted.add(inner)

    missing = sorted(set(packaged) - found_admitted)
    if missing:
        ctx.fail("sdist", "closure-incomplete",
                 f"approved packaged files missing from sdist: {missing}")

    # SOURCES.txt is setuptools' own closure statement: it must contain every
    # packaged file and must never reference an excluded/non-packaged path.
    sources = _read_sources_txt(ctx, sdist)
    listed = {line.strip() for line in sources if line.strip()}
    if not set(packaged) <= listed:
        ctx.fail("sdist", "sources-closure",
                 f"SOURCES.txt omits: {sorted(set(packaged) - listed)}")
    forbidden_listed = sorted(
        line for line in listed
        if line in admitted and admitted[line]["role"] not in PACKAGED_ROLES
    )
    if forbidden_listed:
        ctx.fail("sdist", "sources-leak",
                 f"SOURCES.txt references non-packaged files: {forbidden_listed}")

    result = {
        "path": str(sdist),
        "sha256": _hash_hex(sdist.read_bytes()),
        "members": len(member_names),
        "admitted_files": sorted(found_admitted),
        "generated_metadata": sorted(generated),
        "sources_txt_entries": len(listed),
    }
    ctx.report["sdist_audit"] = result
    return result


def _read_sources_txt(ctx: GateContext, sdist: Path) -> list[str]:
    with tarfile.open(sdist, mode="r:gz") as tar:
        handle = next((tar.extractfile(m) for m in tar.getmembers()
                       if EGG_INFO_RE.fullmatch(SDIST_PREFIX_RE.sub("", m.name, count=1))
                       and m.name.endswith("SOURCES.txt")), None)
        if handle is None:
            ctx.fail("sdist", "sources-missing", "SOURCES.txt not found in sdist")
        return handle.read().decode("utf-8").splitlines()


# --------------------------------------------------------------------------- #
# wheel
# --------------------------------------------------------------------------- #
def audit_wheel(ctx: GateContext, wheel: Path, admitted: dict[str, dict]) -> dict:
    """Audit a wheel: safe members, byte-level mapping, and RECORD integrity."""
    wheel_files = _expected_wheel_mapping(admitted)
    found: set[str] = set()
    generated: list[str] = []
    record_rows: dict[str, tuple[str, str]] = {}

    with zipfile.ZipFile(wheel) as zf:
        for info in zf.infolist():
            _safe_member_name(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            # ZIPs encode symlinks via mode bits; refuse anything non-regular.
            if mode and not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
                ctx.fail("wheel", "non-regular-member",
                         f"{info.filename} has non-regular mode {oct(mode)}")
            if info.is_dir():
                continue
            name = info.filename
            ctx.scan_path_name("wheel", PurePosixPath(name).parts)
            blob = zf.read(name)
            ctx.scan_bytes("wheel", name, blob)
            if name.endswith(".dist-info/RECORD"):
                record_rows = _parse_record(ctx, name, blob.decode("utf-8"))
                generated.append(name)
                continue
            if DIST_INFO_RE.fullmatch(name):
                generated.append(name)
                continue
            entry_rel = wheel_files.get(name)
            if entry_rel is None:
                ctx.fail("wheel", "unlisted-member",
                         f"{name} is not an approved package file or recognised metadata")
            if _hash_hex(blob) != admitted[entry_rel]["sha256"]:
                ctx.fail("wheel", "byte-drift",
                         f"{name} bytes do not match approved hash for {entry_rel}")
            found.add(name)

    expected_names = set(wheel_files)
    if found != expected_names:
        ctx.fail("wheel", "closure-mismatch",
                 f"wheel content mismatch extra={sorted(found - expected_names)} "
                 f"missing={sorted(expected_names - found)}")
    if not record_rows:
        ctx.fail("wheel", "record-missing", "RECORD absent from wheel")

    # Re-verify every RECORD row against the actual zip contents.
    with zipfile.ZipFile(wheel) as zf:
        zip_names = {n for n in zf.namelist() if not n.endswith("/")}
        for row_name, (row_hash, _size) in record_rows.items():
            if row_name not in zip_names:
                ctx.fail("wheel", "record-dangling", f"RECORD lists missing file {row_name}")
            if row_hash:  # RECORD's own row carries an empty hash
                actual = _hash64(zf.read(row_name))
                if actual != row_hash:
                    ctx.fail("wheel", "record-hash",
                             f"RECORD hash mismatch for {row_name}")
        unrecorded = sorted(zip_names - set(record_rows))
        if unrecorded:
            ctx.fail("wheel", "record-incomplete",
                     f"wheel files absent from RECORD: {unrecorded}")

    result = {
        "path": str(wheel),
        "sha256": _hash_hex(wheel.read_bytes()),
        "package_files": sorted(found),
        "generated_metadata": sorted(generated),
        "record_entries": len(record_rows),
    }
    ctx.report["wheel_audit"] = result
    return result


def _expected_wheel_mapping(admitted: dict[str, dict]) -> dict[str, str]:
    """Map wheel member names back to the manifest's package-source entries."""
    mapping: dict[str, str] = {}
    for rel, entry in admitted.items():
        if entry["role"] != "package-source":
            continue
        if not rel.startswith("src/"):
            raise GateFailure(f"package-source outside src/: {rel}")
        wheel_name = rel.removeprefix("src/")
        mapping[wheel_name] = rel
    return mapping


def _parse_record(ctx: GateContext, label: str, text: str) -> dict[str, tuple[str, str]]:
    rows: dict[str, tuple[str, str]] = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if len(row) != 3:
            ctx.fail("wheel", "record-format", f"{label}: malformed RECORD row {row!r}")
        name, digest, size = row
        _safe_member_name(name)
        if name in rows:
            ctx.fail("wheel", "record-duplicate", f"{label}: duplicate RECORD row {name}")
        rows[name] = (digest, size)
    return rows


# --------------------------------------------------------------------------- #
# installed tree
# --------------------------------------------------------------------------- #
def audit_install(ctx: GateContext, install_root: Path, wheel: Path,
                  admitted: dict[str, dict]) -> dict:
    """Verify the unpacked install matches the wheel's RECORD exactly.

    Only the redacta package, its .dist-info and the pinned setuptools .pth
    are in scope: pip/setuptools/wheel bootstrapped into the venv are build
    tooling, not artifacts of this release, and are covered by the wheelhouse
    hash lock instead.
    """
    with zipfile.ZipFile(wheel) as zf:
        record_blob = next(
            zf.read(n) for n in zf.namelist() if n.endswith(".dist-info/RECORD")
        )
        record = _parse_record(ctx, "installed-RECORD", record_blob.decode("utf-8"))
        wheel_bytes = {n: zf.read(n) for n in zf.namelist() if not n.endswith("/")}

    seen: set[str] = set()
    for current, dirs, files in os.walk(install_root):
        # Bytecode caches are interpreter-generated after installation, never
        # part of the wheel; prune them so they cannot mask unrecorded files.
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        base = Path(current)
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                continue
            path = base / name
            if path.is_symlink():
                ctx.fail("install", "symlink", f"installed symlink refused: {path}")
            rel = path.relative_to(install_root).as_posix()
            # Out-of-scope toolchain files: bootstrapped pip/setuptools/wheel
            # plus Python's own site machinery.
            top = PurePosixPath(rel).parts[0]
            if (top in {"pip", "setuptools", "wheel", "_distutils_hack", "pkg_resources"}
                    or top.startswith(("pip-", "setuptools-", "wheel-"))
                    or rel in {"__editable__.pth", "site.py"}):
                continue
            seen.add(rel)
            ctx.scan_path_name("install", PurePosixPath(rel).parts)
            blob = path.read_bytes()
            ctx.scan_bytes("install", rel, blob)
            if rel == "distutils-precedence.pth":
                # Tooling-generated, outside the wheel's RECORD; exact bytes
                # are pinned so nothing else can use this exception.
                if blob.decode("utf-8", errors="replace") != DISTUTILS_PTH:
                    ctx.fail("install", "pth-content",
                             "distutils-precedence.pth differs from pinned setuptools content")
                continue
            if rel.endswith(".dist-info/REQUESTED"):
                # pip marker recording an explicit user request; always empty.
                if blob != b"":
                    ctx.fail("install", "requested-marker",
                             "dist-info/REQUESTED must be empty")
                continue
            if rel.endswith(".dist-info/INSTALLER"):
                # pip writes its installer identity; pin the exact bytes.
                if blob != b"pip\n":
                    ctx.fail("install", "installer-marker",
                             f"unexpected INSTALLER content: {blob!r}")
                continue
            if rel.endswith(".dist-info/direct_url.json"):
                # pip records the local install source. It must be a file://
                # URL pointing at this exact wheel (hash-bound), never an
                # index/remote URL, and must not carry canaries.
                try:
                    payload = json.loads(blob.decode("utf-8"))
                except ValueError:
                    ctx.fail("install", "direct-url", "direct_url.json is not valid JSON")
                url = payload.get("url", "")
                if not url.startswith("file://") or not url.endswith("/" + wheel.name):
                    ctx.fail("install", "direct-url",
                             f"direct_url.json does not name local wheel {wheel.name}: {url!r}")
                recorded_hash = payload.get("archive_info", {}).get("hashes", {}).get("sha256")
                if recorded_hash != hashlib.sha256(wheel.read_bytes()).hexdigest():
                    ctx.fail("install", "direct-url",
                             "direct_url.json hash does not match the audited wheel")
                continue
            if rel not in record:
                ctx.fail("install", "unrecorded-file",
                         f"{rel} exists in install tree but not in wheel RECORD")
            expected_hash, _ = record[rel]
            if expected_hash and _hash64(blob) != expected_hash:
                ctx.fail("install", "install-drift",
                         f"{rel} does not match the wheel RECORD hash")
            # RECORD carries no hash for itself; compare its parsed rows
            # instead of raw bytes (pip may normalise line ordering).
            if rel in wheel_bytes and not rel.endswith(".dist-info/RECORD") \
                    and blob != wheel_bytes[rel]:
                ctx.fail("install", "install-drift", f"{rel} differs from wheel bytes")

    extra_from_record = sorted(set(record) - seen)
    if extra_from_record:
        ctx.fail("install", "missing-installed",
                 f"RECORD files missing from install tree: {extra_from_record}")

    result = {
        "install_root": str(install_root),
        "installed_files": sorted(seen),
        "record_entries": len(record),
        "tooling_pth_allowed": "distutils-precedence.pth",
    }
    ctx.report["install_audit"] = result
    return result
