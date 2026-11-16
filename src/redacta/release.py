"""Recoverable, revocable publication protocol.

State machine for every release row (the durable intent is committed to
SQLite *before* any directory is written):

    preparing --commit--> active
    preparing --failure--> failed      (failed rows may be retried/recovered)
    preparing --revoke---> revoked
    active    --revoke---> revoked     (terminal; recovery can never undo it)
    failed    --revoke---> revoked

There is deliberately no cross-media transaction.  Instead the ordering of
single-resource commits makes every crash interval conservative:

  1. intent row committed (status=preparing) -- a killed process leaves a row
     but no readable package; ``recover`` or a same-request retry resolves it;
  2. immutable artifacts staged + atomically renamed into place -- a killed
     process leaves a directory that nothing will adopt without a matching
     intent row *and* a valid authenticated manifest;
  3. status flip to active in one SQLite commit -- the only "readable commit".

A directory that looks complete but has no registered intent, an unknown key
id, or only an ordinary checksum is never auto-adopted.
"""
import hashlib
import json
import os
import re
import shutil
import sqlite3
import time
import uuid
from collections import Counter
from pathlib import Path

from .identity import (
    KEY_ID_RE,
    MANIFEST_FORMAT,
    REQUEST_ID_RE,
    TRANSFORM_VERSION,
    IdentityConflict,
    KeyRing,
    ManifestIntegrityError,
    PublicationError,
    ReleaseStateError,
    collect_namespaces,
    dumps_envelope,
    identity_fingerprint,
    identity_tuple,
    input_fingerprint,
    loads_envelope,
    sign_manifest,
    verify_envelope,
)
from .policy import Policy, canonical
from .transforms import Transformer

# Explicit statuses (the old code only had active/revoked implicitly).
PREPARING = "preparing"
ACTIVE = "active"
REVOKED = "revoked"
FAILED = "failed"

_RELEASE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_TABLE_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


def _fsync_dir(path):
    """Durably persist a rename inside a directory."""
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Publisher:
    """Publish datasets under a recoverable authenticated identity protocol."""

    def __init__(self, root, key=None, *, key_id=None, key_ring=None,
                 transformer=None, transform_version=TRANSFORM_VERSION,
                 legacy_compat=False):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        # Controlled injection only: accept one key plus its id, or a ring.
        if key_ring is not None:
            if key is not None or key_id is not None:
                raise PublicationError("pass either a key ring or a single key")
            self.keys = key_ring
        else:
            if not isinstance(key, bytes) or len(key) < 32:
                raise PublicationError("provide at least 32 bytes of key material")
            if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
                raise PublicationError("an explicit key id is required")
            self.keys = KeyRing.single(key_id, key)
        self.transform_version = transform_version
        self.legacy_compat = bool(legacy_compat)
        active_id, active_material = self.keys.active
        self.transformer = transformer or Transformer(active_material)
        self.db = sqlite3.connect(self.root / "audit.sqlite", timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout=30000")
        self._init_schema()

    # ------------------------------------------------------------------ schema
    def _init_schema(self):
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS release_requests (
              id TEXT PRIMARY KEY,
              request_id TEXT NOT NULL UNIQUE,
              identity_fingerprint TEXT NOT NULL,
              request_identity TEXT NOT NULL,
              status TEXT NOT NULL,
              policy_digest TEXT NOT NULL,
              envelope TEXT,
              created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_release_requests_status
              ON release_requests(status);
            CREATE TABLE IF NOT EXISTS policies (
              digest TEXT PRIMARY KEY,
              document TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS materialization_locks (
              release_id TEXT PRIMARY KEY,
              holder TEXT NOT NULL,
              pid INTEGER NOT NULL,
              acquired TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        # The legacy v1 table is only present in old audit databases.
        self._has_legacy_table = self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='releases'"
        ).fetchone() is not None
        self.db.commit()

    # ------------------------------------------------------------- public API
    def publish(self, tables, policy, request_id, *, on_event=None):
        """Publish one request.

        Retrying the same ``request_id`` returns the original release as long
        as every frozen identity field matches; any difference is rejected.
        A request whose prior attempt was revoked can never be republished.
        """
        request_id = self._validate_request_id(request_id)
        if not isinstance(policy, Policy):
            policy = Policy(policy)
        specs = policy.document["tables"]
        # Closed input contract (fail before an intent row is written).
        if not isinstance(tables, dict) or not tables:
            raise PublicationError("input tables are required")
        if set(tables) != set(specs):
            raise PublicationError("input tables must exactly match the policy")

        active_key_id, _ = self.keys.active
        identity = identity_tuple(
            request_id=request_id,
            input_fp=input_fingerprint(tables),
            policy_digest=policy.digest,
            transform_version=self.transform_version,
            key_id=active_key_id,
            namespaces=collect_namespaces(policy.document),
        )
        fingerprint = identity_fingerprint(identity)

        existing = self._row_by_request(request_id)
        if existing is not None:
            return self._handle_retry(existing, identity, fingerprint, on_event,
                                      tables=tables, policy=policy)

        # Boundary 1: transformer execution + cascading suppression fixed point.
        # Any failure here happens before the durable intent, so no readable
        # package and no audit row can exist afterwards.
        try:
            transformed, totals = self._execute_transforms(tables, specs)
        except BaseException:
            raise
        release_id = uuid.uuid4().hex
        envelope = self._build_envelope(release_id, policy, identity, transformed)

        # Boundary 2: durable intent committed first.  A kill between this
        # commit and the final status flip leaves status=preparing, which is
        # never readable and is resolved by recover()/retry.
        try:
            with self.db:
                self.db.execute(
                    "INSERT OR IGNORE INTO policies VALUES (?,?)",
                    (policy.digest, canonical(policy.document)),
                )
                self.db.execute(
                    "INSERT INTO release_requests"
                    "(id,request_id,identity_fingerprint,request_identity,status,"
                    "policy_digest,envelope) VALUES (?,?,?,?,?,?,?)",
                    (release_id, request_id, fingerprint, canonical(identity),
                     PREPARING, policy.digest, None),
                )
        except sqlite3.IntegrityError:
            # A concurrent worker won the unique request_id insert.  Adjudicate
            # against its row under exactly the same identity rules.
            winner = self._row_by_request(request_id)
            return self._handle_retry(winner, identity, fingerprint, on_event,
                                      tables=tables, policy=policy)
        self._emit(on_event, "intent_committed", release_id)
        # Concurrent winner with the same request id? Adjudicate identically.
        row = self._row_by_request(request_id)
        if row["id"] != release_id:
            return self._handle_retry(row, identity, fingerprint, on_event,
                                      tables=tables, policy=policy)

        return self._materialize_and_commit(row, identity, policy, transformed,
                                            envelope, on_event)

    def read(self, release_or_request_id, table):
        """Read a table only from an active, fully verified release."""
        row = self._row_by_id_or_request(release_or_request_id)
        if row["status"] != ACTIVE:
            raise ReleaseStateError(
                f"release is {row['status']}, not readable")
        manifest = self._verified_manifest(row)
        if table not in manifest["tables"]:
            raise KeyError(table)
        self._verify_file(row["id"], table, manifest["tables"][table]["sha256"])
        content = (self.root / row["id"] / (table + ".jsonl")).read_bytes()
        return [json.loads(line) for line in content.splitlines()]

    def read_legacy(self, release_id, table):
        """Read an old unsigned v1 release under an explicit compatibility mark.

        Legacy data never receives a v2 trusted identity: no envelope is
        synthesized and the row stays in the legacy table.
        """
        if not self.legacy_compat:
            raise ReleaseStateError(
                "legacy releases require legacy_compat to be enabled explicitly")
        if not self._has_legacy_table:
            raise KeyError("unknown release")
        record = self.db.execute(
            "SELECT status,manifest FROM releases WHERE id=?", (release_id,)
        ).fetchone()
        if record is None:
            raise KeyError("unknown release")
        status, raw_manifest = record
        if status != "active":
            raise ReleaseStateError("release is revoked")
        manifest = json.loads(raw_manifest)
        if table not in manifest["tables"]:
            raise KeyError(table)
        path = self.root / release_id / (table + ".jsonl")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != manifest["tables"][table]["sha256"]:
            raise ManifestIntegrityError("legacy release checksum mismatch")
        return [json.loads(line) for line in content.splitlines()]

    def revoke(self, release_or_request_id):
        """Idempotent revocation; the tombstone is terminal.

        The SQLite tombstone commits before local files are removed, so a crash
        in between still leaves every new read rejected.  Recovery never turns
        a tombstone back into active even if the old directory is intact.
        """
        row = self._row_by_id_or_request(release_or_request_id)
        if row["status"] == REVOKED:
            return self.status(row["request_id"])
        with self.db:
            # Conditional update serializes against a concurrent commit/recover.
            cursor = self.db.execute(
                "UPDATE release_requests SET status=?, updated=CURRENT_TIMESTAMP "
                "WHERE id=? AND status!=?",
                (REVOKED, row["id"], REVOKED),
            )
            if cursor.rowcount == 0:
                refreshed = self._row_by_id(row["id"])
                if refreshed["status"] != REVOKED:
                    raise ReleaseStateError("concurrent status change during revoke")
        shutil.rmtree(self.root / row["id"], ignore_errors=True)
        shutil.rmtree(self._stage_path(row["id"]), ignore_errors=True)
        return self.status(row["request_id"])

    def recover(self, *, on_event=None):
        """Resolve every non-terminal release after a crash or restart.

        Same identity and commit rules as publish: only an intent row plus a
        directory whose files match an authenticated manifest can become
        active.  Revoked rows stay revoked no matter how intact the directory.
        """
        report = {"recovered": [], "failed": [], "revoked_dirs_removed": [],
                  "quarantined": [], "active_verified": [], "active_corrupt": []}
        rows = self.db.execute(
            "SELECT * FROM release_requests WHERE status!=? ORDER BY created",
            (REVOKED,),
        ).fetchall()
        for record in rows:
            row = dict(record)
            if row["status"] == ACTIVE:
                outcome = self._verify_active(row)
                report["active_verified" if outcome else "active_corrupt"].append(
                    row["request_id"])
                continue
            # preparing / failed
            result = self._recover_one(row, on_event)
            report[result].append(row["request_id"])
        # Revoked tombstones: an intact old directory must not be resurrected.
        for record in self.db.execute(
            "SELECT id,request_id FROM release_requests WHERE status=?", (REVOKED,)
        ).fetchall():
            row = dict(record)
            directory = self.root / row["id"]
            if directory.exists():
                shutil.rmtree(directory, ignore_errors=True)
                report["revoked_dirs_removed"].append(row["request_id"])
            shutil.rmtree(self._stage_path(row["id"]), ignore_errors=True)
        return report

    def status(self, release_or_request_id):
        row = self._row_by_id_or_request(release_or_request_id)
        envelope = None
        if row["envelope"]:
            envelope = loads_envelope(row["envelope"])
        return {
            "id": row["id"],
            "request_id": row["request_id"],
            "status": row["status"],
            "identity_fingerprint": row["identity_fingerprint"],
            "key_id": (envelope or {}).get("key_id"),
            "manifest_format": (envelope or {}).get("format"),
        }

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ----------------------------------------------------------- transform
    def _execute_transforms(self, tables, specs):
        """Run the Transformer and the cascading suppression fixed point."""
        transformed, totals = {}, {}
        for table, spec in specs.items():
            rows = []
            for row in tables[table]:
                if set(row) != set(spec["fields"]):
                    raise PublicationError(f"{table}: undeclared or missing input fields")
                output = {
                    field: self.transformer.apply(
                        value, spec["fields"][field],
                        row.get(spec.get("subject")))
                    for field, value in row.items()
                    if spec["fields"][field]["op"] != "drop"
                }
                rows.append(output)
            totals[table] = len(rows)
            quasi = spec.get("quasi", [])
            counts = Counter(canonical([row[q] for q in quasi]) for row in rows)
            transformed[table] = [
                row for row in rows
                if counts[canonical([row[q] for q in quasi])] >= spec.get("k", 1)
            ]
        # Cascading link suppression iterated to a fixed point: deleting a
        # parent re-triggers k suppression on children, which may cascade again.
        while True:
            changed = False
            for table, spec in specs.items():
                rows = transformed[table]
                for link in spec.get("links", []):
                    allowed = {r[link["target"]] for r in transformed[link["table"]]}
                    rows = [r for r in rows if r[link["field"]] in allowed]
                quasi = spec.get("quasi", [])
                counts = Counter(canonical([r[q] for q in quasi]) for r in rows)
                rows = [r for r in rows
                        if counts[canonical([r[q] for q in quasi])] >= spec.get("k", 1)]
                changed |= len(rows) != len(transformed[table])
                transformed[table] = rows
            if not changed:
                break
        return transformed, totals

    # ------------------------------------------------------------ publish
    def _build_envelope(self, release_id, policy, identity, transformed):
        tables_manifest = {}
        for table, rows in transformed.items():
            content = "".join(canonical(row) + "\n" for row in rows).encode()
            tables_manifest[table] = {
                "rows": len(rows),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        manifest = {
            "id": release_id,
            "format": MANIFEST_FORMAT,
            "policy_digest": policy.digest,
            "policy_version": policy.document["version"],
            "identity": identity,
            "tables": tables_manifest,
        }
        return sign_manifest(self.keys, identity["key_id"], manifest)

    def _materialize(self, release_id, transformed, envelope, on_event=None):
        """Write immutable artifacts to a stage and atomically rename into place."""
        stage = self._stage_path(release_id)
        destination = self.root / release_id
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(mode=0o700)
        for table, rows in transformed.items():
            content = "".join(canonical(r) + "\n" for r in rows).encode()
            self._write_durable(stage / (table + ".jsonl"), content)
        self._write_durable(
            stage / "manifest.json",
            dumps_envelope(envelope).encode("utf-8"))
        if on_event is not None:
            on_event("files_staged", release_id)
        if destination.exists():
            # Leftover from an earlier attempt; callers only reach this point
            # when the old directory was proven absent or unauthentic.
            shutil.rmtree(destination)
        os.rename(stage, destination)
        _fsync_dir(self.root)
        if on_event is not None:
            on_event("directory_renamed", release_id)

    def _acquire_material_lock(self, release_id, *, timeout=30.0):
        """Serialize writers of one release across connections/processes.

        Waits for an in-flight holder; a holder whose pid no longer exists is
        treated as a crashed worker and its lock reclaimed, so a SIGKILL cannot
        permanently block recovery.
        """
        holder = f"{os.getpid()}-{uuid.uuid4().hex}"
        deadline = time.monotonic() + timeout
        while True:
            try:
                with self.db:
                    self.db.execute(
                        "INSERT INTO materialization_locks VALUES (?,?,?,CURRENT_TIMESTAMP)",
                        (release_id, holder, os.getpid()))
                return True
            except sqlite3.IntegrityError:
                record = self.db.execute(
                    "SELECT holder,pid FROM materialization_locks WHERE release_id=?",
                    (release_id,)).fetchone()
                if record is not None and not self._pid_alive(record["pid"]):
                    with self.db:
                        self.db.execute(
                            "DELETE FROM materialization_locks WHERE release_id=? AND holder=?",
                            (release_id, record["holder"]))
                    continue
                row = self._row_by_id(release_id)
                if row["status"] == ACTIVE:
                    return False
                if time.monotonic() >= deadline:
                    raise ReleaseStateError(
                        "timed out waiting for the materialization lock")
                time.sleep(0.05)

    @staticmethod
    def _pid_alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _release_material_lock(self, release_id):
        self.db.execute(
            "DELETE FROM materialization_locks WHERE release_id=?",
            (release_id,))
        self.db.commit()

    def _materialize_and_commit(self, row, identity, policy, transformed,
                                envelope, on_event):
        release_id = row["id"]
        stage = self._stage_path(release_id)
        locked = self._acquire_material_lock(release_id)
        try:
            if not locked:
                # Another worker finished while we waited for the lock.
                return self._public_manifest(self._row_by_id(release_id))
            self._materialize(release_id, transformed, envelope, on_event)
            return self._commit_active(release_id, envelope, on_event)
        except BaseException:
            # Ordinary failures become an explicit failed intent; hard process
            # kills leave status=preparing for the conservative recovery path.
            shutil.rmtree(stage, ignore_errors=True)
            self._mark_failed(release_id)
            raise
        finally:
            if locked:
                self._release_material_lock(release_id)

    def _commit_active(self, release_id, envelope, on_event):
        # Boundary 3: the single readable commit.  preparing and failed are
        # both non-terminal working states; the conditional WHERE makes a
        # concurrent revoke win, so a tombstone can never be flipped to active.
        with self.db:
            cursor = self.db.execute(
                "UPDATE release_requests SET status=?, envelope=?, "
                "updated=CURRENT_TIMESTAMP WHERE id=? AND status!=?",
                (ACTIVE, dumps_envelope(envelope), release_id, REVOKED),
            )
            if cursor.rowcount == 0:
                row = self._row_by_id(release_id)
                if row["status"] == REVOKED:
                    shutil.rmtree(self.root / release_id, ignore_errors=True)
                    raise ReleaseStateError("request was revoked before commit")
                if row["status"] == ACTIVE and row["envelope"]:
                    return self._public_manifest(row)
                raise ReleaseStateError(
                    f"cannot commit from status {row['status']}")
        self._emit(on_event, "committed_active", release_id)
        return self._public_manifest(self._row_by_id(release_id))

    def _handle_retry(self, row, identity, fingerprint, on_event, *,
                      tables=None, policy=None):
        """Same request id adjudication: identical identity or hard reject."""
        if row["identity_fingerprint"] != fingerprint:
            stored = json.loads(row["request_identity"])
            differences = sorted(
                name for name in identity
                if stored.get(name) != identity.get(name))
            raise IdentityConflict(
                f"request id {identity['request_id']!r} was already registered "
                f"with a different identity; differing fields: {differences}")
        if row["status"] == REVOKED:
            raise ReleaseStateError(
                "request id was revoked; retries cannot republish it")
        if row["status"] == ACTIVE:
            # Re-read: a concurrent winner may have committed since the snapshot.
            refreshed = self._row_by_id(row["id"])
            if refreshed["status"] == ACTIVE:
                return self._public_manifest(refreshed)
            row = refreshed
        # preparing/failed: drive the same conservative recovery transition.
        rebuild = None
        if tables is not None and policy is not None:
            transformed, _ = self._execute_transforms(tables, policy.document["tables"])
            envelope = self._build_envelope(row["id"], policy, identity, transformed)
            rebuild = (transformed, envelope)
        outcome = self._recover_one(row, on_event, expected_identity=identity,
                                    rebuild=rebuild)
        if outcome != "recovered":
            refreshed = self._row_by_id(row["id"])
            if refreshed["status"] == ACTIVE:
                return self._public_manifest(refreshed)
            raise ReleaseStateError(
                f"request could not be recovered (outcome={outcome}, "
                f"status={refreshed['status']})")
        return self._public_manifest(self._row_by_id(row["id"]))

    # ------------------------------------------------------------ recovery
    def _recover_one(self, row, on_event, expected_identity=None, rebuild=None):
        release_id = row["id"]
        destination = self.root / release_id
        identity = json.loads(row["request_identity"])
        if expected_identity is not None and \
                identity_fingerprint(expected_identity) != row["identity_fingerprint"]:
            # Defensive: _handle_retry already checked, but keep one rule here.
            raise IdentityConflict("retry identity mismatch")
        if row["status"] == REVOKED:
            if destination.exists():
                shutil.rmtree(destination, ignore_errors=True)
            return "revoked_dirs_removed"
        if not destination.exists():
            # Without the caller inputs nobody may reconstruct artifacts: stay
            # conservative.  A same-request retry that still holds the inputs can
            # deterministically rebuild under the same id without adopting anything.
            if rebuild is None:
                self._mark_failed(release_id)
                return "failed"
            transformed, envelope = rebuild
            locked = self._acquire_material_lock(release_id)
            if not locked:
                return "recovered"
            try:
                self._materialize(release_id, transformed, envelope, on_event)
                self._commit_active(release_id, envelope, on_event)
                return "recovered"
            except ReleaseStateError:
                raise
            except Exception:
                self._mark_failed(release_id)
                return "failed"
            finally:
                self._release_material_lock(release_id)
        try:
            envelope = loads_envelope(
                (destination / "manifest.json").read_text(encoding="utf-8"))
            manifest = verify_envelope(self.keys, envelope)
            self._assert_manifest_matches(row, manifest, identity)
            for table, spec in manifest["tables"].items():
                self._verify_file(release_id, table, spec["sha256"])
        except (PublicationError, OSError, KeyError) as exc:
            # A tampered/unauthenticated directory is never trusted.  When the
            # retry still carries inputs, replace it with a freshly built,
            # authenticated one under the same identity; otherwise quarantine.
            if rebuild is not None:
                transformed, rebuilt_envelope = rebuild
                locked = self._acquire_material_lock(release_id)
                if not locked:
                    return "recovered"
                try:
                    shutil.rmtree(destination, ignore_errors=True)
                    self._materialize(release_id, transformed, rebuilt_envelope)
                    self._commit_active(release_id, rebuilt_envelope, on_event)
                    return "recovered"
                except ReleaseStateError:
                    raise
                except Exception:
                    self._mark_failed(release_id)
                    return "failed"
                finally:
                    self._release_material_lock(release_id)
            self._quarantine(release_id, reason=str(exc))
            self._mark_failed(release_id)
            self._emit(on_event, "quarantined", release_id)
            return "quarantined"
        # Directory is authentic and complete; use the same conditional commit
        # as the normal publish path, so revoke/recover concurrency is ruled
        # by one identity and one commit rule.
        try:
            self._commit_active(release_id, envelope, on_event)
            return "recovered"
        except ReleaseStateError:
            raise
        except Exception:
            self._mark_failed(release_id)
            return "failed"

    def _verify_active(self, row):
        """Check an active row still matches its authenticated artifacts."""
        try:
            manifest = self._verified_manifest(row)
            for table, spec in manifest["tables"].items():
                self._verify_file(row["id"], table, spec["sha256"])
            return True
        except (PublicationError, OSError, KeyError):
            return False

    def _quarantine(self, release_id, *, reason):
        target = self.root / f".quarantine-{release_id}"
        source = self.root / release_id
        counter = 0
        while target.exists():
            counter += 1
            target = self.root / f".quarantine-{release_id}-{counter}"
        try:
            os.rename(source, target)
            _fsync_dir(self.root)
        except OSError:
            shutil.rmtree(source, ignore_errors=True)
        (target / "QUARANTINE-REASON.txt").write_text(reason, encoding="utf-8")
        return target

    # ------------------------------------------------------------- helpers
    def _verified_manifest(self, row):
        if not row["envelope"]:
            raise ManifestIntegrityError("release has no authenticated manifest")
        envelope = loads_envelope(row["envelope"])
        manifest = verify_envelope(self.keys, envelope)
        self._assert_manifest_matches(row, manifest, json.loads(row["request_identity"]))
        return manifest

    def _assert_manifest_matches(self, row, manifest, identity):
        if manifest.get("id") != row["id"]:
            raise ManifestIntegrityError("manifest id does not match intent row")
        if manifest.get("identity") != identity:
            raise ManifestIntegrityError(
                "manifest identity does not match registered intent")
        if manifest.get("policy_digest") != row["policy_digest"]:
            raise ManifestIntegrityError("manifest policy digest mismatch")
        fingerprint = identity_fingerprint(identity)
        if fingerprint != row["identity_fingerprint"]:
            raise ManifestIntegrityError("identity fingerprint mismatch")

    def _verify_file(self, release_id, table, expected_sha256):
        if not _RELEASE_ID_RE.fullmatch(release_id) or not _TABLE_NAME_RE.fullmatch(table):
            raise PublicationError("unsafe release path")
        path = self.root / release_id / (table + ".jsonl")
        content = path.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected_sha256:
            raise ManifestIntegrityError(f"{table}: checksum mismatch")
        return content

    def _mark_failed(self, release_id):
        try:
            with self.db:
                # Only working states can become failed; tombstones stay.
                self.db.execute(
                    "UPDATE release_requests SET status=?, updated=CURRENT_TIMESTAMP "
                    "WHERE id=? AND status IN (?,?)",
                    (FAILED, release_id, PREPARING, FAILED))
        except sqlite3.Error:
            pass

    def _row_by_request(self, request_id):
        record = self.db.execute(
            "SELECT * FROM release_requests WHERE request_id=?", (request_id,)
        ).fetchone()
        return dict(record) if record else None

    def _row_by_id(self, release_id):
        record = self.db.execute(
            "SELECT * FROM release_requests WHERE id=?", (release_id,)
        ).fetchone()
        if record is None:
            raise KeyError("unknown release")
        return dict(record)

    def _row_by_id_or_request(self, identifier):
        if not isinstance(identifier, str) or not identifier:
            raise PublicationError("invalid release identifier")
        if _RELEASE_ID_RE.fullmatch(identifier):
            record = self.db.execute(
                "SELECT * FROM release_requests WHERE id=?", (identifier,)
            ).fetchone()
            if record is not None:
                return dict(record)
        row = self._row_by_request(identifier)
        if row is None:
            raise KeyError("unknown release")
        return row

    def _public_manifest(self, row):
        envelope = loads_envelope(row["envelope"])
        manifest = verify_envelope(self.keys, envelope)
        return {"id": row["id"], "request_id": row["request_id"],
                "status": row["status"], **manifest}

    @staticmethod
    def _validate_request_id(request_id):
        if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
            raise PublicationError(
                "request id must be 1-128 chars of letters, digits, '_', '.', '-'")
        return request_id

    def _stage_path(self, release_id):
        return self.root / (".stage-" + release_id)

    @staticmethod
    def _write_durable(path, content):
        with open(path, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

    @staticmethod
    def _emit(on_event, event, release_id):
        if on_event is not None:
            on_event(event, release_id)
