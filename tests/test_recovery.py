"""Process-kill crash matrix and legacy compatibility tests.

Each crash is a real ``os._exit`` in a child process, then a fresh Publisher
in another process/connection attempts retry, read, recover and revoke.
The acceptance rule: a half-published release is never treated as success,
and recovery can never re-release data behind a tombstone.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from redacta import (
    KeyRing,
    ManifestIntegrityError,
    Publisher,
    PublicationError,
    ReleaseStateError,
)
from redacta.identity import LEGACY_MANIFEST_FORMAT

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "tests" / "_crash_worker.py"
FIXTURES = ROOT / "examples"
KEY = b"test-key-material-never-use-in-prod-000"
KEY2 = b"rotated-test-key-material-also-32-bytes!!"


class CrashRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "releases"
        self.tables = json.loads((FIXTURES / "tables.json").read_text())
        self.policy = json.loads((FIXTURES / "policy.json").read_text())
        self.addCleanup(self.tmp.cleanup)

    def publisher(self, ring=None):
        return Publisher(self.root,
                         key_ring=ring or KeyRing.single("k1", KEY))

    def run_worker(self, request_id, crash_at="", *, expect_crash=False):
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"),
                   REDACTA_KEY=KEY.decode(), REDACTA_KEY_ID="k1")
        proc = subprocess.run(
            [sys.executable, str(WORKER), str(self.root), request_id, crash_at],
            env=env, capture_output=True, text=True)
        if expect_crash:
            self.assertEqual(proc.returncode, 99, proc.stderr)
            self.assertIn("INJECTED CRASH", proc.stderr)
        else:
            self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc

    def find_row(self, request_id):
        with self.publisher() as p:
            return p.db.execute(
                "SELECT * FROM release_requests WHERE request_id=?",
                (request_id,)).fetchone()

    # --------------------------------------------------- crash boundaries
    def test_kill_after_intent_commit_is_not_readable_then_retry_completes(self):
        self.run_worker("crash-intent", "intent_committed", expect_crash=True)
        row = self.find_row("crash-intent")
        self.assertEqual(row["status"], "preparing")
        self.assertIsNone(row["envelope"])
        # A new read must be rejected while preparing.
        with self.publisher() as p:
            with self.assertRaises(ReleaseStateError):
                p.read("crash-intent", "people")
        # Same-request retry with inputs rebuilds under the same release id.
        with self.publisher() as p:
            manifest = p.publish(self.tables, self.policy, "crash-intent")
            self.assertEqual(manifest["id"], row["id"])
            self.assertEqual(len(p.read("crash-intent", "people")), 2)

    def test_kill_after_staging_leaves_hidden_stage_only(self):
        self.run_worker("crash-stage", "files_staged", expect_crash=True)
        row = self.find_row("crash-stage")
        self.assertEqual(row["status"], "preparing")
        # Final directory must not exist; only the hidden stage is present.
        self.assertFalse((self.root / row["id"]).exists())
        stages = list(self.root.glob(f".stage-{row['id']}"))
        self.assertEqual(len(stages), 1)
        with self.publisher() as p:
            with self.assertRaises(ReleaseStateError):
                p.read("crash-stage", "people")
        # Input-less recovery cannot rebuild: marked failed, nothing adopted.
        with self.publisher() as p:
            report = p.recover()
            self.assertIn("crash-stage", report["failed"])
        with self.publisher() as p:
            with self.assertRaises(ReleaseStateError):
                p.read("crash-stage", "people")
        # Retry carrying the inputs completes deterministically.
        with self.publisher() as p:
            manifest = p.publish(self.tables, self.policy, "crash-stage")
            self.assertEqual(len(p.read(manifest["id"], "people")), 2)

    def test_kill_after_rename_recovers_from_authenticated_directory(self):
        self.run_worker("crash-rename", "directory_renamed", expect_crash=True)
        row = self.find_row("crash-rename")
        self.assertEqual(row["status"], "preparing")
        directory = self.root / row["id"]
        self.assertTrue(directory.exists())
        # Present on disk but not committed: still not readable.
        with self.publisher() as p:
            with self.assertRaises(ReleaseStateError):
                p.read("crash-rename", "people")
        # The explicit recovery entry point promotes it after verification.
        with self.publisher() as p:
            report = p.recover()
            self.assertEqual(report["recovered"], ["crash-rename"])
        with self.publisher() as p:
            people = p.read("crash-rename", "people")
            visits = p.read("crash-rename", "visits")
        self.assertEqual((len(people), len(visits)), (2, 1))

    def test_recovery_quarantines_tampered_prepared_directory(self):
        self.run_worker("crash-tamper", "directory_renamed", expect_crash=True)
        row = self.find_row("crash-tamper")
        target = self.root / row["id"] / "people.jsonl"
        target.write_text('{"id":"forged"}\n')
        with self.publisher() as p:
            report = p.recover()
            self.assertEqual(report["quarantined"], ["crash-tamper"])
            self.assertEqual(p.status("crash-tamper")["status"], "failed")
            self.assertFalse(target.exists())
            quarantine = list(self.root.glob(".quarantine-*"))
            self.assertEqual(len(quarantine), 1)
            # Failed rows are not readable regardless of directory contents.
            with self.assertRaises(ReleaseStateError):
                p.read("crash-tamper", "people")
        # A retry with the original inputs rebuilds an authentic package.
        with self.publisher() as p:
            manifest = p.publish(self.tables, self.policy, "crash-tamper")
            self.assertEqual(manifest["status"], "active")
            self.assertEqual(len(p.read(manifest["id"], "people")), 2)

    def test_recovery_unknown_key_cannot_adopt_directory(self):
        self.run_worker("crash-foreign-key", "directory_renamed",
                        expect_crash=True)
        row = self.find_row("crash-foreign-key")
        # Open with a ring that does not contain k1.
        stranger = Publisher(self.root,
                             key_ring=KeyRing.single("k9", KEY2))
        try:
            report = stranger.recover()
            self.assertEqual(report["quarantined"], ["crash-foreign-key"])
            with self.assertRaises(PublicationError):
                stranger.read("crash-foreign-key", "people")
        finally:
            stranger.close()
        # Correct key + retry inputs can still rebuild under the same identity.
        with self.publisher() as p:
            manifest = p.publish(self.tables, self.policy,
                                 "crash-foreign-key")
            self.assertEqual(manifest["id"], row["id"])

    def test_revoke_then_retry_and_recover_never_releases_data(self):
        # Kill after rename, then revoke the preparing intent.
        self.run_worker("crash-revoke", "directory_renamed", expect_crash=True)
        row = self.find_row("crash-revoke")
        with self.publisher() as p:
            status = p.revoke("crash-revoke")
            self.assertEqual(status["status"], "revoked")
            # Intact directory removed by revoke.
            self.assertFalse((self.root / row["id"]).exists())
        # Recovery must keep the tombstone even if a directory reappears.
        (self.root / row["id"]).mkdir(mode=0o700)
        with self.publisher() as p:
            report = p.recover()
            self.assertIn("crash-revoke", report["revoked_dirs_removed"])
            self.assertEqual(p.status("crash-revoke")["status"], "revoked")
            with self.assertRaises(ReleaseStateError):
                p.read("crash-revoke", "people")
        # Same-request retry is rejected: tombstone is terminal.
        with self.publisher() as p:
            with self.assertRaises(ReleaseStateError):
                p.publish(self.tables, self.policy, "crash-revoke")

    def test_full_happy_path_in_worker_is_immediately_readable(self):
        proc = self.run_worker("clean")
        release_id = json.loads(proc.stdout)["id"]
        with self.publisher() as p:
            self.assertEqual(p.status(release_id)["status"], "active")
            self.assertEqual(len(p.read(release_id, "people")), 2)

    def test_stale_materialization_lock_from_dead_holder_is_reclaimed(self):
        self.run_worker("crash-lock", "files_staged", expect_crash=True)
        row = self.find_row("crash-lock")
        dead_pid = next(pid for pid in range(999900, 999999)
                        if not self._pid_exists(pid))
        with self.publisher() as p:
            # The killed worker left a real lock row; reassign it to a pid that
            # provably no longer exists.
            updated = p.db.execute(
                "UPDATE materialization_locks SET holder=?, pid=? WHERE release_id=?",
                ("dead-holder", dead_pid, row["id"]))
            self.assertEqual(updated.rowcount, 1)
            p.db.commit()
            report = p.recover()
            # No directory yet and no inputs in recover(): conservative fail,
            # but the stale lock must not block the subsequent retry.
            self.assertIn("crash-lock", report["failed"])
        with self.publisher() as p:
            manifest = p.publish(self.tables, self.policy, "crash-lock")
            self.assertEqual(manifest["status"], "active")
            remaining = p.db.execute(
                "SELECT count(*) FROM materialization_locks").fetchone()[0]
            self.assertEqual(remaining, 0)

    @staticmethod
    def _pid_exists(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    # ------------------------------------------------- legacy compatibility
    def _seed_legacy_v1_release(self):
        """Reproduce the pre-protocol on-disk and SQLite layout."""
        self.root.mkdir(parents=True, exist_ok=True)
        release_id = "cd" * 16
        directory = self.root / release_id
        directory.mkdir(parents=True, exist_ok=True)
        content = b'{"id":"legacy-row"}\n'
        (directory / "people.jsonl").write_bytes(content)
        legacy_manifest = {
            "id": release_id,
            "policy": "0" * 64,
            "policy_version": "legacy",
            "tables": {"people": {
                "rows": 1, "suppressed": 0,
                "sha256": __import__("hashlib").sha256(content).hexdigest()}},
        }
        (directory / "manifest.json").write_text(
            json.dumps({"format": LEGACY_MANIFEST_FORMAT,
                        "manifest": legacy_manifest}))
        import sqlite3
        db = sqlite3.connect(self.root / "audit.sqlite")
        db.executescript(
            "CREATE TABLE policies (digest TEXT PRIMARY KEY, document TEXT);"
            "CREATE TABLE releases (id TEXT PRIMARY KEY, policy TEXT, "
            "status TEXT, manifest TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);")
        db.execute("INSERT INTO releases(id,policy,status,manifest) VALUES (?,?,?,?)",
                   (release_id, "0" * 64, "active",
                    json.dumps(legacy_manifest, sort_keys=True)))
        db.commit()
        db.close()
        return release_id

    def test_legacy_release_requires_explicit_compat_flag(self):
        release_id = self._seed_legacy_v1_release()
        # Default: no v2 identity, and ordinary read cannot see it.
        with self.publisher() as p:
            with self.assertRaises(KeyError):
                p.read(release_id, "people")
            with self.assertRaises(ReleaseStateError):
                p.read_legacy(release_id, "people")
        # Explicit compatibility mark allows a read but grants no v2 identity.
        compat = Publisher(self.root, key_ring=KeyRing.single("k1", KEY),
                           legacy_compat=True)
        try:
            rows = compat.read_legacy(release_id, "people")
            self.assertEqual(rows, [{"id": "legacy-row"}])
            with self.assertRaises(KeyError):
                compat.read(release_id, "people")
            # New protocol publishing still works alongside the legacy table.
            manifest = compat.publish(self.tables, self.policy, "new-era")
            self.assertEqual(manifest["identity"]["key_id"], "k1")
            self.assertEqual(
                compat.status("new-era")["manifest_format"],
                "redacta.authenticated-manifest.v2")
        finally:
            compat.close()

    def test_legacy_checksum_tamper_still_fails_closed(self):
        release_id = self._seed_legacy_v1_release()
        (self.root / release_id / "people.jsonl").write_text('{"id":"x"}\n')
        compat = Publisher(self.root, key_ring=KeyRing.single("k1", KEY),
                           legacy_compat=True)
        try:
            with self.assertRaises(ManifestIntegrityError):
                compat.read_legacy(release_id, "people")
        finally:
            compat.close()


if __name__ == "__main__":
    unittest.main()
