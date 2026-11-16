import copy
import json
import tempfile
import unittest
from pathlib import Path

from redacta import (
    IdentityConflict,
    KeyRing,
    ManifestIntegrityError,
    Policy,
    PublicationError,
    Publisher,
    ReleaseStateError,
    TRANSFORM_VERSION,
    UnknownKeyError,
)
from redacta.transforms import Transformer, classify

KEY = b"test-key-material-never-use-in-prod-000"
KEY2 = b"rotated-test-key-material-also-32-bytes!!"
FIXTURES = Path(__file__).resolve().parents[1] / "examples"


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.publisher = Publisher(self.root, KEY, key_id="k1")
        self.tables = json.loads((FIXTURES / "tables.json").read_text())
        self.policy = json.loads((FIXTURES / "policy.json").read_text())
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.publisher.close)

    def publish(self, request_id="req-1", tables=None, policy=None):
        return self.publisher.publish(tables or self.tables,
                                      policy or self.policy, request_id)

    # ------------------------------------------------- transform semantics
    def test_suppression_cascades_and_tokens_join(self):
        result = self.publish()
        people = self.publisher.read(result["request_id"], "people")
        visits = self.publisher.read(result["id"], "visits")
        self.assertEqual((len(people), len(visits)), (2, 1))
        self.assertEqual(visits[0]["person_id"], people[0]["id"])
        self.assertNotIn("email", people[0])
        self.assertNotIn("alice@example.test", visits[0]["note"])

    def test_stable_tokens_and_version_digest(self):
        first = self.publish("r1")
        second = self.publish("r2")
        self.assertEqual(self.publisher.read(first["id"], "people"),
                         self.publisher.read(second["id"], "people"))
        changed = copy.deepcopy(self.policy)
        changed["version"] = "v2"
        third = self.publish("r3", policy=changed)
        self.assertNotEqual(first["policy_digest"], third["policy_digest"])

    def test_unknown_fields_fail_before_intent(self):
        self.tables["people"][0]["passport"] = "secret"
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(
            self.publisher.db.execute(
                "SELECT count(*) FROM release_requests").fetchone()[0], 0)

    def test_revoke_survives_restart_and_blocks_reads(self):
        result = self.publish()
        self.publisher.revoke(result["request_id"])
        # Idempotent revocation.
        self.publisher.revoke(result["id"])
        other = Publisher(self.root, KEY, key_id="k1")
        self.addCleanup(other.close)
        with self.assertRaises(ReleaseStateError):
            other.read(result["id"], "people")
        self.assertFalse((self.root / result["id"]).exists())

    def test_checksum_and_signature_detect_tamper(self):
        result = self.publish()
        (self.root / result["id"] / "people.jsonl").write_text("{}\n")
        with self.assertRaises(ManifestIntegrityError):
            self.publisher.read(result["id"], "people")

    def test_date_offset_is_consistent(self):
        t = self.publisher.transformer
        rule = {"op": "date_shift", "days": 20}
        from datetime import date
        a = date.fromisoformat(t.apply("2026-01-01", rule, "u1"))
        b = date.fromisoformat(t.apply("2026-01-10", rule, "u1"))
        self.assertEqual((b - a).days, 9)
        with self.assertRaises(ValueError):
            t.apply("2026-01-01", rule, None)

    def test_key_and_namespaces(self):
        with self.assertRaises(ValueError):
            Transformer(b"short")
        t = self.publisher.transformer
        self.assertNotEqual(t.apply("u1", {"op": "token", "namespace": "a"}),
                            t.apply("u1", {"op": "token", "namespace": "b"}))

    def test_invalid_policies(self):
        for change in ("bucket", "quasi", "link", "path"):
            with self.subTest(change=change):
                p = copy.deepcopy(self.policy)
                if change == "bucket":
                    p["tables"]["people"]["fields"]["age"]["width"] = 0
                if change == "quasi":
                    p["tables"]["people"]["quasi"] = ["email"]
                if change == "link":
                    p["tables"]["visits"]["fields"]["person_id"]["namespace"] = "other"
                if change == "path":
                    p["tables"]["../escape"] = p["tables"].pop("people")
                with self.assertRaises(ValueError):
                    Policy(p)

    def test_policy_cannot_mutate_after_hash(self):
        policy = Policy(self.policy)
        before = policy.digest
        policy.document["tables"].clear()
        self.assertTrue(policy.document["tables"])
        self.assertEqual(before, policy.digest)

    def test_classification_and_negative_bucket(self):
        self.assertEqual(classify({"contact": "a@example.test"})["contact"], "email")
        self.assertEqual(
            self.publisher.transformer.apply(-1, {"op": "bucket", "width": 10}),
            "[-10,0)")
        with self.assertRaises(ValueError):
            self.publisher.transformer.apply(
                float("nan"), {"op": "bucket", "width": 10})

    def test_custom_transform_requires_explicit_policy_permission(self):
        document = {"version": "v1", "tables": {
            "samples": {"fields": {"value": {"op": "initial"}}}}}
        with self.assertRaises(ValueError):
            Policy(document)
        policy = Policy(document, operations={"initial"})
        self.publisher.transformer.extensions["initial"] = \
            lambda value, rule, subject: value[:1]
        released = self.publish("ext", tables={"samples": [{"value": "ABCDE"}]},
                                policy=policy)
        self.assertEqual(self.publisher.read(released["id"], "samples"),
                         [{"value": "A"}])

    def test_cascade_rechecks_k_after_parent_suppression(self):
        policy = copy.deepcopy(self.policy)
        policy["tables"]["visits"].update(k=2, quasi=["note"])
        tables = copy.deepcopy(self.tables)
        tables["visits"][0]["note"] = "same"
        tables["visits"][1]["note"] = "same"
        result = self.publish("cascade", tables=tables, policy=policy)
        # Independent fixed-point and row-count checks.
        self.assertEqual(result["tables"]["people"]["rows"], 2)
        self.assertEqual(result["tables"]["visits"]["rows"], 0)
        self.assertEqual(self.publisher.read(result["id"], "visits"), [])

    def test_tokens_and_date_shifts_normalize_same_subject(self):
        t = self.publisher.transformer
        rule = {"op": "date_shift", "days": 20}
        self.assertEqual(t.apply("2026-01-01", rule, " U1 "),
                         t.apply("2026-01-01", rule, "u1"))

    # ------------------------------------------------- identity protocol
    def test_manifest_carries_full_authenticated_identity(self):
        result = self.publish("req-x")
        identity = result["identity"]
        self.assertEqual(identity["request_id"], "req-x")
        self.assertEqual(identity["key_id"], "k1")
        self.assertEqual(identity["transform_version"], TRANSFORM_VERSION)
        self.assertEqual(identity["policy_digest"], Policy(self.policy).digest)
        self.assertEqual(identity["namespaces"], ["person", "subject"])
        self.assertRegex(identity["input_fingerprint"], r"^[0-9a-f]{64}$")
        envelope = json.loads(
            self.publisher.db.execute(
                "SELECT envelope FROM release_requests WHERE id=?",
                (result["id"],)).fetchone()[0])
        self.assertEqual(envelope["format"],
                         "redacta.authenticated-manifest.v2")
        self.assertEqual(envelope["algorithm"], "HMAC-SHA256")
        self.assertEqual(envelope["key_id"], "k1")
        self.assertTrue(envelope["signature"])

    def test_retry_same_request_returns_original_release(self):
        first = self.publish("idem")
        second = self.publish("idem")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(
            self.publisher.db.execute(
                "SELECT count(*) FROM release_requests").fetchone()[0], 1)

    def test_same_request_new_input_is_rejected(self):
        self.publish("conflict")
        changed = copy.deepcopy(self.tables)
        changed["people"][0]["age"] = 99
        with self.assertRaises(IdentityConflict) as ctx:
            self.publish("conflict", tables=changed)
        self.assertIn("input_fingerprint", str(ctx.exception))

    def test_same_request_new_policy_is_rejected(self):
        self.publish("conflict2")
        changed = copy.deepcopy(self.policy)
        changed["version"] = "different"
        with self.assertRaises(IdentityConflict) as ctx:
            self.publish("conflict2", policy=changed)
        self.assertIn("policy_digest", str(ctx.exception))

    def test_same_request_other_namespaces_rejected(self):
        self.publish("ns1")
        changed = copy.deepcopy(self.policy)
        changed["tables"]["people"]["fields"]["id"]["namespace"] = "citizen"
        changed["tables"]["visits"]["fields"]["person_id"]["namespace"] = "citizen"
        with self.assertRaises(IdentityConflict):
            self.publish("ns1", policy=Policy(changed))

    def test_same_request_other_transform_version_rejected(self):
        self.publish("tv")
        other = Publisher(self.root, KEY, key_id="k1",
                          transform_version="transform-v9")
        self.addCleanup(other.close)
        with self.assertRaises(IdentityConflict):
            other.publish(self.tables, self.policy, "tv")

    def test_key_rotation_preserves_prepared_identities(self):
        first = self.publish("rotate")
        original_identity = copy.deepcopy(first["identity"])
        ring = KeyRing({"k1": KEY, "k2": KEY2}, active_key_id="k2")
        rotated = Publisher(self.root, key_ring=ring)
        self.addCleanup(rotated.close)
        # Old release is still readable and keeps the k1 identity.
        people = rotated.read(first["id"], "people")
        self.assertEqual(len(people), 2)
        self.assertEqual(rotated.status(first["id"])["key_id"], "k1")
        self.assertEqual(
            json.loads(rotated.db.execute(
                "SELECT request_identity FROM release_requests WHERE id=?",
                (first["id"],)).fetchone()[0])["key_id"], "k1")
        # A new request is signed by k2; old identity is untouched.
        second = rotated.publish(self.tables, self.policy, "rotate-2")
        self.assertEqual(second["identity"]["key_id"], "k2")
        self.assertEqual(
            rotated.status(first["id"])["key_id"], "k1")
        self.assertEqual(original_identity["key_id"], "k1")

    def test_unknown_key_fails_closed_on_read(self):
        first = self.publish("foreign")
        stranger = Publisher(self.root,
                             key_ring=KeyRing.single("k9", KEY2))
        self.addCleanup(stranger.close)
        with self.assertRaises(UnknownKeyError):
            stranger.read(first["id"], "people")

    def test_read_requires_active_registered_release(self):
        with self.assertRaises(KeyError):
            self.publisher.read("never-existed", "people")
        result = self.publish("rev")
        self.publisher.revoke(result["request_id"])
        with self.assertRaises(ReleaseStateError):
            self.publisher.read(result["request_id"], "people")

    def test_foreign_complete_directory_is_not_adopted(self):
        # A directory that "looks complete" (files + plain checksum manifest)
        # but has no registered intent must never become readable.
        fake_id = "ab" * 16
        directory = self.root / fake_id
        directory.mkdir(mode=0o700)
        (directory / "people.jsonl").write_text('{"id":"x"}\n')
        (directory / "manifest.json").write_text(
            json.dumps({"id": fake_id, "tables": {
                "people": {"rows": 1, "sha256": "0" * 64}}}))
        with self.assertRaises(KeyError):
            self.publisher.read(fake_id, "people")
        report = self.publisher.recover()
        self.assertEqual(report["recovered"], [])
        # Still unregistered, still unreadable.
        self.assertTrue(directory.exists())
        with self.assertRaises(KeyError):
            self.publisher.read(fake_id, "people")

    def test_prepare_failure_leaves_no_readable_package(self):
        # Field-set mismatch is rejected before the durable intent exists.
        broken = copy.deepcopy(self.tables)
        broken["people"][0]["passport"] = "secret"
        with self.assertRaises(PublicationError):
            self.publish("broken", tables=broken)
        self.assertEqual(
            self.publisher.db.execute(
                "SELECT count(*) FROM release_requests WHERE request_id=?",
                ("broken",)).fetchone()[0], 0)
        self.assertEqual(list(self.root.glob(".stage-*")), [])

    def test_invalid_request_id(self):
        for bad in ("", "bad id", "../x", "x" * 129):
            with self.subTest(bad=bad):
                with self.assertRaises(PublicationError):
                    self.publish(bad)

    def test_no_raw_key_or_token_mapping_persisted(self):
        result = self.publish("secrets")
        raw_db = (self.root / "audit.sqlite").read_bytes()
        self.assertNotIn(KEY, raw_db)
        for path in (self.root / result["id"]).iterdir():
            blob = path.read_bytes()
            self.assertNotIn(KEY, blob)
            self.assertNotIn(b"alice@example.test", blob)
        # Only the non-secret key id label is stored.
        self.assertIn(b"k1", raw_db)
        # No table mapping token -> raw identifier anywhere on disk.
        self.assertNotIn(b"token_map", raw_db)

    def test_recover_revoked_never_resurrects_intact_directory(self):
        result = self.publish("tomb")
        directory = self.root / result["id"]
        self.publisher.revoke(result["request_id"])
        # Simulate an intact old directory reappearing after revocation
        # (e.g. restored from a local snapshot).
        directory.mkdir(mode=0o700)
        (directory / "people.jsonl").write_text('{"id":"ghost"}\n')
        report = self.publisher.recover()
        self.assertIn(result["request_id"], report["revoked_dirs_removed"])
        self.assertEqual(self.publisher.status(result["id"])["status"], "revoked")
        self.assertFalse(directory.exists())
        with self.assertRaises(ReleaseStateError):
            self.publisher.read(result["id"], "people")

    def test_recover_verifies_active_rows(self):
        result = self.publish("healthy")
        report = self.publisher.recover()
        self.assertIn(result["request_id"], report["active_verified"])
        (self.root / result["id"] / "visits.jsonl").write_text("{}\n")
        report = self.publisher.recover()
        self.assertIn(result["request_id"], report["active_corrupt"])

    def test_concurrent_revoke_loses_to_commit_but_tombstone_is_terminal(self):
        # Revoke a preparing intent right after the intent commit: the
        # materialization must observe the tombstone and refuse to activate.
        def revoke_on_intent(event, release_id):
            if event == "intent_committed":
                self.publisher.revoke(release_id)

        with self.assertRaises(ReleaseStateError):
            self.publisher.publish(self.tables, self.policy, "race",
                                   on_event=revoke_on_intent)
        self.assertEqual(self.publisher.status("race")["status"], "revoked")

    def test_concurrent_same_request_id_resolves_to_one_release(self):
        import threading
        outcomes, errors = [], []

        def worker():
            try:
                # Each thread gets its own connection, same durable root.
                with Publisher(self.root, KEY, key_id="k1") as p:
                    outcomes.append(
                        p.publish(self.tables, self.policy, "parallel"))
            except Exception as exc:  # pragma: no cover - surfaced via assertion
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        ids = {m["id"] for m in outcomes}
        self.assertEqual(len(ids), 1)
        self.assertEqual(
            self.publisher.db.execute(
                "SELECT count(*) FROM release_requests WHERE request_id=?",
                ("parallel",)).fetchone()[0], 1)
        self.assertEqual(self.publisher.status("parallel")["status"], "active")


if __name__ == "__main__":
    unittest.main()
