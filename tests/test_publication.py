import copy
import json
import tempfile
import unittest
from pathlib import Path
from redacta import Policy, Publisher
from redacta.transforms import Transformer, classify


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.publisher = Publisher(self.root, b"test-key-material-never-use-in-prod-000")
        fixtures = Path(__file__).resolve().parents[1] / "examples"
        self.tables = json.loads((fixtures / "tables.json").read_text())
        self.policy = json.loads((fixtures / "policy.json").read_text())
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.publisher.close)

    def test_suppression_cascades_and_tokens_join(self):
        result = self.publisher.publish(self.tables, self.policy)
        people = self.publisher.read(result["id"], "people")
        visits = self.publisher.read(result["id"], "visits")
        self.assertEqual((len(people), len(visits)), (2, 1))
        self.assertEqual(visits[0]["person_id"], people[0]["id"])
        self.assertNotIn("email", people[0])
        self.assertNotIn("alice@example.test", visits[0]["note"])

    def test_stable_tokens_and_version_digest(self):
        first = self.publisher.publish(self.tables, self.policy)
        second = self.publisher.publish(self.tables, self.policy)
        self.assertEqual(self.publisher.read(first["id"], "people"), self.publisher.read(second["id"], "people"))
        self.policy["version"] = "v2"
        third = self.publisher.publish(self.tables, self.policy)
        self.assertNotEqual(first["policy"], third["policy"])

    def test_unknown_fields_fail_closed(self):
        self.tables["people"][0]["passport"] = "secret"
        with self.assertRaises(ValueError):
            self.publisher.publish(self.tables, self.policy)
        self.assertEqual(self.publisher.db.execute("SELECT count(*) FROM releases").fetchone()[0], 0)

    def test_revoke_survives_restart(self):
        result = self.publisher.publish(self.tables, self.policy)
        self.publisher.revoke(result["id"])
        self.publisher.revoke(result["id"])
        other = Publisher(self.root, b"another-test-key-material-at-least32")
        self.addCleanup(other.close)
        with self.assertRaises(ValueError):
            other.read(result["id"], "people")
        self.assertFalse((self.root / result["id"]).exists())

    def test_checksum_detects_tamper(self):
        result = self.publisher.publish(self.tables, self.policy)
        (self.root / result["id"] / "people.jsonl").write_text("{}\n")
        with self.assertRaises(ValueError):
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
                if change == "bucket": p["tables"]["people"]["fields"]["age"]["width"] = 0
                if change == "quasi": p["tables"]["people"]["quasi"] = ["email"]
                if change == "link": p["tables"]["visits"]["fields"]["person_id"]["namespace"] = "other"
                if change == "path": p["tables"]["../escape"] = p["tables"].pop("people")
                with self.assertRaises(ValueError): Policy(p)

    def test_policy_cannot_mutate_after_hash(self):
        policy = Policy(self.policy)
        before = policy.digest
        policy.document["tables"].clear()
        self.assertTrue(policy.document["tables"])
        self.assertEqual(before, policy.digest)

    def test_classification_and_negative_bucket(self):
        self.assertEqual(classify({"contact": "a@example.test"})["contact"], "email")
        self.assertEqual(self.publisher.transformer.apply(-1, {"op": "bucket", "width": 10}), "[-10,0)")
        with self.assertRaises(ValueError):
            self.publisher.transformer.apply(float("nan"), {"op": "bucket", "width": 10})

    def test_custom_transform_requires_explicit_policy_permission(self):
        document = {"version": "v1", "tables": {"samples": {"fields": {"value": {"op": "initial"}}}}}
        with self.assertRaises(ValueError): Policy(document)
        policy = Policy(document, operations={"initial"})
        self.publisher.transformer.extensions["initial"] = lambda value, rule, subject: value[:1]
        released = self.publisher.publish({"samples": [{"value": "ABCDE"}]}, policy)
        self.assertEqual(self.publisher.read(released["id"], "samples"), [{"value": "A"}])

    def test_cascade_rechecks_k_after_parent_suppression(self):
        self.policy["tables"]["visits"].update(k=2, quasi=["note"])
        self.tables["visits"][0]["note"] = "same"
        self.tables["visits"][1]["note"] = "same"
        result = self.publisher.publish(self.tables, self.policy)
        self.assertEqual(self.publisher.read(result["id"], "visits"), [])

    def test_tokens_and_date_shifts_normalize_same_subject(self):
        t = self.publisher.transformer
        rule = {"op": "date_shift", "days": 20}
        self.assertEqual(t.apply("2026-01-01", rule, " U1 "), t.apply("2026-01-01", rule, "u1"))


if __name__ == "__main__":
    unittest.main()
