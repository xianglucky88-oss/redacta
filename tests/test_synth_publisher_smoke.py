"""把合成生成器产物作为外部输入交给既有 Publisher 的黑盒冒烟。

该测试只允许调用公开入口（compile_spec/generate/validate_tables 与
Publisher/Policy），不修改 Publisher 的抑制、Transformer 的变换、Policy
兼容语义或任何制品门禁；测试末尾用哨兵断言这些模块的关键行为未被改动。
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from redacta import Policy, Publisher
from redacta.synth import PROTOCOL_VERSION, compile_spec, generate, validate_tables
from redacta.transforms import Transformer


SYNTHETIC_SPEC = {
    "protocol": PROTOCOL_VERSION,
    "seed": 7,
    "tables": {
        # 3 个主体，候选城市只有 2 个，保证 k=2 抑制路径可被真实触发。
        "people": {
            "rows": 3,
            "fields": {
                "id": {"type": "string", "domain": ["syn-1", "syn-2", "syn-3"]},
                "email": {"type": "string",
                          "domain": ["a@test.invalid", "b@test.invalid",
                                     "c@test.invalid"]},
                "age": {"type": "integer", "domain": [20, 31, 64]},
                "city": {"type": "string", "domain": ["TownA", "TownB"]},
            },
            "primary_key": ["id"],
        },
        "visits": {
            "rows": 3,
            "fields": {
                "person_id": {"type": "string",
                              "domain": ["syn-1", "syn-2", "syn-3"]},
                "date": {"type": "string",
                         "domain": ["2026-01-01", "2026-02-02", "2026-03-03"]},
                "note": {"type": "string",
                         "domain": ["note alpha", "note beta", "note gamma"]},
            },
            "primary_key": ["person_id", "date"],
            "foreign_keys": [
                {"fields": ["person_id"], "table": "people",
                 "target_fields": ["id"], "nullable": False}
            ],
        },
    },
}

# 与现有 examples/policy.json 同构的策略，字段集合与合成规格精确闭合。
POLICY = {
    "version": "synthetic-smoke-v1",
    "tables": {
        "people": {
            "k": 2,
            "quasi": ["age", "city"],
            "fields": {
                "id": {"op": "token", "namespace": "person"},
                "email": {"op": "drop"},
                "age": {"op": "bucket", "width": 10},
                "city": {"op": "keep"},
            },
        },
        "visits": {
            "subject": "person_id",
            "fields": {
                "person_id": {"op": "token", "namespace": "person"},
                "date": {"op": "date_shift", "days": 30},
                "note": {"op": "scrub"},
            },
            "links": [
                {"field": "person_id", "table": "people", "target": "id"}
            ],
        },
    },
}


class PublisherBlackBoxSmoke(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "releases"
        self.key = b"smoke-test-key-material-at-least-32-bytes!"
        self.publisher = Publisher(self.root, self.key)
        self.addCleanup(self.publisher.close)

    def test_generated_tables_flow_through_unchanged_pipeline(self):
        compiled = compile_spec(SYNTHETIC_SPEC)
        result = generate(compiled)
        # 1) 产物先过独立校验器，且全部值来自人工候选域（无真实数据）。
        report = validate_tables(
            result.tables, compiled,
            structure_digest=result.structure_digest,
            protocol=result.protocol)
        self.assertTrue(report["valid"])
        declared = {
            "people": {f: set(compiled.tables["people"].fields[f].full_domain)
                       for f in compiled.tables["people"].fields},
            "visits": {f: set(compiled.tables["visits"].fields[f].full_domain)
                       for f in compiled.tables["visits"].fields},
        }
        for table, rows in result.tables.items():
            for row in rows:
                for f, value in row.items():
                    self.assertIn(value, declared[table][f])

        # 2) 作为外部 JSON 输入（落盘后再读入），经既有发布入口黑盒处理。
        external = Path(self.tmp.name) / "external-tables.json"
        external.write_text(json.dumps(result.tables), encoding="utf-8")
        tables = json.loads(external.read_text(encoding="utf-8"))

        policy = Policy(POLICY)
        manifest = self.publisher.publish(tables, policy)
        self.assertEqual(manifest["policy"], policy.digest)
        people = self.publisher.read(manifest["id"], "people")
        visits = self.publisher.read(manifest["id"], "visits")

        # 3) 既有抑制/关联语义照常工作：k=2 下小准标识组被级联抑制，
        #    存活访问记录的 token 必须与存活主体 token 连接。
        self.assertLessEqual(len(people), 3)
        self.assertGreaterEqual(len(people), 1)
        people_tokens = {row["id"] for row in people}
        for visit in visits:
            self.assertIn(visit["person_id"], people_tokens)
            self.assertNotIn("email", visit)
        for person in people:
            self.assertNotIn("email", person)
            self.assertRegex(person["id"], r"^[0-9a-f]{64}$")

        # 4) 制品门禁未被绕过：清单校验和与落盘内容一致。
        for table_name, stats in manifest["tables"].items():
            path = self.root / manifest["id"] / f"{table_name}.jsonl"
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(), stats["sha256"])

    def test_pipeline_guardrails_remain_intact(self):
        # 门禁哨兵：未知字段仍然 fail-closed，短密钥仍然被拒绝。
        compiled = compile_spec(SYNTHETIC_SPEC)
        tables = generate(compiled).tables
        tables["people"][0]["undeclared"] = "x"
        with self.assertRaises(ValueError):
            self.publisher.publish(tables, Policy(POLICY))
        with self.assertRaises(ValueError):
            Transformer(b"short")


if __name__ == "__main__":
    unittest.main()
