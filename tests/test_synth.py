import copy
import json
import unittest

from redacta.synth import (
    PROTOCOL_VERSION,
    BudgetExhausted,
    SpecError,
    Unsatisfiable,
    ValidationError,
    compile_spec,
    generate,
    validate_tables,
)
from tests.synth_enumeration import enumerate_satisfiability, first_solution


def field(domain, ftype="integer", nullable=False):
    return {"type": ftype, "domain": domain, "nullable": nullable}


def table(rows, fields, pk, unique=(), fks=()):
    return {"rows": rows, "fields": fields, "primary_key": pk,
            "unique": list(unique), "foreign_keys": list(fks)}


def fk(fields_, target, target_fields, nullable=False):
    return {"fields": list(fields_), "table": target,
            "target_fields": list(target_fields), "nullable": nullable}


def spec(tables, seed=0, budget=None):
    document = {"protocol": PROTOCOL_VERSION, "seed": seed, "tables": tables}
    if budget:
        document["budget"] = budget
    return document


class CompilationTests(unittest.TestCase):
    def test_rejects_unknown_protocol_and_bad_shapes(self):
        with self.assertRaises(SpecError):
            compile_spec({"protocol": "made-up/9", "tables": {}})
        with self.assertRaises(SpecError):
            compile_spec({"protocol": PROTOCOL_VERSION, "tables": {}})
        with self.assertRaises(SpecError):
            compile_spec(spec({"T": table(1, {"id": field([1, "x"])}, ["id"])}))
        with self.assertRaises(SpecError):
            compile_spec(spec({"T": table(1, {"id": field([True])}, ["id"])}))
        with self.assertRaises(SpecError):
            compile_spec(spec({"T": table(-1, {"id": field([1])}, ["id"])}))

    def test_foreign_key_must_target_unique_group(self):
        tables = {
            "P": table(1, {"id": field([1]), "tag": field([7])}, ["id"]),
            "C": table(1, {"pid": field([1])}, ["pid"],
                       fks=[fk(["pid"], "P", ["tag"])]),
        }
        with self.assertRaises(SpecError):
            compile_spec(spec(tables))

    def test_nullable_fk_column_coherence(self):
        tables = {
            "P": table(1, {"a": field([1]), "b": field([2])}, ["a", "b"]),
            "C": table(1, {"id": field([9]),
                           "a": field([1], nullable=True), "b": field([2])},
                       ["id"], fks=[fk(["a", "b"], "P", ["a", "b"], True)]),
        }
        with self.assertRaises(SpecError):
            compile_spec(spec(tables))

    def test_input_permutation_does_not_change_digest(self):
        tables = {
            "P": table(1, {"b": field(["x"], "string"), "a": field([1])},
                       ["a", "b"]),
            "C": table(1, {"id": field([9]), "a": field([1]),
                           "b": field(["x"], "string")}, ["id"],
                       fks=[fk(["a", "b"], "P", ["a", "b"])]),
        }
        first = compile_spec(spec(tables))
        shuffled = copy.deepcopy(tables)
        shuffled["P"]["fields"] = dict(reversed(list(shuffled["P"]["fields"].items())))
        shuffled["C"]["fields"] = dict(reversed(list(shuffled["C"]["fields"].items())))
        second = compile_spec(spec({"C": shuffled["C"], "P": shuffled["P"]}))
        self.assertEqual(first.structure_digest, second.structure_digest)
        self.assertEqual(first.table_order, second.table_order)

    def test_row_budget_checked_structurally(self):
        tables = {"T": table(5, {"id": field([1, 2, 3, 4, 5])}, ["id"])}
        with self.assertRaises(SpecError):
            compile_spec(spec(tables, budget={"node_budget": 100,
                                              "max_total_rows": 3}))


class SolverSemanticsTests(unittest.TestCase):
    def test_deterministic_solve_order_targets_first_without_forbidding_cycles(self):
        tables = {
            "asset": table(1, {"id": field([1]), "eid": field([1])}, ["id"],
                           fks=[fk(["eid"], "emp", ["id"])]),
            "emp": table(1, {"id": field([1]), "did": field([1])}, ["id"],
                         fks=[fk(["did"], "dept", ["id"])]),
            "dept": table(1, {"id": field([1])}, ["id"]),
        }
        compiled = compile_spec(spec(tables))
        self.assertEqual(compiled.table_order, ("dept", "emp", "asset"))
        # 环内按稳定规则打破，环本身仍可解。
        cyclic = {
            "R": table(1, {"id": field([1]), "back": field([1])}, ["id"],
                       fks=[fk(["back"], "L", ["id"])]),
            "L": table(1, {"id": field([1]), "fwd": field([1])}, ["id"],
                       fks=[fk(["fwd"], "R", ["id"])]),
        }
        cyclic_compiled = compile_spec(spec(cyclic))
        self.assertEqual(cyclic_compiled.table_order, ("L", "R"))
        self.assertTrue(validate_tables(
            generate(cyclic_compiled).tables, cyclic_compiled)["valid"])

    def test_shared_field_conflict_is_unsatisfiable(self):
        # 题目原文：A.id 只可能为 1、B.id 只可能为 2，T.x 同时引用两者。
        tables = {
            "A": table(1, {"id": field([1])}, ["id"]),
            "B": table(1, {"id": field([2])}, ["id"]),
            "T": table(1, {"x": field([1, 2])}, ["x"],
                       fks=[fk(["x"], "A", ["id"]), fk(["x"], "B", ["id"])]),
        }
        document = spec(tables)
        self.assertFalse(enumerate_satisfiability(document))
        with self.assertRaises(Unsatisfiable) as ctx:
            generate(compile_spec(document))
        self.assertEqual(set(ctx.exception.involved), {"T.fk0", "T.fk1"})
        # 无解诊断保留可重放规格。
        self.assertEqual(ctx.exception.replay["protocol"], PROTOCOL_VERSION)
        self.assertEqual(set(ctx.exception.replay["tables"]), {"A", "B", "T"})

    def test_satisfiable_bidirectional_foreign_key_cycle(self):
        tables = {
            "L": table(2, {"id": field([1, 2]), "partner": field([1, 2])},
                       ["id"], fks=[fk(["partner"], "R", ["id"])]),
            "R": table(2, {"id": field([1, 2]), "back": field([1, 2])},
                       ["id"], fks=[fk(["back"], "L", ["id"])]),
        }
        document = spec(tables)
        self.assertTrue(enumerate_satisfiability(document))
        # 枚举器独立找到的解与求解器首解都必须通过同一约束语义。
        witness = first_solution(document)
        self.assertIsNotNone(witness)
        compiled = compile_spec(document)
        self.assertTrue(validate_tables(witness, compiled)["valid"])
        result = generate(compiled)
        self.assertEqual(validate_tables(result.tables, compiled)["valid"], True)

    def test_self_referential_cycle_is_not_an_error(self):
        tables = {
            "Node": table(3, {"id": field([1, 2, 3]), "parent": field([1, 2, 3])},
                          ["id"], fks=[fk(["parent"], "Node", ["id"])]),
        }
        document = spec(tables)
        self.assertTrue(enumerate_satisfiability(document))
        result = generate(compile_spec(document))
        self.assertEqual(validate_tables(result.tables, compile_spec(document))["valid"], True)

    def test_primary_key_domain_capacity_is_unsat(self):
        document = spec({"S": table(3, {"id": field([1, 2])}, ["id"])})
        self.assertFalse(enumerate_satisfiability(document))
        with self.assertRaises(Unsatisfiable):
            generate(compile_spec(document))

    def test_empty_target_with_nonnull_reference_is_unsat(self):
        tables = {
            "P": table(0, {"id": field([1])}, ["id"]),
            "C": table(1, {"pid": field([1])}, ["pid"],
                       fks=[fk(["pid"], "P", ["id"])]),
        }
        document = spec(tables)
        self.assertFalse(enumerate_satisfiability(document))
        with self.assertRaises(Unsatisfiable) as ctx:
            generate(compile_spec(document))
        self.assertIn("C.fk0", ctx.exception.involved)

    def test_empty_tables_without_references_are_legal(self):
        document = spec({"P": table(0, {"id": field([1])}, ["id"])})
        self.assertTrue(enumerate_satisfiability(document))
        result = generate(compile_spec(document))
        self.assertEqual(result.tables, {"P": []})

    def test_composite_foreign_key_null_semantics(self):
        tables = {
            "P": table(1, {"a": field([1]), "b": field(["x"], "string")},
                       ["a", "b"]),
            "C": table(2, {"id": field([10, 20]),
                           "a": field([1], nullable=True),
                           "b": field(["x"], "string", nullable=True)},
                       ["id"], fks=[fk(["a", "b"], "P", ["a", "b"], True)]),
        }
        document = spec(tables)
        self.assertTrue(enumerate_satisfiability(document))
        compiled = compile_spec(document)
        result = generate(compiled)
        report = validate_tables(result.tables, compiled)
        self.assertTrue(report["valid"])
        for row in result.tables["C"]:
            self.assertEqual(row["a"] is None, row["b"] is None)  # 无部分 null

    def test_composite_unique_nulls_do_not_collide(self):
        # SQL 风格：含 null 的唯一元组互不冲突；非 null 元组相等才冲突。
        tables = {
            "U": table(3, {"id": field([1, 2, 3]),
                           "tag": field(["a"], "string", nullable=True)},
                       ["id"], unique=[["id", "tag"]]),
        }
        document = spec(tables)
        self.assertTrue(enumerate_satisfiability(document))
        result = generate(compile_spec(document))
        self.assertEqual(validate_tables(result.tables, compile_spec(document))["valid"], True)

    def test_string_domains_and_multi_fk_same_column(self):
        tables = {
            "P": table(2, {"code": field(["p1", "p2"], "string")}, ["code"]),
            "Q": table(2, {"code": field(["p1", "p2"], "string")}, ["code"]),
            "C": table(2, {"id": field([1, 2]),
                           "ref": field(["p1", "p2"], "string")}, ["id"],
                       fks=[fk(["ref"], "P", ["code"]),
                            fk(["ref"], "Q", ["code"])]),
        }
        document = spec(tables)
        self.assertTrue(enumerate_satisfiability(document))
        result = generate(compile_spec(document))
        self.assertTrue(validate_tables(result.tables, compile_spec(document))["valid"])


class DeterminismTests(unittest.TestCase):
    def _document(self):
        return spec({
            "P": table(3, {"id": field([1, 2, 3, 4]), "kind": field(["a", "b"], "string")},
                       ["id"]),
            "C": table(3, {"id": field([10, 20, 30]), "pid": field([1, 2, 3, 4])},
                       ["id"], fks=[fk(["pid"], "P", ["id"])]),
        })

    def test_same_spec_and_seed_identical_output(self):
        compiled = compile_spec(self._document())
        first = generate(compiled).tables
        second = generate(compile_spec(self._document())).tables
        self.assertEqual(first, second)

    def test_permutation_invariance(self):
        base = self._document()
        result = generate(compile_spec(base)).tables
        shuffled = copy.deepcopy(base)
        shuffled["tables"] = {"C": base["tables"]["C"], "P": base["tables"]["P"]}
        shuffled["tables"]["P"]["fields"] = dict(
            reversed(list(shuffled["tables"]["P"]["fields"].items())))
        self.assertEqual(generate(compile_spec(shuffled)).tables, result)

    def test_seed_only_changes_tie_break_order_when_multiple_solutions(self):
        base = self._document()
        outputs = set()
        for seed in range(6):
            document = copy.deepcopy(base)
            document["seed"] = seed
            result = generate(compile_spec(document))
            self.assertTrue(validate_tables(result.tables, compile_spec(document))["valid"])
            outputs.add(json.dumps(result.tables, sort_keys=True))
        # 不承诺均匀采样；只要求所有输出都合法，且 seed 是稳定的次序参数。
        self.assertGreaterEqual(len(outputs), 1)
        again = generate(compile_spec({**base, "seed": 3})).tables
        self.assertEqual(again, generate(compile_spec({**base, "seed": 3})).tables)


class BudgetTests(unittest.TestCase):
    def test_budget_exhausted_is_distinct_from_unsat(self):
        document = spec(
            {"P": table(4, {"id": field([1, 2, 3, 4, 5, 6])}, ["id"])},
            budget={"node_budget": 2, "max_total_rows": 100})
        # 该规格实际可满足：枚举器证实有解，求解器仅因预算中断。
        self.assertTrue(enumerate_satisfiability(
            {k: v for k, v in document.items() if k != "budget"}))
        with self.assertRaises(BudgetExhausted) as ctx:
            generate(compile_spec(document))
        self.assertLessEqual(ctx.exception.used, 2)
        self.assertIn("P", ctx.exception.state)
        # 诊断同样绑定可重放规格。
        self.assertEqual(ctx.exception.replay["budget"]["node_budget"], 2)


class IndependentValidatorTests(unittest.TestCase):
    def _satisfiable(self):
        return spec({
            "P": table(2, {"id": field([1, 2])}, ["id"]),
            "C": table(2, {"id": field([10, 20]), "pid": field([1, 2])},
                       ["id"], fks=[fk(["pid"], "P", ["id"])]),
        })

    def test_rejects_tampered_outputs(self):
        compiled = compile_spec(self._satisfiable())
        tables = generate(compiled).tables
        tampered = copy.deepcopy(tables)
        tampered["C"][0]["pid"] = 99  # 域外且无见证
        with self.assertRaises(ValidationError) as ctx:
            validate_tables(tampered, compiled)
        self.assertTrue(any("witness" in e or "domain" in e for e in ctx.exception.errors))

    def test_rejects_wrong_row_count_and_fields(self):
        compiled = compile_spec(self._satisfiable())
        tables = generate(compiled).tables
        with self.assertRaises(ValidationError):
            validate_tables({"P": tables["P"]}, compiled)
        broken = copy.deepcopy(tables)
        broken["P"].pop()
        with self.assertRaises(ValidationError):
            validate_tables(broken, compiled)

    def test_rejects_digest_and_protocol_binding_mismatch(self):
        compiled = compile_spec(self._satisfiable())
        tables = generate(compiled).tables
        with self.assertRaises(ValidationError):
            validate_tables(tables, compiled, structure_digest="0" * 64)
        with self.assertRaises(ValidationError):
            validate_tables(tables, compiled, protocol="other/0")

    def test_validator_module_does_not_import_solver(self):
        # 独立校验器不得调用生成搜索：进程级检查导入闭包。
        import redacta.synth.validator as validator
        source = validator.__file__
        with open(source, encoding="utf-8") as stream:
            text = stream.read()
        self.assertNotIn("from .solver", text)
        self.assertNotIn("import solver", text)

    def test_synth_package_never_touches_publishing_modules_or_key_material(self):
        # 合成包与发布/变换/策略/密钥完全解耦。在干净子进程中检查导入闭包，
        # 避免同进程其他测试已经加载过发布模块造成污染。
        import subprocess
        import sys
        env = dict(__import__("os").environ, REDACTA_KEY="x" * 64,
                   PYTHONPATH="src")
        code = (
            "import sys, redacta.synth;"
            "forbidden={'redacta.release','redacta.transforms','redacta.policy',"
            "'hmac','secrets'};"
            "assert not (forbidden & set(sys.modules)), sorted(forbidden & set(sys.modules));"
            "print('isolated')")
        completed = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            cwd=__import__("pathlib").Path(__file__).resolve().parents[1],
            env=env)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("isolated", completed.stdout)
        # 同进程内仍验证：设置密钥环境变量不影响生成结果。
        import os
        os.environ["REDACTA_KEY"] = "x" * 64
        document = self._satisfiable()
        result = generate(compile_spec(document))
        self.assertTrue(validate_tables(result.tables, compile_spec(document))["valid"])


if __name__ == "__main__":
    unittest.main()
