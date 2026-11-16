"""独立有限域枚举器（验收用）。

该枚举器与 :mod:`redacta.synth.solver` 没有任何共享代码路径：它直接在字段
候选域的笛卡尔积上枚举每张表所有可能的多集行组合，再用与
:mod:`redacta.synth.validator` 相同的约束语义做纯函数式判定。只适用于
小有限域，用来交叉验证求解器“有解/无解”的结论与首个见证。
"""
from __future__ import annotations

import itertools

from redacta.synth.spec import compile_spec


def _all_rows(spec):
    names = sorted(spec.fields)
    domains = [list(spec.fields[n].full_domain) for n in names]
    for combo in itertools.product(*domains):
        yield dict(zip(names, combo))


def _unique_ok(spec, rows):
    for constraint in spec.uniques:
        seen = set()
        for row in rows:
            key = tuple(row[f] for f in constraint.fields)
            if any(v is None for v in key):
                continue
            if key in seen:
                return False
            seen.add(key)
    return True


def _fk_ok(compiled, name, rows, tables):
    spec = compiled.tables[name]
    for fk in spec.foreign_keys:
        target = tables[fk.target_table]
        witness = {tuple(row[f] for f in fk.target_fields) for row in target}
        for row in rows:
            values = tuple(row[f] for f in fk.fields)
            nulls = [v is None for v in values]
            if all(nulls):
                if not fk.nullable:
                    return False
                continue
            if any(nulls):
                return False
            if values not in witness:
                return False
    return True


def enumerate_satisfiability(document) -> bool:
    """完整枚举整个表集合，返回是否存在满足全部约束的赋值。"""
    compiled = compile_spec(document)
    per_table = {}
    for name in compiled.table_order:
        spec = compiled.tables[name]
        distinct = list(_all_rows(spec))
        # 行按规范化元组去重后，枚举“可重复选取 spec.rows 行”的全部组合；
        # 唯一/主键约束随后精确过滤，保证语义与求解器一致。
        combos = [list(c) for c in itertools.combinations_with_replacement(
            distinct, spec.rows)] if spec.rows else [[]]
        per_table[name] = [c for c in combos if _unique_ok(spec, c)]

    table_names = list(compiled.table_order)
    table_choices = [per_table[n] for n in table_names]
    for assignment in itertools.product(*table_choices):
        tables = dict(zip(table_names, assignment))
        if all(_fk_ok(compiled, n, tables[n], tables) for n in table_names):
            return True
    return False


def first_solution(document):
    """枚举器自己找到的第一个解（仅用于交叉比对，不参与生产路径）。"""
    compiled = compile_spec(document)
    per_table = {}
    for name in compiled.table_order:
        spec = compiled.tables[name]
        distinct = list(_all_rows(spec))
        combos = [list(c) for c in itertools.combinations_with_replacement(
            distinct, spec.rows)] if spec.rows else [[]]
        per_table[name] = [c for c in combos if _unique_ok(spec, c)]
    table_names = list(compiled.table_order)
    for assignment in itertools.product(*(per_table[n] for n in table_names)):
        tables = dict(zip(table_names, assignment))
        if all(_fk_ok(compiled, n, tables[n], tables) for n in table_names):
            return tables
    return None
