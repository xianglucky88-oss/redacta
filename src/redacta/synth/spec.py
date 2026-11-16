"""人工合成规格的规范化与约束编译。

本模块只处理调用方手写的合成规格（synthetic specification）：

* 不读取任何真实数据行；
* 不读取 HMAC 密钥，也不导入发布/变换/策略模块；
* Policy 不是本模块的输入，更不是一种生成约束语言。

一张表独立声明：精确行数、每个字段的有限候选域与可空性、非空复合主键、
复合唯一约束和外键。所有跨表约束在 :mod:`redacta.synth.solver` 中对整个
表集合同时求解，这里只做结构编译与确定性规范化。

确定语义（详见 README「合成数据生成器」一节）：

* 复合外键所有列均为 ``null`` 时，仅当该外键显式声明 ``"nullable": true``
  才允许“不建立引用”；任何部分为 null 的复合外键一律拒绝；
* 复合唯一约束采用 SQL 风格语义：含 null 的元组互不冲突，两条非 null
  元组完全相等才冲突；主键非空，因此主键元组永远按相等去重；
* 主键候选域容量小于行数 => 无解（由求解器穷尽后报告，或由编译期的
  可靠容量预检提前报告，二者同为“矛盾”而非“预算耗尽”）；
* 空目标表上存在非空引用 => 无解；
* 有环依赖（含自引用）不是错误，搜索把所有外键当作整个表集合上的见证，
  允许前向引用，环可以被满足。
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

# 生成协议版本。搜索次序、输出封装、规格摘要算法等协议面的任何变化都必须
# 提升该版本；同一 (规范化规格, seed, 协议版本) 必须产生相同数据。
PROTOCOL_VERSION = "redacta-synth/1"

_TABLE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_FIELD_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_TYPES = {"string", "integer"}


class SpecError(ValueError):
    """规格在结构上不合法（区别于结构合法但约束无解）。"""


def canonical(value) -> str:
    """与项目其他入口一致的确定性 JSON 规范化文本（不依赖 policy 模块）。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class FieldSpec:
    name: str
    type: str
    # 非空候选域；已去重并按类型规范化排序。空域是合法规格，通常导致无解。
    domain: tuple
    nullable: bool

    @property
    def full_domain(self) -> tuple:
        return self.domain + ((None,) if self.nullable else ())


@dataclass(frozen=True)
class ForeignKey:
    name: str
    fields: tuple            # 本表字段，按名称排序后的声明顺序保留
    target_table: str
    target_fields: tuple
    nullable: bool           # 显式可空：允许全 null 不建立引用


@dataclass(frozen=True)
class UniqueConstraint:
    name: str
    fields: tuple


@dataclass(frozen=True)
class TableSpec:
    name: str
    rows: int
    fields: dict
    primary_key: tuple
    uniques: tuple           # 含主键派生项
    foreign_keys: tuple


@dataclass(frozen=True)
class Budget:
    # 求解中允许尝试的完整行赋值次数；耗尽 => 未求得（不是矛盾）。
    node_budget: int
    # 输出表集合允许的总行数预算；超出 => 结构上无法在预算内交付。
    max_total_rows: int


@dataclass(frozen=True)
class CompiledSpec:
    tables: dict
    # 确定性求解顺序：最小化前向外键引用的稳定拓扑序（环内按表名打破），
    # 使被引用目标尽量先填充；输入排列不影响该顺序。
    table_order: tuple
    # 规范化后的表名字典序，用于摘要与输出。
    sorted_names: tuple
    seed: int
    budget: Budget
    # 结构摘要只覆盖协议与表结构，不覆盖 seed / 预算（搜索参数）。
    structure_digest: str
    # 可重放的规范化规格（不含 seed 与预算）。
    replay: dict

    def to_replay_document(self) -> dict:
        """无解诊断里携带的完整可重放规格（含 seed 与预算）。"""
        return {
            "protocol": PROTOCOL_VERSION,
            "seed": self.seed,
            "budget": {"node_budget": self.budget.node_budget,
                       "max_total_rows": self.budget.max_total_rows},
            "tables": self.replay["tables"],
        }


def _is_int(value) -> bool:
    # JSON 的 true/false 不是整数候选。
    return isinstance(value, int) and not isinstance(value, bool)


def _compile_field(table: str, name: str, raw: dict) -> FieldSpec:
    if not isinstance(name, str) or not _FIELD_NAME.fullmatch(name):
        raise SpecError(f"table {table}: invalid field name {name!r}")
    if not isinstance(raw, dict):
        raise SpecError(f"table {table}.{name}: field declaration must be an object")
    ftype = raw.get("type")
    if ftype not in _TYPES:
        raise SpecError(f"table {table}.{name}: type must be one of {sorted(_TYPES)}")
    domain = raw.get("domain", [])
    if not isinstance(domain, list):
        raise SpecError(f"table {table}.{name}: domain must be a finite list")
    checker = _is_int if ftype == "integer" else lambda v: isinstance(v, str)
    values = set()
    for value in domain:
        if not checker(value):
            raise SpecError(
                f"table {table}.{name}: domain value {value!r} is not {ftype}")
        values.add(value)
    ordered = tuple(sorted(values))
    nullable = raw.get("nullable", False)
    if not isinstance(nullable, bool):
        raise SpecError(f"table {table}.{name}: nullable must be boolean")
    return FieldSpec(name, ftype, ordered, nullable)


def _as_name_list(value, label: str, table: str, known_fields: set) -> tuple:
    if not isinstance(value, list) or not value:
        raise SpecError(f"table {table}: {label} must be a non-empty field list")
    if any(not isinstance(f, str) for f in value) or len(set(value)) != len(value):
        raise SpecError(f"table {table}: {label} fields must be unique strings")
    for f in value:
        if f not in known_fields:
            raise SpecError(f"table {table}: {label} references unknown field {f}")
    return tuple(value)


def _solve_order(tables: dict) -> tuple:
    """确定性求解顺序：Kahn 拓扑 + 字母序平局，环按字母序稳定打破。

    边 ``目标 -> 来源``：入度为 0 的表没有未满足的外键目标，优先填充。
    出现环时剩余节点入度恒 > 0，按字母序选一个打破，环内仍保持确定性，
    且环本身在求解中通过前向引用被满足，不会被当成错误。
    """
    names = sorted(tables)
    indegree = {name: set() for name in names}
    for name in names:
        for fk in tables[name].foreign_keys:
            if fk.target_table != name:  # 自引用不阻塞表级顺序
                indegree[name].add(fk.target_table)
    ordered = []
    remaining = set(names)
    while remaining:
        ready = sorted(n for n in remaining if not indegree[n])
        if not ready:  # 环：稳定地取字母序最小的剩余表打破
            ready = [min(remaining)]
        chosen = ready[0]
        ordered.append(chosen)
        remaining.remove(chosen)
        for name in remaining:
            indegree[name].discard(chosen)
    return tuple(ordered)


def compile_spec(document: dict) -> CompiledSpec:
    """把手写规格编译成规范化、可求解、可摘要的结构。"""
    if not isinstance(document, dict):
        raise SpecError("specification must be a JSON object")
    protocol = document.get("protocol")
    if protocol != PROTOCOL_VERSION:
        raise SpecError(
            f"unsupported protocol {protocol!r}; expected {PROTOCOL_VERSION!r}")
    seed = document.get("seed", 0)
    if not _is_int(seed) or seed < 0:
        raise SpecError("seed must be a non-negative integer")
    raw_tables = document.get("tables")
    if not isinstance(raw_tables, dict) or not raw_tables:
        raise SpecError("specification requires a non-empty tables object")

    raw_budget = document.get("budget", {})
    if not isinstance(raw_budget, dict):
        raise SpecError("budget must be an object")
    node_budget = raw_budget.get("node_budget", 1_000_000)
    max_total_rows = raw_budget.get("max_total_rows", 1_000_000)
    if not _is_int(node_budget) or node_budget < 1:
        raise SpecError("budget.node_budget must be a positive integer")
    if not _is_int(max_total_rows) or max_total_rows < 1:
        raise SpecError("budget.max_total_rows must be a positive integer")
    budget = Budget(node_budget, max_total_rows)

    tables: dict[str, TableSpec] = {}
    replay_tables: dict[str, dict] = {}

    for table in sorted(raw_tables):
        if not _TABLE_NAME.fullmatch(table):
            raise SpecError(f"unsafe table name {table!r}")
        raw = raw_tables[table]
        if not isinstance(raw, dict):
            raise SpecError(f"table {table}: declaration must be an object")
        rows = raw.get("rows")
        if not _is_int(rows) or rows < 0:
            raise SpecError(f"table {table}: rows must be a non-negative integer")

        raw_fields = raw.get("fields")
        if not isinstance(raw_fields, dict) or not raw_fields:
            raise SpecError(f"table {table}: needs at least one field")
        fields = {name: _compile_field(table, name, decl)
                  for name in sorted(raw_fields)
                  for decl in [raw_fields[name]]}

        pk = _as_name_list(raw.get("primary_key"), "primary_key", table, set(fields))
        if any(fields[f].nullable for f in pk):
            raise SpecError(f"table {table}: primary key columns must be non-nullable")

        unique_groups = [UniqueConstraint(f"{table}.pk", pk)]
        seen_groups = {pk}
        for idx, group in enumerate(raw.get("unique", [])):
            cols = _as_name_list(group, "unique entry", table, set(fields))
            if cols in seen_groups:
                raise SpecError(f"table {table}: duplicate unique group {list(cols)}")
            seen_groups.add(cols)
            unique_groups.append(UniqueConstraint(f"{table}.uq{idx}", cols))
        unique_groups.sort(key=lambda u: u.name)

        fks = []
        for idx, raw_fk in enumerate(raw.get("foreign_keys", [])):
            if not isinstance(raw_fk, dict):
                raise SpecError(f"table {table}: foreign key {idx} must be an object")
            cols = _as_name_list(raw_fk.get("fields"), "foreign key fields",
                                 table, set(fields))
            target_table = raw_fk.get("table")
            if not isinstance(target_table, str):
                raise SpecError(f"table {table}: foreign key target table required")
            raw_targets = raw_fk.get("target_fields")
            if not isinstance(raw_targets, list) or not raw_targets:
                raise SpecError(
                    f"table {table}: foreign key target_fields must be a non-empty list")
            if any(not isinstance(f, str) for f in raw_targets) or \
                    len(set(raw_targets)) != len(raw_targets):
                raise SpecError(
                    f"table {table}: foreign key target_fields must be unique strings")
            target_fields = tuple(raw_targets)
            if target_table not in raw_tables:
                raise SpecError(
                    f"table {table}: foreign key targets unknown table {target_table}")
            if len(cols) != len(target_fields):
                raise SpecError(
                    f"table {table}: foreign key arity must match target")
            nullable = raw_fk.get("nullable", False)
            if not isinstance(nullable, bool):
                raise SpecError(f"table {table}: foreign key nullable must be boolean")
            # 可空外键要求其所有列均可空；非空外键要求所有列均非空。
            # 这样“全 null 不建立引用 / 部分 null 拒绝”的语义才没有歧义。
            nullables = {fields[f].nullable for f in cols}
            if nullable and not all(nullables):
                raise SpecError(
                    f"table {table}: nullable foreign key requires all its "
                    f"columns {list(cols)} to be nullable")
            if not nullable and any(nullables):
                raise SpecError(
                    f"table {table}: non-nullable foreign key requires all its "
                    f"columns {list(cols)} to be non-nullable")
            fks.append(ForeignKey(
                f"{table}.fk{idx}", cols, target_table, target_fields, nullable))
        fks.sort(key=lambda fk: fk.name)

        tables[table] = TableSpec(table, rows, fields, pk, tuple(unique_groups),
                                  tuple(fks))
        replay_tables[table] = {
            "rows": rows,
            "fields": {name: {"type": f.type, "domain": list(f.domain),
                              "nullable": f.nullable}
                       for name, f in fields.items()},
            "primary_key": list(pk),
            "unique": [list(u.fields) for u in unique_groups if u.name != f"{table}.pk"],
            "foreign_keys": [
                {"name": fk.name, "fields": list(fk.fields), "table": fk.target_table,
                 "target_fields": list(fk.target_fields), "nullable": fk.nullable}
                for fk in fks],
        }

    # 第二轮：外键目标列、类型与目标唯一性校验（允许前向引用与环）。
    for table, spec in tables.items():
        for fk in spec.foreign_keys:
            target = tables.get(fk.target_table)
            if target is None:
                raise SpecError(
                    f"{fk.name}: unknown target table {fk.target_table}")
            for remote in fk.target_fields:
                if remote not in target.fields:
                    raise SpecError(
                        f"{fk.name}: unknown target field "
                        f"{fk.target_table}.{remote}")
            target_groups = {u.fields for u in target.uniques}
            if fk.target_fields not in target_groups:
                raise SpecError(
                    f"{fk.name}: target {fk.target_table}{list(fk.target_fields)} "
                    f"must be a primary key or unique constraint")
            for local, remote in zip(fk.fields, fk.target_fields):
                if spec.fields[local].type != target.fields[remote].type:
                    raise SpecError(
                        f"{fk.name}: type mismatch on {local} -> "
                        f"{fk.target_table}.{remote}")

    total_rows = sum(spec.rows for spec in tables.values())
    if total_rows > max_total_rows:
        # 这是声明的输出行数预算与规格本身冲突，属于可靠的结构性矛盾。
        raise SpecError(
            f"declared row total {total_rows} exceeds budget.max_total_rows "
            f"{max_total_rows}")

    replay = {"protocol": PROTOCOL_VERSION, "tables": replay_tables}
    structure_digest = hashlib.sha256(canonical(replay).encode()).hexdigest()
    sorted_names = tuple(sorted(tables))
    return CompiledSpec(
        tables=tables,
        table_order=_solve_order(tables),
        sorted_names=sorted_names,
        seed=seed,
        budget=budget,
        structure_digest=structure_digest,
        replay=replay,
    )
