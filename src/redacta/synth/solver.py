"""跨表见证搜索：有限关系模型 + 约束传播/前向检查 + 确定性回溯。

模型
====

把整个表集合展开成一个全局的**槽位序列**：每张表的 ``rows`` 个行槽按
确定性求解顺序（见下）排列，每个槽位在该表字段候选域的笛卡尔积上取一个
完整候选行。所有主键、唯一约束、外键都是这些槽位上的有限域约束，在一次
深度优先回溯中同时求解。

表的求解顺序是一张依赖 DAG 的稳定拓扑序（边为“目标 -> 来源”，平局与环
均按规范化表名打破，见 :func:`redacta.synth.spec._solve_order`），使被
引用目标尽量先填充；环不被当作错误，环内表通过前向引用满足。候选行及其
唯一键、外键值、域级可行性在搜索开始前一次性预计算，节点上只做集合判定。

关键机制
========

* **原子行准入**：槽位一次性取完整候选行，绝不逐列拼凑后再修补外键，因此
  不存在“按表生成后随便改一个键”的步骤。
* **增量唯一索引**：主键（永远非空，按相等去重）与复合唯一约束（SQL 风格
  null 语义，含 null 的元组互不冲突）在准入时检查；压栈记录新增的键、弹栈
  精确撤销，其他表已接受的行永远不会被本槽的回溯改写。
* **外键前向检查（双向）**：
  - 引用已填充目标时，候选值必须命中目标主键/唯一组的现有投影；
  - 引用尚未填充的目标时允许前向引用（环依赖由此可满足，不把环当错误），
    但域级传播保证候选值落在目标列候选域内；
  - 每个目标组维护“还有哪些入向引用值未被见证”，当某个表的全部槽位填充
    完毕，立即检查它是否仍欠见证，欠见证则当场剪枝而不是等到叶节点，避免
    在必然失败的前缀上枚举下游表。
* **可空复合外键**：全 null 仅在显式可空时不建立引用；部分 null 在准入阶段
  直接拒绝。

为什么不会破坏其他表的唯一性或引用
==================================

1. 回溯只弹出当前递归路径上的槽位（整个行），从不修改已返回的其他表行；
2. 唯一索引与外键投影都从“当前已接受行集合”派生，随压栈/弹栈同步维护；
3. 叶节点还有一次覆盖整个表集合的最终外键见证，独立校验器
   （:mod:`redacta.synth.validator`）在不调用本搜索的情况下再验一遍。

完备性、预算与确定性
====================

剪枝只拒绝在当前前缀下已被违反、或在候选域层面不可能被任何扩展满足的
候选，因此**完整穷尽即证明无解**（:class:`Unsatisfiable`）；在穷尽前达到
``node_budget`` 只能报告 :class:`BudgetExhausted`（未求得），绝不伪装成
矛盾。表顺序、字段顺序、候选域全部来自规范化规格，seed 仅通过显式伪随机
排列改变多解时的尝试次序；同一（规范化规格, seed, 协议版本）产出相同数据。
本生成器**不声称均匀采样**。
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from .spec import CompiledSpec, TableSpec, canonical


class GenerationError(RuntimeError):
    """生成失败基类。"""

    def __init__(self, message, *, compiled: CompiledSpec):
        super().__init__(message)
        self.compiled = compiled

    @property
    def replay(self) -> dict:
        return self.compiled.to_replay_document()


class Unsatisfiable(GenerationError):
    """完整穷尽后确认无解（规格矛盾，而非资源中断）。"""

    def __init__(self, message, *, compiled: CompiledSpec, involved: list,
                 rejection_counts: dict):
        super().__init__(message, compiled=compiled)
        # 诊断中指出涉及的约束名；不伪造最小冲突集。
        self.involved = involved
        self.rejection_counts = rejection_counts


class BudgetExhausted(GenerationError):
    """预算耗尽：未求得，不能据此声称规格有解或无解。"""

    def __init__(self, message, *, compiled: CompiledSpec, used: int, state: dict):
        super().__init__(message, compiled=compiled)
        self.used = used
        self.state = state


@dataclass
class GenerationResult:
    tables: dict                 # 裸表：{table: [row, ...]}，可直接 JSON 化
    structure_digest: str
    protocol: str
    seed: int
    node_attempts: int


def _choice_order(compiled: CompiledSpec, table: str, field: str, values: tuple):
    """seed 只在这里影响多解时的稳定尝试次序。"""
    rng = random.Random()
    rng.seed(f"{compiled.structure_digest}|{compiled.seed}|{table}|{field}")
    ordered = list(values)
    rng.shuffle(ordered)
    return ordered


def _candidate_rows(compiled: CompiledSpec, spec: TableSpec):
    """该表全部完整候选行，顺序由规范化规格与 seed 固定。"""
    field_names = tuple(sorted(spec.fields))
    per_field = [_choice_order(compiled, spec.name, name,
                               spec.fields[name].full_domain)
                 for name in field_names]
    rows = [[]]
    for options in per_field:
        rows = [prefix + [value] for prefix in rows for value in options]
    return [dict(zip(field_names, row)) for row in rows]


def _prepare_candidates(compiled: CompiledSpec):
    """预计算每个候选行的热路径数据，避免搜索节点上重复构造元组/JSON。

    域级传播只依赖静态候选域，因此每个候选在每条外键上的域级可行性可
    一次性算好；唯一键元组、外键值元组同样预算，节点上只做集合判定。
    """
    prepared = {}
    for name in compiled.table_order:
        spec = compiled.tables[name]
        entries = []
        for row in _candidate_rows(compiled, spec):
            unique_keys = []
            for constraint in spec.uniques:
                key = tuple(row[f] for f in constraint.fields)
                unique_keys.append(
                    (constraint.name, None if any(v is None for v in key) else key))
            fk_values = []
            domain_block = None
            for fk in spec.foreign_keys:
                values = tuple(row[f] for f in fk.fields)
                nulls = [v is None for v in values]
                fk_values.append((fk, values, all(nulls), any(nulls)))
                if all(nulls):
                    if not fk.nullable:
                        domain_block = fk.name
                        break
                elif any(nulls):
                    domain_block = fk.name
                    break
                else:
                    target = compiled.tables[fk.target_table]
                    if any(value not in target.fields[remote].full_domain
                           for value, remote in zip(values, fk.target_fields)):
                        domain_block = fk.name
                        break
            marker = tuple(row[f] for f in sorted(spec.fields))
            entries.append({
                "row": row,
                "marker": marker,
                "unique_keys": unique_keys,
                "fk_values": fk_values,
                "domain_block": domain_block,
            })
        prepared[name] = entries
    return prepared


def generate(compiled: CompiledSpec) -> GenerationResult:
    # 全局槽位序列：(表名, 该表内槽序号)，按最小化前向引用的确定性顺序展开。
    slots = []
    for name in compiled.table_order:
        for slot_index in range(compiled.tables[name].rows):
            slots.append((name, slot_index))

    prepared = _prepare_candidates(compiled)

    # 每个表的运行态：已接受候选、唯一索引、目标投影、入向外键与增量日志。
    runtime = {
        name: {
            "spec": compiled.tables[name],
            "accepted": [],          # 已接受的 prepared entry
            "unique_seen": {u.name: set() for u in compiled.tables[name].uniques},
            "projections": {},       # 目标列组 -> 已出现投影
            "incoming": [],
            "logs": [],              # 每次 push 的增量键，pop 时精确撤销
        }
        for name in compiled.table_order
    }
    for name in compiled.table_order:
        target_groups = {fk.target_fields for spec in compiled.tables.values()
                         for fk in spec.foreign_keys if fk.target_table == name}
        runtime[name]["projections"] = {group: set() for group in target_groups}
    for name in compiled.table_order:
        for fk in compiled.tables[name].foreign_keys:
            runtime[fk.target_table]["incoming"].append(
                (name, fk.name, fk.fields, fk.target_fields, fk.nullable))

    rejection_counts = {}

    def reject(constraint_name: str):
        rejection_counts[constraint_name] = \
            rejection_counts.get(constraint_name, 0) + 1

    used = 0

    def fail_unsat():
        raise Unsatisfiable(
            "exhaustive search found no assignment satisfying every "
            "constraint over the whole table set",
            compiled=compiled,
            involved=sorted(rejection_counts),
            rejection_counts=dict(sorted(rejection_counts.items())),
        )

    def is_full(name: str) -> bool:
        node = runtime[name]
        return len(node["accepted"]) == node["spec"].rows

    def unique_violation(name: str, entry: dict) -> str | None:
        seen = runtime[name]["unique_seen"]
        for constraint_name, key in entry["unique_keys"]:
            if key is not None and key in seen[constraint_name]:
                return constraint_name
        return None

    def admission_foreign_keys(name: str, entry: dict) -> str | None:
        """对已填充目标立即见证；未填充目标挂起，由完成检查/叶节点兜底。"""
        for fk, values, all_null, any_null in entry["fk_values"]:
            if all_null or any_null:
                continue  # 合法性已在 domain_block 预算阶段保证
            target = runtime[fk.target_table]
            if not is_full(fk.target_table):
                continue  # 前向引用：环依赖在此被允许
            if values not in target["projections"][fk.target_fields]:
                return fk.name
        return None

    def push(name: str, entry: dict):
        node = runtime[name]
        added_unique, added_proj = [], []
        for constraint_name, key in entry["unique_keys"]:
            if key is not None and key not in node["unique_seen"][constraint_name]:
                node["unique_seen"][constraint_name].add(key)
                added_unique.append((constraint_name, key))
        for group, projection in node["projections"].items():
            key = tuple(entry["row"][f] for f in group)
            if key not in projection:
                projection.add(key)
                added_proj.append((group, key))
        node["logs"].append((added_unique, added_proj))
        node["accepted"].append(entry)

    def pop(name: str):
        node = runtime[name]
        entry = node["accepted"].pop()
        added_unique, added_proj = node["logs"].pop()
        for constraint_name, key in added_unique:
            node["unique_seen"][constraint_name].discard(key)
        for group, key in added_proj:
            node["projections"][group].discard(key)
        return entry

    def incoming_debts_satisfied(name: str) -> list:
        """目标表 name 已填满：所有入向外键的来源行必须已有见证。"""
        failures = []
        node = runtime[name]
        for source, fk_name, local_fields, target_fields, nullable in node["incoming"]:
            projection = node["projections"][target_fields]
            for entry in runtime[source]["accepted"]:
                values = tuple(entry["row"][f] for f in local_fields)
                if all(v is None for v in values):
                    if not nullable:
                        failures.append(fk_name)
                        break
                    continue
                if any(v is None for v in values) or values not in projection:
                    failures.append(fk_name)
                    break
        return sorted(set(failures))

    def leaf_check() -> list:
        failures = []
        for name in compiled.table_order:
            failures.extend(incoming_debts_satisfied(name))
        return sorted(set(failures))

    depth = 0
    # 每个槽位一份“当前前缀下已尝试候选标记”，回溯后不重复同一失败。
    tried = [set() for _ in slots]

    while True:
        if depth == len(slots):
            failures = leaf_check()
            if not failures:
                return _build_result(compiled, runtime, used)
            for fk_name in failures:
                reject(fk_name)
            depth -= 1
            pop(slots[depth][0])
            continue

        name, _ = slots[depth]
        marker_set = tried[depth]

        entry = None
        for candidate in prepared[name]:
            if candidate["marker"] in marker_set:
                continue
            marker_set.add(candidate["marker"])
            entry = candidate
            break

        if entry is None:
            # 该槽在当前前缀下穷尽：回退并重试上一槽；更深槽位记忆作废。
            for deeper in range(depth + 1, len(slots)):
                tried[deeper].clear()
            tried[depth].clear()
            if depth == 0:
                fail_unsat()
            depth -= 1
            pop(slots[depth][0])
            continue

        used += 1
        if used > compiled.budget.node_budget:
            raise BudgetExhausted(
                f"node_budget {compiled.budget.node_budget} exhausted before the "
                f"finite search space was exhausted; result is undetermined, "
                f"not a contradiction",
                compiled=compiled,
                used=used - 1,
                state=_state_summary(runtime, compiled),
            )

        conflict = unique_violation(name, entry)
        if conflict:
            reject(conflict)
            continue
        if entry["domain_block"] is not None:
            reject(entry["domain_block"])
            continue
        conflict = admission_foreign_keys(name, entry)
        if conflict:
            reject(conflict)
            continue

        push(name, entry)

        # 前向检查：表刚填满即验证入向欠账，避免在死前缀上继续深入。
        if is_full(name):
            debts = incoming_debts_satisfied(name)
            if debts:
                for fk_name in debts:
                    reject(fk_name)
                pop(name)
                continue

        depth += 1


def _state_summary(runtime: dict, compiled: CompiledSpec) -> dict:
    return {
        name: {"accepted_rows": len(node["accepted"]),
               "required_rows": node["spec"].rows,
               "complete": len(node["accepted"]) == node["spec"].rows}
        for name, node in runtime.items()
    }


def _build_result(compiled: CompiledSpec, runtime: dict, used: int) -> GenerationResult:
    tables = {}
    # 输出按规范化字典序，与内部求解顺序解耦，保证排列不变性。
    for name in compiled.sorted_names:
        rows = sorted((dict(entry["row"]) for entry in runtime[name]["accepted"]),
                      key=lambda row: canonical(row))
        tables[name] = rows
    return GenerationResult(
        tables=tables,
        structure_digest=compiled.structure_digest,
        protocol=compiled.replay["protocol"],
        seed=compiled.seed,
        node_attempts=used,
    )
