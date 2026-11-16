"""独立结果校验器。

校验器刻意**不导入** :mod:`redacta.synth.solver`、不调用任何搜索过程：它
只面对一份已经生成出来的裸表与一份规格，从零重新检查全部约束。测试套件
会用进程级断言保证这一隔离。

校验内容
========

1. 表集合与规格完全一致，每张表行数精确等于声明行数，字段集合精确匹配；
2. 每个值属于字段声明的有限候选域，null 只允许出现在显式可空字段；
3. 主键非空且在表内唯一；复合唯一约束按 SQL 风格 null 语义校验；
4. 每条外键在整个表集合上见证：全 null 仅在显式可空时不建立引用，
   部分 null 一律失败，非空复合键必须在目标主键/唯一组中存在；
5. 输出绑定的结构摘要与协议版本与规格一致。

校验失败抛出 :class:`ValidationError`，其中聚合全部发现的问题；调用方不得
在校验失败时把部分表当作成功产物返回。
"""
from __future__ import annotations

import hashlib

from .spec import CompiledSpec, PROTOCOL_VERSION, canonical, compile_spec


class ValidationError(ValueError):
    def __init__(self, errors: list):
        super().__init__("; ".join(errors))
        self.errors = errors


def validate_tables(tables: dict, spec, *, structure_digest: str | None = None,
                    protocol: str | None = None) -> dict:
    """对生成产物做独立校验，成功时返回一份校验报告，失败抛 ValidationError。"""
    if isinstance(spec, CompiledSpec):
        compiled = spec
    else:
        compiled = compile_spec(spec)

    errors = []
    if protocol is not None and protocol != PROTOCOL_VERSION:
        errors.append(f"protocol mismatch: output {protocol!r} vs {PROTOCOL_VERSION!r}")
    if structure_digest is not None and structure_digest != compiled.structure_digest:
        errors.append("structure digest mismatch: output is not bound to this spec")

    if not isinstance(tables, dict) or set(tables) != set(compiled.tables):
        errors.append(
            f"table set mismatch: output {sorted(tables) if isinstance(tables, dict) else tables!r} "
            f"vs spec {list(compiled.sorted_names)}")
        raise ValidationError(errors)

    for name in compiled.sorted_names:
        spec_table = compiled.tables[name]
        rows = tables[name]
        if not isinstance(rows, list):
            errors.append(f"table {name}: rows must be a list")
            continue
        if len(rows) != spec_table.rows:
            errors.append(
                f"table {name}: expected exactly {spec_table.rows} rows, got {len(rows)}")

        seen_pk = set()
        unique_seen = {u.name: set() for u in spec_table.uniques}
        for position, row in enumerate(rows):
            if not isinstance(row, dict):
                errors.append(f"table {name}[{position}]: row must be an object")
                continue
            if set(row) != set(spec_table.fields):
                errors.append(
                    f"table {name}[{position}]: field set {sorted(row)} does not "
                    f"match spec {sorted(spec_table.fields)}")
                continue
            for field_name, field in spec_table.fields.items():
                value = row[field_name]
                if value is None:
                    if not field.nullable:
                        errors.append(
                            f"table {name}[{position}].{field_name}: null in non-nullable field")
                elif value not in field.domain:
                    errors.append(
                        f"table {name}[{position}].{field_name}: value {value!r} "
                        f"outside declared finite domain")

            pk_value = tuple(row[f] for f in spec_table.primary_key)
            if any(v is None for v in pk_value):
                errors.append(f"table {name}[{position}]: primary key must be non-null")
            elif pk_value in seen_pk:
                errors.append(
                    f"table {name}[{position}]: duplicate primary key {list(pk_value)}")
            else:
                seen_pk.add(pk_value)

            for unique in spec_table.uniques:
                if unique.name == f"{name}.pk":
                    continue
                key = tuple(row[f] for f in unique.fields)
                if any(v is None for v in key):
                    continue  # SQL 风格：含 null 不参与去重
                if key in unique_seen[unique.name]:
                    errors.append(
                        f"table {name}[{position}]: unique constraint {unique.name} "
                        f"violated by {list(key)}")
                else:
                    unique_seen[unique.name].add(key)

    # 外键见证在完整表集合上检查（独立于搜索顺序，允许环）。
    for name in compiled.sorted_names:
        spec_table = compiled.tables[name]
        target_index = {}
        for fk in spec_table.foreign_keys:
            index_key = (fk.target_table, fk.target_fields)
            if index_key not in target_index:
                target = compiled.tables[fk.target_table]
                target_index[index_key] = [
                    tuple(row[f] for f in fk.target_fields)
                    for row in tables[fk.target_table]
                    if isinstance(row, dict) and set(row) == set(target.fields)
                ]
            witness = target_index[index_key]
            for position, row in enumerate(tables[name]):
                if not isinstance(row, dict) or set(row) != set(spec_table.fields):
                    continue
                values = tuple(row[f] for f in fk.fields)
                nulls = [v is None for v in values]
                if all(nulls):
                    if not fk.nullable:
                        errors.append(
                            f"table {name}[{position}]: all-null foreign key {fk.name} "
                            f"is not explicitly nullable")
                    continue
                if any(nulls):
                    errors.append(
                        f"table {name}[{position}]: partially-null composite foreign "
                        f"key {fk.name} is never a valid reference")
                    continue
                if values not in witness:
                    errors.append(
                        f"table {name}[{position}]: foreign key {fk.name} has no "
                        f"witness in {fk.target_table}{list(fk.target_fields)}: "
                        f"{list(values)}")

    if errors:
        raise ValidationError(errors)
    return {
        "valid": True,
        "protocol": PROTOCOL_VERSION,
        "structure_digest": compiled.structure_digest,
        "rows": {name: len(tables[name]) for name in compiled.sorted_names},
        "canonical_digest": hashlib.sha256(
            canonical(tables).encode()).hexdigest(),
    }
