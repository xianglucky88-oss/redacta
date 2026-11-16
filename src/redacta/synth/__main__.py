"""合成生成器命令行入口（与发布 CLI 完全分离）。

用法::

    python -m redacta.synth generate spec.json tables.json [--meta meta.json]
    python -m redacta.synth validate spec.json tables.json [--meta meta.json]

``tables.json`` 是可直接交给现有发布入口（``redacta.cli publish``）消费的
裸 JSON 表；它不是 release、策略版本或脱敏报告。``meta.json`` 绑定结构摘要
与协议版本，供独立校验使用。

退出码：0 成功；2 规格/校验错误；3 完整穷尽后无解；4 预算耗尽（未求得）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import (
    BudgetExhausted,
    SpecError,
    Unsatisfiable,
    ValidationError,
    compile_spec,
    generate,
    validate_tables,
)

EXIT_SPEC_ERROR = 2
EXIT_UNSATISFIABLE = 3
EXIT_BUDGET = 4


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _atomic_write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _cmd_generate(args) -> int:
    document = _load(args.spec)
    try:
        compiled = compile_spec(document)
        result = generate(compiled)
        # 成功产物在返回前必须通过不调用搜索的独立校验器；
        # 校验失败不得返回部分表作为成功。
        report = validate_tables(
            result.tables, compiled,
            structure_digest=result.structure_digest,
            protocol=result.protocol)
    except SpecError as exc:
        print(json.dumps({"status": "spec_error", "error": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        return EXIT_SPEC_ERROR
    except Unsatisfiable as exc:
        print(json.dumps({
            "status": "unsatisfiable",
            "error": str(exc),
            "involved_constraints": exc.involved,
            "rejection_counts": exc.rejection_counts,
            "replay": exc.replay,
        }, ensure_ascii=False), file=sys.stderr)
        return EXIT_UNSATISFIABLE
    except BudgetExhausted as exc:
        print(json.dumps({
            "status": "undetermined_budget_exhausted",
            "error": str(exc),
            "node_attempts": exc.used,
            "state": exc.state,
            "replay": exc.replay,
        }, ensure_ascii=False), file=sys.stderr)
        return EXIT_BUDGET

    _atomic_write_json(Path(args.output), result.tables)
    meta = {
        "protocol": result.protocol,
        "structure_digest": result.structure_digest,
        "seed": result.seed,
        "node_attempts": result.node_attempts,
        "validation": report,
    }
    if args.meta:
        _atomic_write_json(Path(args.meta), meta)
    print(json.dumps({"status": "generated", "output": args.output,
                      "meta": meta}, ensure_ascii=False, indent=2))
    return 0


def _cmd_validate(args) -> int:
    document = _load(args.spec)
    tables = _load(args.tables)
    meta = _load(args.meta) if args.meta else {}
    try:
        report = validate_tables(
            tables, document,
            structure_digest=meta.get("structure_digest"),
            protocol=meta.get("protocol"))
    except (SpecError, ValidationError) as exc:
        errors = exc.errors if isinstance(exc, ValidationError) else [str(exc)]
        print(json.dumps({"status": "invalid", "errors": errors},
                         ensure_ascii=False), file=sys.stderr)
        return EXIT_SPEC_ERROR
    print(json.dumps({"status": "valid", "report": report},
                     ensure_ascii=False, indent=2))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Synthetic multi-table generator (hand-authored specs only)")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="solve a synthetic specification")
    gen.add_argument("spec")
    gen.add_argument("output", help="path for bare JSON tables consumable by publish")
    gen.add_argument("--meta", help="optional sidecar binding digest and protocol")
    gen.set_defaults(func=_cmd_generate)

    val = sub.add_parser("validate", help="independently validate generated tables")
    val.add_argument("spec")
    val.add_argument("tables")
    val.add_argument("--meta")
    val.set_defaults(func=_cmd_validate)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "io_error", "error": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        return EXIT_SPEC_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
