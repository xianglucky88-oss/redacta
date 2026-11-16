"""只接受人工合成规格的多表数据生成器。

公开入口：

* :func:`compile_spec` —— 规范化规格并编译约束；
* :func:`generate` —— 在整个表集合上求解全部约束；
* :func:`validate_tables` —— 不调用搜索的独立结果校验；
* :class:`Unsatisfiable` / :class:`BudgetExhausted` —— 两类不同的失败。

本包不导入 release / transforms / policy，不读取真实数据行或 HMAC 密钥。
"""
from .spec import PROTOCOL_VERSION, CompiledSpec, SpecError, canonical, compile_spec
from .solver import (
    BudgetExhausted,
    GenerationResult,
    Unsatisfiable,
    generate,
)
from .validator import ValidationError, validate_tables

__all__ = [
    "PROTOCOL_VERSION",
    "SpecError",
    "ValidationError",
    "Unsatisfiable",
    "BudgetExhausted",
    "CompiledSpec",
    "GenerationResult",
    "compile_spec",
    "generate",
    "validate_tables",
    "canonical",
]
