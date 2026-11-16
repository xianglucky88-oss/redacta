"""Redacta 公开 API。

发布相关重对象（Publisher/Policy）采用惰性导入：仅使用
:mod:`redacta.synth` 合成生成器的调用方不会因此加载发布、变换或 HMAC
模块，保证“合成不接触密钥与发布链路”的隔离在导入层面也成立。
"""
__all__ = ["Publisher", "Policy"]


def __getattr__(name):
    if name == "Publisher":
        from .release import Publisher
        return Publisher
    if name == "Policy":
        from .policy import Policy
        return Policy
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
