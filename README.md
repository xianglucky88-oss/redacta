# Redacta · 可追溯隐私数据发布

按显式字段规则把多表数据转换为可发布 JSONL 包，保持被允许的跨表关联，并记录策略版本、文件校验和和发布撤销状态。

## 已实现

- 字段分类提示（邮箱、电话、常见标识字段名）；只提供提示，不自动批准字段发布。
- 输入字段必须与策略完全匹配，新增未知字段会拒绝发布。
- `keep/drop/token/mask/bucket/date_shift/scrub` 七种策略。
- HMAC-SHA256 Token 和命名空间，跨表关联键可保持一致；字符串键去首尾空白并忽略大小写。
- 数值分桶支持负数；主体稳定日期偏移保持相对日差；自由文本清理邮箱/电话。
- 按声明的准标识字段做 k 分组抑制；关联字段级联抑制并迭代到稳定，删除造成的小分组再次抑制。
- 不可变策略内容哈希、独立发布目录、JSONL 文件校验、SQLite 发布审计、撤销并删除本地发布文件。

## 运行

Python 3.11+。在项目目录执行：

```bash
export PYTHONPATH="$PWD/src"
export REDACTA_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
python3 -m redacta.cli classify examples/tables.json
python3 -m redacta.cli --root /tmp/redacta-demo publish examples/tables.json examples/policy.json
python3 -m unittest discover -s tests -v
python3 examples/smoke.py
```

发布返回 `id` 后，可以执行 `python3 -m redacta.cli --root /tmp/redacta-demo revoke RELEASE_ID`。密钥通过环境注入，代码不会将密钥存入发布包或审计库。跨次再生成需由调用者安全保留并提供原密钥、原始输入和策略；每次发布会生成新包 ID。

样例：3 位主体中 1 位因准标识组过小被抑制，关联访问表同步删除其记录；最终输出 2 位主体和 1 次访问。

## 架构与扩展

`policy.py` 负责闭合字段契约、关联规则和策略指纹；`transforms.py` 负责确定性变换；`release.py` 负责抑制、文件交付和状态；`cli.py` 读取 JSON。

```python
from redacta import Policy, Publisher
from redacta.transforms import Transformer

# key 由调用者的密钥服务提供，至少 32 字节。
# 新变换同时在 Policy 中显式授权，避免未知操作静默放行。
transformer = Transformer(key, extensions={
    "prefix_only": lambda value, rule, subject: str(value)[:rule.get("length", 1)]
})
policy = Policy({"version": "v1", "tables": {
    "samples": {"fields": {"code": {"op": "prefix_only", "length": 2}}}
}}, operations={"prefix_only"})
publisher = Publisher("releases", key, transformer=transformer)
try:
    manifest = publisher.publish({"samples": [{"code": "ABCDE"}]}, policy)
finally:
    publisher.close()
```

## 当前边界

所有输入表和变换结果在内存中处理，未实现外部排序/流式大表发布。文件目录原子重命名与 SQLite 提交没有跨介质事务，进程在二者之间崩溃可能留下孤立目录，需后续对账；普通可捕获异常会清理输出。撤销无法收回外部已下载副本。

PII 识别是启发式规则，地址/姓名等字段需显式配置 `drop/mask`；正则不保证识别所有自由文本隐私内容。k 分组只是对该发布包声明的准标识进行最小分组控制，不构成差分隐私或法律合规保证，也不抵抗多批次联合推断。发布目录需要受信任本地权限管理，审计库包含发布统计但不保存原值映射。
