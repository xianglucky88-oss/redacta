# Redacta · 可恢复、可撤销的认证发布协议

按显式字段规则把多表数据转换为可发布 JSONL 包，保持被允许的跨表关联，并把**调用方 request id、输入指纹、Policy digest、变换实现版本、key id、namespace** 与实际 JSONL checksum 一起固化进受 HMAC 认证的 manifest。发布是一个显式状态机，进程在任何持久化边界被杀死都可以保守恢复，且撤销（tombstone）不可逆转。

## 发布身份与状态机

每次 `publish(tables, policy, request_id)` 冻结一个身份元组并写入审计库：

| 身份字段 | 含义 |
| --- | --- |
| `request_id` | 调用方提供的幂等键（1–128 字符） |
| `input_fingerprint` | 原始输入规范化后的 SHA-256 |
| `policy_digest` | 不可变 Policy 内容 digest |
| `transform_version` | 变换实现版本（`transform-v2`，语义变更必须 bump） |
| `key_id` | 签名所用密钥的非秘密标识 |
| `namespaces` | Policy 中全部 token/date_shift namespace 的有序去重列表 |

状态转换（意图行先于任何目录落盘）：

```
preparing ──可读提交──▶ active        （唯一可读状态）
preparing ──失败──────▶ failed        （可重试 / 可恢复 / 可撤销）
preparing/failed/active ──撤销──▶ revoked   （终态 tombstone）
```

- 同一 `request_id` 重试：身份元组完全一致时返回**原发布**（同一 release id、同一 envelope）；任一身份字段不同（换输入、换策略、换 namespace、换 transform 版本、换 key）直接 `IdentityConflict` 拒绝。
- 已 `revoked` 的 request id 永远不能重新发布；恢复程序即使发现完好的旧目录也不会把 tombstone 变回 active。
- 轮换当前密钥（向 `KeyRing` 注入新 active key）只影响新发布；已准备好的发布仍由旧 key id 签名，身份不变，旧 key 保留在 key ring 中即可继续验签读取。

## 为什么是“先登记意图，再写目录”

跨文件系统与 SQLite 不存在原子事务，本项目不用一个大 `try/except` 假装跨介质提交，而是用单资源提交的**顺序**保证每个崩溃区间都保守：

1. **意图提交**：先在 SQLite 插入 `status=preparing` 的意图行（含冻结身份）。此刻进程被杀 → 只有数据库行，没有任何可读包；`recover()` 或同 request id 重试解决。
2. **制品准备**：在隐藏 stage 目录写不可变 JSONL 与认证 manifest，`fsync` 后原子 `rename` 到发布目录。此刻被杀 → 目录存在但数据库仍是 `preparing`，`read` 一律拒绝；只有“意图行 + 认证 manifest + 逐文件 checksum 全部吻合”才允许提升为 active。
3. **可读提交**：一条条件 `UPDATE ... WHERE status != 'revoked'` 把状态翻成 active 并写入 envelope。并发撤销赢时提交失败并删除目录——tombstone 永远不可能被翻成 active。

对照“先准备不可变制品再登记意图”的代价：该方案在制品写好后、意图登记前崩溃会产生**无主目录**。无主目录无法安全自动收养（无法证明调用方是否真的发起过请求），只能人工对账或等调用方重试，调用方仍需猜目录是否可交付。意图优先方案把“调用方确实发起过请求”这一事实先持久化，使每个磁盘状态都有确定的裁决规则，代价仅是失败时留下一行需要清理/恢复的意图记录——这正是显式 `failed` 状态与 `recover()` 的职责。

## 不会被自动收养的三类东西

`read` 与 `recover` 对以下情况全部 fail-closed：

1. 看似完整但**没有登记发布意图**的目录（无 `release_requests` 行）；
2. manifest 引用了 key ring 中**不存在的 key id**（`UnknownKeyError`）；
3. 只有普通 checksum、没有有效 HMAC envelope 的文件或旧版无认证 manifest。

认证失败但存在意图行的目录会被移入 `.quarantine-<id>/`（附原因文件）并标记 `failed`；同 request id 重试若仍持有输入，可在同一身份下重建一份全新认证制品。

## 恢复与撤销语义

- `Publisher.recover()` 扫描全部非终态行：active 行只做验签+checksum 复核（损坏进 `active_corrupt`，不静默降级）；preparing/failed 行按上述规则恢复、失败或隔离；revoked 行若目录重现则再次删除，**绝不复活**。
- 没有调用方输入时，恢复程序不能重建丢失的制品（标记 `failed`）；同 request id 的 `publish` 重试仍持有输入时，可在同一 release id 下确定性重建。
- 撤销先提交 SQLite tombstone 再删本地文件，二者之间崩溃时新 read 仍被拒绝。**已下载到外部的副本不在本地撤销能力范围内**，撤销只保证本地不再交付。
- 并发的发布/恢复/撤销由同一身份规则、同一条件提交和每个 release 一把的 SQLite 物化锁裁决；持锁进程被 SIGKILL 后，发现其 pid 已死的后来者会回收陈旧锁。

## 密钥注入边界

密钥只通过构造函数受控注入（单 key + `key_id`，或多密钥 `KeyRing`）。SQLite 与报告中只保存非秘密的 `key_id` 标签、HMAC 摘要和 checksum；**不保存原始密钥，也不保存 token→原值映射**。CLI 通过 `REDACTA_KEY` 与 `REDACTA_KEY_ID` 环境变量注入。

## 旧版兼容

v1 的无认证 manifest/`releases` 表不会自动获得 v2 可信身份。只有显式以 `legacy_compat=True`（CLI: `--compat legacy-v1`）打开时，才能用 `read_legacy` 按普通 checksum 读取旧行；新协议发布与旧表共存但互不晋升。

## 运行

Python 3.11+，无第三方依赖：

```bash
export PYTHONPATH="$PWD/src"
export REDACTA_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
export REDACTA_KEY_ID="k1"
python3 -m redacta.cli classify examples/tables.json
python3 -m redacta.cli --root /tmp/redacta-demo publish \
  examples/tables.json examples/policy.json --request-id req-2026-001
python3 -m redacta.cli --root /tmp/redacta-demo read req-2026-001 people
python3 -m redacta.cli --root /tmp/redacta-demo recover
python3 -m redacta.cli --root /tmp/redacta-demo revoke req-2026-001
python3 -m unittest discover -s tests -v
python3 examples/smoke.py
```

库用法（含密钥轮换）：

```python
from redacta import Policy, Publisher, KeyRing

ring = KeyRing({"k1": old_key_bytes, "k2": new_key_bytes}, active_key_id="k2")
publisher = Publisher("releases", key_ring=ring)
manifest = publisher.publish(tables, policy, request_id="caller-id-123")
publisher.read("caller-id-123", "people")
publisher.recover()
publisher.revoke("caller-id-123")
```

## 验收测试覆盖

- 跨表 token 关联与“父表抑制后子表再次触发 k 抑制”的级联固定点，独立断言固定点结果与 manifest 实际行数。
- 进程在三个持久化点（意图提交后、stage 写盘后、目录 rename 后）被真实 `os._exit` 杀死，重启后分别尝试重试、读取、恢复、撤销，证明半发布不会被当成功、tombstone 不会因恢复重新释放数据。
- 同 request id 换输入/策略/namespace/transform 版本被拒；未知 key、无主目录、被篡改目录 fail-closed；并发同 id 只产生一个发布。
- 旧无认证格式仅在显式兼容标记下可读，且不获得 v2 身份。

## 仍存在的边界

所有输入表和变换结果在内存中处理，未实现外部排序/流式大表发布。撤销无法收回外部已下载副本。PII 识别是启发式规则，地址/姓名等字段需显式配置 `drop/mask`；k 抑制不构成差分隐私或法律合规保证，也不抵抗多批次联合推断。发布目录需要受信任本地权限管理。
