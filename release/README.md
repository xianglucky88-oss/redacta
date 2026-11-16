# Redacta 离线发布门禁

目标：保证发布制品（sdist / wheel / 安装目录）中的每一个字节都来自经批准的源码清单，
开发机上的试跑数据（`.env`、SQLite、`releases/`、临时 JSONL、密钥）无法通过路径改名、
符号链接或旧 `dist/` 残留进入制品。门禁**不**声称能自动识别任意 PII；检测边界由三部分
显式定义：

1. 文件准入规则（`gate/source-manifest.json` 白名单 + 路径拒绝规则）；
2. 批准样例的 SHA-256 摘要（`examples/*.json` 的哈希固化在清单中）；
3. 注入的非敏感 canary（`gate/canaries.json`，随机假密钥/假发布记录，非真实凭据）。

## 1. 两种收集方式的取舍

| 方案 | 能证明什么 | 不能证明什么 | 本仓库选择 |
|---|---|---|---|
| 白名单收集源文件（先把批准文件复制进干净树，再构建） | 构建后端只能看到批准输入，工作树里的脏文件物理上不在构建上下文 | 单独使用时无法证明构建产物没有夹带生成期注入的额外成员 | 采用，作为**构建前**边界 |
| 先构建再审计制品（对 sdist/wheel/安装树做成员、链接、RECORD、哈希审计） | 制品每个成员可回溯到清单哈希，恶意路径/越界链接/RECORD 不一致直接阻断 | 若构建上下文本身脏，只能事后发现、不能预防 | 采用，作为**构建后**边界 |

两者是串联而不是二选一：**白名单 pristine 树证明“输入闭包干净”，制品审计证明
“输出字节等于批准输入”**。仅靠 `.gitignore` 或按后缀清理不构成门禁——改名（
`.env.production.bak`）、嵌套（`src/redacta/audit.sqlite-wal`）、符号链接、旧 wheel
残留都绕过后缀清理，因此本门禁在准入阶段对每个路径组件做完整文件名/目录名匹配并拒绝
一切符号链接。

## 2. 流水线（`gate/gate_run.py`）

| 阶段 | 检查内容 |
|---|---|
| 0 wheelhouse 锁 | 本地 `wheelhouse/SHA256SUMS` 逐 wheel 验哈希，拒绝锁外 wheel |
| 1 源码准入 | 清单白名单逐文件验 SHA-256；拒绝符号链接/非常规文件/拒绝路径/未列文件/哈希漂移；canary 内容扫描；只把 `package-source`、`approved-sample`、`packaging-metadata`、`project-doc` 角色复制进 pristine 树 |
| 2 PEP 517 sdist | 无第三方依赖的最小前端（`pep517_driver.py`）在隔离子进程中调用 `setuptools.build_meta.build_sdist`，`sys.path` 仅含 wheelhouse，环境变量清空、`PIP_NO_INDEX=1`、代理指向不可达地址 |
| 3 sdist 审计 | tar 成员路径安全（绝对路径/`..`/反斜杠/设备/链接一律阻断）；成员映射到清单哈希或窄口径生成元数据；`SOURCES.txt` 闭包与非打包角色互斥；canary 扫描 |
| 4 sdist → wheel | 解压**已审计的 sdist**，在第二个隔离构建环境重建 wheel（永远不从工作树直接出 wheel） |
| 5 wheel 审计 | zip 成员模式位拒绝链接；成员只允许 `src/` 下 package-source 与 `.dist-info` 元数据；逐行校验 `RECORD` 哈希并检查无遗漏/悬挂条目；canary 扫描 |
| 6 隔离安装 | 全新 venv，`--no-index --find-links wheelhouse` 安装重建 wheel；按 RECORD 逐文件比对安装树，拒绝符号链接与未记录文件；断言 `redacta` 导入来源是 site-packages 而非源码路径；验证 console script |
| 7 黑盒 smoke | 仅注入当次生成的临时 `REDACTA_KEY`（不写入报告），用安装后的包跑 publish/read/revoke，检查退出码与日志，确认抑制/跨表 token 关联/撤销语义不变；日志不得回显密钥或 canary |
| 8 报告绑定 | 报告文件名与内容均绑定候选制品 SHA-256；`accepted/` 保留 PEP 规范文件名并附 `SHA256SUMS` 旁车；仅全部通过才写入 `accepted/`，失败写入 `quarantine/` 且 `accepted/` 保持空 |

### 失败如何阻止旧制品继续安装

- 任一阶段失败 → 进程退出码 1，制品只进 `quarantine/<run-id>/`，`accepted/` 不产生文件；
- 每次运行使用全新临时 `runs/gate-<run-id>-*/`，不读取、不复制历史制品，因此
  **重试不可能复用上一次“通过”的报告**——验收报告按本次制品哈希命名，哈希不同则报告不同；
- wheelhouse 哈希锁防止构建工具被替换；RECORD 与安装树逐字节比对防止安装环节漂移。

## 3. 离线引导

```bash
make wheelhouse        # 一次性联网：仅下载 pip/setuptools/wheel 三个纯 Python wheel
                       # 下载后立即按固定 SHA-256 校验，生成 SHA256SUMS 锁
make release-gate      # 此后全程离线（PIP_NO_INDEX=1，无 index 可达）
```

wheelhouse 已存在且与锁匹配时，引导脚本直接复用、不发起任何网络请求。

## 4. 污染实验（`experiments/run_experiments.py`）

每个实验在**临时沙箱副本**中注入 canary（真实源码树不被修改），共 17 个场景：

- `.env` 根目录、`.env.production.bak` 改名、嵌套 `env.local`、`..env` 变体；
- `audit.sqlite` 与嵌套 `*.sqlite-wal`；
- `releases/<id>/canary-release.jsonl` 发布目录残留、`*.jsonl.tmp` 临时文件；
- 源码树内未列 JSON、批准样例被植入 canary（先重批准清单再跑，证明 canary 扫描独立于哈希准入）、
  已列源码哈希漂移；
- 指向清单外文件的符号链接（含伪装改名的 env 链接）；
- 旧 `dist/` 中携带 canary 的残留 wheel；
- `__pycache__/*.pyc` 字节码缓存残留（缓存目录不再被静默跳过，出现即拒绝）；
- canary 仅存在于环境变量（应通过且日志无回显）；
- 干净对照（应通过，accepted/ 无 canary）。

实验断言：负例必须在文档化规则（`path-denylist`/`canary-filename`/`canary-content`/
`unlisted-file`/`hash-drift`/`symlink-refused`）处阻断，且 quarantine/reports/runs 中无 canary；
正例必须通过。结果写入 `experiments/records/contamination-<run-id>.json`。

### 阻断发生在构建之前

准入阶段失败时 PEP 517 构建不会启动，`quarantine/<run-id>/` 中只有拒绝报告、没有任何
sdist/wheel——因此不存在“被隔离的旧制品还能拿去安装”的路径。构建后阶段（sdist/wheel/
安装审计）失败时，已产出的制品进入 quarantine 且永远不会复制到 `accepted/`；`accepted/`
中的文件采用 PEP 规范原名并由 `SHA256SUMS` 旁车与按制品哈希命名的验收报告双重绑定，
同名不同字节的写入会被 `name-collision` 拒绝。

## 5. 日常使用

```bash
make check            # 既有单元测试 + smoke（业务语义保持原样）
make release-gate     # 离线发布门禁
make contamination    # 污染实验
make gate-all         # CI 全量
```

源码经评审变更后执行 `make manifest` 重生成清单；未经此步的任何源码改动都会在准入阶段
以 `hash-drift` 阻断。领域变换、k 抑制、级联撤销与 Publisher 业务语义未被门禁修改。
