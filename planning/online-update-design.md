# 在线更新（Online Update）功能规划

日期：2026-10-07
状态：草案（待评审）

## 1. 背景与现状盘点

本仓库已经具备较完整的"升级前校验"基础设施，在线更新应当复用而不是另起炉灶：

| 能力 | 现状 | 位置 |
| --- | --- | --- |
| 升级预检（preflight） | 11 项门禁：runtime_abi、runtime_target、schema_compatibility、migration_prefix、runtime_readiness、active_transport_bundles、critical_alerts、backup_recovery_freshness，另有 filesystem_capacity / n_minus_compatibility 两个 `blocked_external` 占位 | `crates/super-gatewayd/src/operations.rs:2052`（durable job `upgrade_preflight_v1`） |
| 预检 API | `POST/GET /admin/v1/operations/upgrade-checks`（platform_admin + CSRF + Idempotency-Key，202 JobEnvelope） | `contracts/openapi/admin.openapi.json:7550`、`crates/super-gatewayd/src/admin_backend.rs:6862` |
| 发布清单 | `release-manifest.json` 固定 14 字段（schema_compatibility 窗口、migration_checksums、cargo_lock/contract_tree 摘要、artifacts） | `tools/build_release_evidence.py`、`admin_backend.rs:13933` |
| 证据门禁 | r10-local profile 固定 10 项 gate 全部 passed，`verify_release_evidence.py` fail-closed | `tools/verify_release_evidence.py` |
| 迁移兼容策略 | expand-only、候选迁移历史必须是已应用历史的严格前缀追加、schema 永不随二进制回滚、产出 `rollback_binary_check_required` | `tools/verify_migration_compatibility.py` |
| 预检数据模型 | `ops.release_manifest`（digest 钉死，同版本不同 digest 409）、`ops.upgrade_run`（`preflight_valid_until` 30 分钟窗口）、`ops.durable_job` + history | migration `20260824003100_upgrade_preflight.sql`、`crates/gateway-storage/src/upgrade.rs` |
| systemd 离线升级脚本 | 验证 evidence/迁移兼容 → check-schema（旧）→ migrate（候选、独立 migrator 身份）→ 停服 → `mv -Tf` 原子符号链接切换 → readyz 60s 观察窗 → 失败自动回滚 | `deploy/systemd/super-gateway-upgrade.sh`（由 `tools/verify_systemd_units.py` 静态强制） |
| 版本上报 | 仅 CLI `--version`；`/healthz` `/readyz` 是刻意固定形状，不得携带版本信息 | `crates/super-gatewayd/src/main.rs:28`、`crates/gateway-api/src/probes.rs:130` |

关键结构约束（设计必须遵守）：

1. **容器内不可能原地自更新**：镜像 rootfs 只读、`cap_drop: ALL`、tmpfs `noexec`（`Dockerfile:43-79`）。容器形态的更新 = 镜像替换（`compose pull && up -d`），任何"容器内下载并替换二进制"的方案都直接排除。
2. **runtime 进程无特权**：systemd 下 `ProtectSystem=strict`、`MemoryDenyWriteExecute`，runtime 用户既不能写 `/opt/super-gateway`，也不能执行 `systemctl`。符号链接切换必须由独立特权路径完成。
3. **签名与信任根**：既有工件签名体系为 JCS(RFC 8785) 规范化 + SHA-256 + Ed25519 域分离签名 + 公钥 trust store，Historical 密钥只能验证旧工件、不能批准新激活（`crates/gateway-transport/src/bundle.rs:558`）。`planning/functional-modules.md:1810` 已要求：自动联网更新默认关闭；若开启，必须使用独立信任根与发布渠道。
4. **bundle/引擎耦合**：新二进制必须落在所有 active transport bundle 的 `min_engine_build`/`max_engine_build` 区间内，否则 `active_transport_bundles` 门禁会（正确地）挡下升级——升级编排要先把"不兼容"转成可操作的提示（先发布新 bundle 或重签）。
5. **PoC 边界**：`transport-poc/`（spike-cli 的 release bundle 签名与编排器）不在 workspace 内，生产功能不能依赖它；需要的逻辑必须在 `crates/` 内重新实现。

## 2. 目标与非目标

### 目标

- G1 版本可见性：管理台能看到运行版本、运行目标、schema 版本、活跃 bundle 及其引擎兼容区间；能手动"检查更新"。
- G2 systemd/裸机形态的在线更新：从受信任发布渠道下载新版本 → 验签 → 预检 → 原子切换 → readyz 观察 → 失败自动回滚，全程可审计、可从管理台触发。
- G3 容器形态的升级编排：提供与预检/回滚策略一致的 `deploy/container/upgrade.sh`（预检 → pull 新镜像 → up → readyz → 失败回退旧 tag）。
- G4 安全默认：自动更新默认关闭；启用时使用独立于 transport bundle 信任库的更新信任根与显式渠道配置。

### 非目标

- 不做容器内二进制自替换（结构上不可能，见约束 1）。
- 不做数据库 schema 回滚（schema 只前进，回滚只针对二进制）。
- 不改动 `/healthz` `/readyz` 的固定响应形状。
- M1/M2 不做自动定时更新（M4 再评估）。

## 3. 总体设计

### 3.1 发布渠道（Release Channel）

- 载体：GitHub Releases（`xixiknow/super-gateway`），附件为每个 target 一组：
  - `super-gatewayd-{target}.tar.zst`（二进制）
  - `release-manifest.json`（既有 14 字段格式，含 `artifacts[]` 摘要）
  - `evidence-manifest.json`（CI 产出，r10-local 10 项 gate）
  - `channel-manifest.json` 签名副本（见下）
- 渠道清单 `channel.json`（新格式）：

  ```json
  {
    "channel": "stable",
    "schema_version": "1.0.0",
    "latest": {
      "application_version": "x.y.z",
      "release_manifest_sha256": "…",
      "release_manifest_signature": { "algorithm": "ed25519", "key_id": "…", "value": "…" },
      "min_upgrade_from": "…",
      "notes_url": "…"
    }
  }
  ```

  签名沿用仓库既定模式：规范化（JCS）→ SHA-256 → Ed25519 域分离（`update_channel_v1`）。
- 信任根：渠道公钥以内置默认 + 配置覆盖的方式提供（`/etc/super-gateway/update-trust-store.json`），与 transport bundle 信任库物理隔离，满足"独立信任根"要求。支持多密钥（Current/Historical/Revoked 状态机直接复用 `bundle.rs` 的抽象）。
- 渠道 URL 可配置，默认 GitHub；自建镜像源只需替换 base URL（国内网络可达性）。
- 渠道分两档：`stable`（默认）、`fast`（灰度）。配置项 `updates.channel`、`updates.source_url`、`updates.enabled=false`（总开关，默认关）。

### 3.2 版本与检查 API（新增，走既有契约驱动路由）

所有端点进入 `admin.openapi.json` 契约与 `admin-routes.json` 注册表，沿用 platform_admin + CSRF + Idempotency-Key 语义：

- `GET /admin/v1/system/version`
  返回 `{ application_version, runtime_target, schema_version, channel, active_bundles:[{id, min_engine_build, max_engine_build}], update_feature_enabled }`。
- `POST /admin/v1/operations/updates/checks`（幂等）
  语义 = 拉取渠道清单 → 验签 → 与当前版本比较 → 拉取候选 `release-manifest.json` → 走既有 `upgrade_preflight_v1` durable job（11 项门禁不变）。body 允许 `{"source":"channel"}` 或内联 manifest（向后兼容现有 `upgrade-checks` 的本地提交语义；现有端点保持不动，新端点独立路径，避免契约漂移）。
- `GET /admin/v1/operations/updates/checks`
  列出检查与预检结果（复用 `ops.upgrade_run` + gate 结果投影）。
- `POST /admin/v1/operations/updates/applies`（幂等）
  body 必须携带 `{ run_id }`（引用一个通过且未过期的预检，30 分钟窗口校验在 apply 入口再查一次）与 `{ acknowledgements: {...} }`（对 `blocked_external` 门禁的人工确认记录，写入审计）。
- `GET /admin/v1/operations/updates/applies[/{id}]`
  应用阶段状态机投影（见 3.3）。

### 3.3 应用阶段：新 durable job `upgrade_apply_v1`

沿用 `ops.durable_job` 的租约/幂等/历史/dead-letter 模式（与 `upgrade_preflight_v1` 同构），状态机：

```
staging → verified → preflight_confirmed → drained → switching → health_watch → completed
                     ↘ (任一步失败) failed → rollback_* (若已切换)
```

各阶段要点：

1. **staging**：下载二进制 + 两份 manifest 到 `state_dir/updates/<version>/`（容器内该路径可写；systemd 下 `/var/lib/super-gateway/updates`）。断点续传、大小上限、落盘后逐一校验 `release-manifest.json` 的 `artifacts[]` 摘要；随后做 `verify_release_evidence.py` 等价的 Rust 侧校验（gate 集合必须与 profile 精确相等且全部 passed）。
2. **verified**：渠道签名验证（独立信任根）+ release manifest 仍与渠道清单摘要一致（防渠道被改后重放旧 manifest）。
3. **preflight_confirmed**：重新执行（或引用 30 分钟内有效的）预检 run；`filesystem_capacity` 在此阶段从 `blocked_external` 变为真实检查（staging 目录所在分区剩余空间 ≥ 2×二进制大小 + 迁移余量）；`n_minus_compatibility` 维持人工确认。
4. **drained**：调度器进入 drain（停止派发新请求，等待 in-flight 完成，超时上限可配，超时则中止 apply 而不是强杀）。
5. **switching**：通过**最小特权升级 helper** 完成（见 3.4）。helper 只做一件事：对"已验签目录"执行既有 `super-gateway-upgrade.sh` 的既有流程（迁移 → 原子切换 → 启动 → readyz 观察 → 失败回滚），脚本本身已是 `verify_systemd_units.py` 静态强制的契约，不重写。
6. **health_watch**：apply job 轮询 `/readyz`（60s 窗口，与脚本一致），并抽查数据面一次探测请求；写 `ops.upgrade_run` 终态 + 审计事件。
7. **completed / rollback**：`rollback_binary_check_required` 的要求在回滚路径同样成立——schema 不回滚，回滚仅回二进制符号链接，且回滚目标二进制必须仍在 `releases/` 目录且摘要匹配。

### 3.4 特权分离方案（设计决策点）

runtime 用户无权切换符号链接、无权 systemctl。候选方案：

- **方案 A（推荐，M2 落地）**：新增 `sudo`/polkit 白名单，仅允许 `super-gateway` 用户免密执行固定路径的 `/usr/local/sbin/super-gateway-apply-update`（内部固定调用 upgrade 脚本，参数白名单只接受 staging 目录与目标版本字符串，且目录内必须存在合法验签标记文件）。攻击面收敛为"能触发已验证流程"，不能注入任意命令。
- 方案 B：独立 `super-gateway-upgrade-agent` systemd 服务（拥有特权），daemon 通过本地 Unix socket 请求。更干净但多一个常驻组件，M3+ 再考虑。
- 方案 C：不内置 apply，管理台只产出"待执行升级"工单，由外部编排（ansible/ssh/人工）调用 upgrade 脚本。作为 M2 之前的过渡形态（半自动）。

容器形态（G3）没有特权问题：升级动作就是宿主机上的 `compose pull && compose up -d`，由 `deploy/container/upgrade.sh` 承载：先在**旧容器**内跑 `updates/checks` 预检 → 通过后 pull 指定 digest（不用浮 tag，防漂移）→ up → readyz 观察 → 失败 `up` 回旧 digest。迁移仍由 compose 的 `migrate` 一次性服务先行完成（现状已如此）。

### 3.5 管理台 UI（web/admin-console）

- 新增"系统 / 版本与更新"页：当前版本卡片（版本、target、schema 版本、渠道、活跃 bundle 及其引擎区间）、检查更新按钮、预检结果门禁矩阵（11 项，含 blocked_external 的确认入口）、一键升级（二次确认 + `acknowledgements` 记录）、应用历史与回滚记录。
- 沿用既有 ResourceAction / JobEnvelope 轮询模式，i18n 中英双语。

## 4. 与既有门禁的协同

- **迁移**：完全复用 expand-only 前缀追加策略与 `migration_prefix` 门禁；apply 阶段的迁移由 upgrade 脚本以独立 migrator 身份执行（`super-gateway-migrate.service` 语义不变）。
- **bundle 兼容**：preflight 的 `active_transport_bundles` 门禁保持不变；管理台在检查更新阶段就预先展示"候选版本是否落在所有 active bundle 的引擎区间内"，不兼容时给出"先发布/重签 bundle"的引导，而不是让用户在 apply 阶段撞墙。
- **备份新鲜度**：`backup_recovery_freshness` 门禁（base ≤26h、WAL ≤300s、restore drill ≤45d）意味着"升级前自动备份"可以由运维侧保证；M2 在 apply 前若检测到备份过期，直接 fail 并提示先触发备份，不代做。
- **预检 30 分钟窗口**：apply 流程内联重验，避免"预检通过→下载半小时→窗口过期"的竞态；顺序固定为"先下载验签、后预检、立即 apply"。

## 5. 分期实施

| 里程碑 | 内容 | 依赖 |
| --- | --- | --- |
| M1 版本可见性（~1 周） | `GET /admin/v1/system/version`、管理台版本页、`updates.*` 配置骨架、渠道清单格式与签名工具（Rust 侧 `crates/super-gatewayd/src/update_channel.rs`） | 无 |
| M2 systemd 在线更新（~2-3 周） | `updates/checks`、`upgrade_apply_v1` durable job、staging 下载验签、最小特权 apply helper（方案 A）、管理台一键升级、回滚演练与审计 | M1 |
| M3 容器升级编排（~1 周） | `deploy/container/upgrade.sh`（预检→pull digest→up→readyz→回退）、README/文档 | M1（预检复用） |
| M4 自动更新（可选） | 定时渠道检查 + 维护窗口 + 通知（默认关闭，开启需显式信任根与渠道配置） | M2 |

## 6. 风险与开放问题

1. **渠道可达性**：GitHub Releases 在部分网络不可达 → `updates.source_url` 必须可指向自建镜像；渠道清单签名保证镜像源只透传、不能篡改。
2. **特权 helper 的攻击面**：固定脚本路径 + 参数白名单 + 验签标记三重限制；helper 自身纳入 `tools/verify_systemd_units.py` 的静态契约检查。
3. **N-1/N-2 兼容门禁**仍为 `blocked_external`：M2 用 `acknowledgements` 人工确认兜底，M3 后考虑用 fixture 化的兼容矩阵自动化。
4. **Windows 开发环境**：在线更新仅面向 Linux 服务端部署（systemd/compose），Windows 下仅保留 M1 的版本可见性。
5. **开放问题**：渠道签名密钥的保管与轮换流程（建议与 release evidence 的 CI 签发分开，人工持有 + Historical 轮换）；`fast` 渠道是否需要在服务端做 canary 灰度（按实例 hash 分流）——M4 再定。
