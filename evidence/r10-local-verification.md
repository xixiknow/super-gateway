# R10 本地验证证据

> 验证日期：2026-08-25  
> 验证环境：Windows 11 x86_64，Rust 1.95.0，PostgreSQL 18.3  
> 证据级别：local；不代表 RC、GA 或 Linux 生产门禁通过

## 1. 验证结果

| 门禁 | 命令 | 结果 |
|---|---|---|
| 格式 | `cargo fmt --all -- --check` | 通过 |
| 静态检查 | `cargo clippy --workspace --all-targets -- -D warnings` | 通过 |
| Windows BoringSSL 全特性 | ASCII `CARGO_TARGET_DIR` 下执行 `cargo test -p gateway-transport --all-features` 与对应 Clippy | 19 通过、0 失败；Clippy 通过 |
| Workspace 测试 | `cargo test --workspace --all-targets` | 206 通过、0 失败、0 ignored |
| 真实 PostgreSQL 集成 | 8 个相互隔离的空数据库执行 R2/R4/R5/R7/R8/R9 suites | 10 个数据库门禁测试通过；守护进程测试二进制 26/26 通过 |
| 合同生成 | `python -B tools/generate_contracts.py` | 196 个 Admin operation、55 个枚举族 |
| 合同一致性 | `python -B tools/validate_contracts.py` | 47 个 JSON 文件、2981 项检查通过 |
| Workspace 一致性 | `python -B tools/validate_workspace.py` | 9 个 package、391 项检查通过 |
| Migration policy | `python -B tools/test_verify_migration_compatibility.py` | 通过 |
| systemd 单元检查 | `python -B tools/verify_systemd_units.py` | 通过 |
| Release evidence verifier 负例 | `python -B tools/test_verify_release_evidence.py` | 通过 |
| Windows Release 构建 | ASCII `CARGO_TARGET_DIR` 下执行 `cargo build --release -p super-gatewayd` | 通过 |
| R1 evidence 生成与验证 | `build_release_evidence.py` + `verify_release_evidence.py` | 8 个哈希产物通过 |
| Secret canary | `python -B tools/r9_secret_canary.py --canary <synthetic> --path target/r1-evidence-20260825-r1r10-pg --path contracts` | 147 个文件、0 个明文命中 |

## 2. 测试构成

206 个 Rust 测试来自 API、Domain、Policy、Scheduler、Services、Storage、Testkit、Transport 和 `super-gatewayd`。其中 10 个 PostgreSQL 门禁测试使用环境变量控制真实数据库执行：

- `TEST_DATABASE_ADMIN_URL`；
- `TEST_R5_ENROLLMENT_DATABASE_ADMIN_URL`；
- `TEST_ROTATION_DATABASE_ADMIN_URL`；
- `TEST_R7_DATABASE_ADMIN_URL`；
- `TEST_R4_RUNTIME_DATABASE_ADMIN_URL`；
- `TEST_R8_DATABASE_ADMIN_URL`；
- `TEST_R9_OPERATIONS_DATABASE_ADMIN_URL`。

本轮在本机 PostgreSQL 18.3 上为各 suite 建立 8 个相互隔离的空数据库，并实际执行：

| Suite | 实际执行结果 | 覆盖重点 |
|---|---|---|
| `gateway-storage/postgres_r2` | 1/1 | 全量 forward-only migration、bootstrap、角色授权与并发合同 |
| `gateway-storage/credential_r5_pg` | 1/1 | Credential 生命周期、CAS、账号去重与 PLAN 合同 |
| `gateway-services/credential_enrollment_pg` | 3/3 | OAuth PKCE、Existing OAuth、Setup Token、加密 checkpoint 与激活 |
| `gateway-services/security_rotation_pg` | 1/1 | 数据库 Business Key 轮换及仅 rewrap DEK |
| `gateway-storage/telemetry_r7_pg` | 1/1 | Request/Attempt/Usage/Cost、取消估算与单终态 |
| `super-gatewayd` R4/R8/R9 数据库路径 | 3/3；测试二进制 26/26 | Group owner 热装配、管理认证/Key 投影、Critical Alert/Outbox |

真实空库执行还暴露并闭合了 migration role 泄漏、嵌套事务、PostgreSQL 截断约束名、全局 quota 的 nullable model、Recovery 清理顺序、测试 fixture、审计表名和密码凭据切换顺序等问题。该结果证明当前 head 可在 PostgreSQL 16+ 合同兼容实例上从空库运行，但不替代 N-1/N-2 升级与备份恢复演练。

## 3. Release evidence

本地 Windows 产物位于构建目录 `target/r1-evidence-20260825-r1r10-pg/`，仅用于本机复核，不作为版本库中的发布制品。验证覆盖：

- Release binary 与部署/校验工具 SHA-256；
- `Cargo.lock`、合同树和全部 forward-only migration 校验和；
- CycloneDX SBOM；
- build provenance；
- source revision 与 `x86_64-pc-windows-msvc` target 绑定。

## 4. 仍保持阻断的外部证据

- Linux x86_64/arm64 原生 Release、BoringSSL、sanitizer、RSS 与可复现构建；
- PostgreSQL 16 的 N-1/N-2 真实升级、备份/PITR/隔离恢复 lineage；
- Managed Browser helper、Model discovery、Server酱³、SMTP/Webhook 的真实 Provider 路径；
- macOS/Linux Claude Code paired capture、H2/HPACK 与 TLS resumption evidence；
- 生产样式负载、24 小时 soak、SLO、值班与升级回滚演练；
- GA trace ledger 全部 requirement 由 `implemented/planned/blocked` 晋级为有证据绑定的 `verified`。

这些事项继续保持 fail-closed；本地结果不得解释为 RC 或 GA。
