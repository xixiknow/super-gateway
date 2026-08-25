# R6 Transport 本地验证记录

日期：2026-08-25  
环境：Windows 11、Rust 1.95；真实 PostgreSQL 结果由后续 R10 本地证据补齐，Linux native 仍作为外部证据

## 已通过

- 生产 `gateway-transport`：JCS/SHA-256/Ed25519 Bundle、TrustStore、确定性 Engine Catalog、九字段 PoolKey、Catalog activation generation、H1、direct/CONNECT/SOCKS5、BoringSSL、ConnectionAttempt、单调 TransportEvent、取消与连接处置。
- Catalog 热切换：attempt 显式冻结 activation generation；A→B 后在途 A 请求不会进入 B 的连接池 shard。
- Catalog 发布：激活事务前完整 stage，数据库 pointer 提交后原子 publish；旧 activation generation 连接池排空，迟到连接归还被拒绝，A→B→A generation 单调递增。
- 连接 deadline：代理 CONNECT/SOCKS5、TCP 与 TLS 共享同一个绝对 deadline，不在阶段切换时重新计时。
- Canary：Bundle 需要 20 次精确、机器绑定 evidence；正常 Credential 分配只接受 Active Archetype/Bundle，Canary 不进入普通调度。
- `gateway-transport` 默认 feature 测试 16/16；在纯 ASCII `CARGO_TARGET_DIR` 下启用 BoringSSL 的 `--all-features` 测试 19/19 通过。
- 全 Workspace Clippy 与 `gateway-transport --all-targets --all-features` Clippy（`-D warnings`）通过。
- 机器合同：47 个 JSON 文件、2981 项一致性检查通过。
- Workspace 边界：9 个 package、391 项检查通过。
- 本文最初记录时 PostgreSQL 路径仅编译未执行；后续 [R10 本地验证证据](r10-local-verification.md) 已在相互隔离的 PostgreSQL 18.3 空库实际执行 R2/R5/R7 与守护进程数据库 suites。
- CI 已增加 Linux x86_64 native BoringSSL transport test/Clippy lane；arm64 release 仍保留独立构建 lane。

## 对应能力保持关闭

- H2：Bundle/compiler/管理状态合同存在；在取得真实 SETTINGS、ACK、frame 与 HPACK 证据前，生产执行路径返回明确的 `h2_bundle_activation_disabled_without_wire_evidence`，不会退化到 H1 或普通 Hyper client。
- TLS resumption：Bundle 与 TLS connector 均保持关闭；没有 evidence 时不建立 TicketStore。

## 外部 Promotion Gate

以下项目不属于本机代码缺口，但继续阻断对应 promotion：

- 生产 Engine Windows H1 exact replay；
- Linux x86_64 与 arm64 目标机 native BoringSSL evidence；
- sanitizer、RustSec、license 与 release SBOM evidence；
- 固定规格 Linux RSS/heap/latency；
- 24 小时混合 transport soak；
- macOS/Linux Claude Code paired capture（只阻断对应 Archetype）；
- H2/HPACK 与 TLS resumption 真实证据（只阻断对应能力激活）。

## 本地复现命令

```powershell
python -B tools/generate_contracts.py
python -B tools/validate_contracts.py
python -B tools/validate_workspace.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked --no-fail-fast
```

PostgreSQL 两个集成测试必须各自在独立空数据库执行：

```powershell
cargo test --locked -p gateway-storage --test credential_r5_pg -- --nocapture
cargo test --locked -p gateway-storage --test postgres_r2 -- --nocapture
```
