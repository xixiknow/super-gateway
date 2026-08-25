# ADR-0001：生产 Rust workspace 边界

- 状态：Accepted
- 日期：2026-08-24
- 对应 Phase：R1

## 决策

生产工程采用八个 library crate 和唯一二进制 `super-gatewayd`。Credential、Security 与 Ops 在首版归入 `gateway-services` 的内部模块；出现独立 native 依赖、编译隔离或所有权边界后，再通过新 ADR 拆分。

`transport-poc` 保持独立 virtual workspace 和证据生成工具链。生产 workspace 不把它整体纳入 member，也不让采集端点、证据探针或 matrix 工具进入生产二进制。已通过门禁的 Bundle verifier、Pool Key、H1/H2/Egress 和取消算法将在 R6 以受审移植方式进入 `gateway-transport`。

## 原因

该结构遵循 `technical-architecture.md` 的依赖方向，使领域层不依赖 Tokio、Axum、SQLx、BoringSSL 或日志实现，并避免默认 `cargo test --workspace` 意外构建 POC 的全部 native BoringSSL 工具。

## 工具链

- toolchain：Rust 1.95.0；
- MSRV：1.94；
- edition：2024；
- 目标：Linux x86_64 与 arm64；
- `Cargo.lock`、构建 hash、SBOM 和 provenance 属于发布证据。
