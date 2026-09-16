# Super Gateway

Claude Code 企业网关的生产实现。部署形态为一个 Linux Rust 单体应用与 PostgreSQL；北向只承诺 Anthropic/Claude Code Gateway 协议，南向只连接 Anthropic 官方服务。

当前工程从 [R0 机器合同](contracts/README.md)生成边界开始，按 [R1–R10 实施路线图](planning/implementation-roadmap.md)推进。`transport-poc/` 保持独立证据 workspace，验证成熟的运行时组件按门禁晋升到生产 crate。

## Workspace

- `gateway-domain`：纯领域 ID、时间、secret 和状态类型。
- `gateway-policy`：Capability、RuleSet 和请求调整的纯逻辑边界。
- `gateway-scheduler`：Group owner、队列、Lease 与 deadline 边界。
- `gateway-transport`：Transport Engine 与 Bundle/Egress 边界。
- `gateway-storage`：Repository、migration 与对象存储边界。
- `gateway-services`：Credential、安全、Usage、Job 与运维服务。
- `gateway-api`：Axum 数据面与管理面协议适配。
- `gateway-testkit`：固定时钟、合成上游、故障与 evidence fixture。
- `super-gatewayd`：唯一 composition root 和生产二进制。

## 本地检查

```powershell
python -B tools/generate_contracts.py
python -B tools/validate_contracts.py
python -B tools/validate_workspace.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

真实服务配置从 `GATEWAY_` 前缀环境变量、`.env` 和 secret file reference 加载。示例见 [`.env.example`](.env.example)，示例文件只含占位值。

> **仓库路径含非 ASCII 字符时**（例如中文目录）：BoringSSL 的 Windows NASM 构建无法处理非 ASCII 中间路径，`cargo build` 会失败。请把 Cargo 中间产物放到 ASCII 路径——设环境变量 `CARGO_TARGET_DIR=C:/some-ascii-path`，或在仓库根自建 `.cargo/config.toml`（已被 `.gitignore` 忽略，不要提交）：
>
> ```toml
> [build]
> target-dir = "C:/codex-targets/super-gateway-runtime"
> ```

## Windows 本机运行

本机开发模式不依赖 Docker。它使用已安装的 PostgreSQL 16+ 工具创建隔离的
`.super-gateway-local/` 数据集群，不修改 Windows 中已有的 PostgreSQL 服务或数据库。

```powershell
cargo run --locked -p super-gatewayd -- local
```

`local` 每次启动都会自动完成以下步骤：

1. 从 `C:\Program Files\PostgreSQL\<VERSION>\bin` 发现最新的 PostgreSQL 16+；
2. 首次运行初始化私有 cluster，并自动选择一个空闲回环端口；
3. 创建缺失的 `super_gateway` 数据库；
4. 执行当前二进制内嵌的全部 SQLx migration，后续版本新增 migration 也在启动时自动应用；
5. 生成本地 digest/audit key 和首次管理员密码；
6. 验签、编译并幂等登记内置的 Windows Claude Code 2.1.241 Bundle；
7. 启动数据面 `127.0.0.1:8080` 与管理面 `127.0.0.1:8081`。

首次管理员用户名为 `admin`，随机密码保存在
`.super-gateway-local/admin-password`。管理台地址为
`http://127.0.0.1:8081/admin/`。

`local` 模式只校验用户名和密码，不要求注册或输入 TOTP 第二因素；首次管理员仍需在首次登录时修改随机初始密码。普通生产启动保留完整的 MFA 流程。

可选覆盖项：

```powershell
$env:GATEWAY_LOCAL_POSTGRES_BIN='D:\PostgreSQL\18\bin'
$env:GATEWAY_LOCAL_POSTGRES_PORT='55432'
$env:GATEWAY_LOCAL_STATE_DIR='D:\super-gateway-local'
cargo run --locked -p super-gatewayd -- local
```

Windows x86_64 本机使用 BoringSSL `ProductionTransportCore`。内置 Bundle 固定显示
`Claude Code 2.1.241`，状态为 `active / passed / loadable`；`local` 只安装和加载该只读
资源，不启动 Claude CLI、不采集证据，也不执行 Replay 或编译发布流水线。后续版本的
采集与签名由 `transport-poc release-bundle` 独立执行，上传后仍需在管理页单独激活。

## 容器部署

管理前端在构建阶段嵌入 `super-gatewayd`，因此一个 Linux 容器同时提供数据面、管理 API 与 `/admin/` 管理页面，无需额外部署 Nginx 或 Node.js 运行时。PostgreSQL 保持外部持久依赖。

```bash
docker pull ghcr.io/xixiknow/super-gateway:latest
docker compose --env-file deploy/container/.env up -d
```

镜像支持 `linux/amd64` 与 `linux/arm64`。完整 Secret、Bundle、端口、升级和只读文件系统配置见 [容器部署说明](deploy/container/README.md)。

## R1 发布证据

Linux x86_64 与 arm64 release lane 会分别执行可重复构建比较，并生成二进制、CycloneDX 1.6 SBOM、release manifest、provenance 和 evidence manifest。对应入口为：

```powershell
python -B tools/build_release_evidence.py --binary PATH_TO_BINARY --target TARGET --output-dir dist/evidence
python -B tools/verify_release_evidence.py dist/evidence
```

本地脚本不默认宣称质量门禁已运行；只有 CI 或调用方通过重复的 `--gate NAME=passed` 显式写入已通过门禁。完整流水线见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)。
