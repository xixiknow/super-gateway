# Claude Code Transport Spike

这是 `super-gateway` 的上游传输拟态验证工程，对应
[Transport POC 设计](../planning/transport-poc.md)。它先固定采集证据的格式、脱敏边界和可重复验证入口，再接入 BoringSSL、有序 HTTP/1.1 writer 与可控 HTTP/2 发送器。

## 当前已实现

- `capture-schema`：TLS ClientHello、HTTP/1.1 请求、HTTP/2 帧、连接生命周期、SSE 与取消行为的版本化采集模型和结构校验。
- `wire-normalizer`：连接 ID、目标地址、认证/会话字段、动态 TLS 属性、正文哈希和精确时间的归一化；保留协议顺序、尺寸和取值形态。
- `wire-diff`：校验归一化制品完整性，逐字段比较 TLS/H2/Header/连接行为，并输出 `PASS|FAIL|INCONCLUSIVE` 报告。
- `archetype-bundle`：将 verified Manifest 与双路参考证据编译成 Transport Engine 可加载的 Bundle candidate，并验证证据绑定、完整性和凭据数据隔离。
- `transport-core`：验证 Bundle 加载、BoringSSL + 有序 H1 writer/H2 能力审计、Probe/Canary fail-closed 门禁、协议判别 Replay Plan 编译与受控重放；Canary TLS 证据绑定 Bundle、Probe Plan、后端、目标和 Engine 二进制哈希后才可解除对应 wire blocker。
- `tls-tap`：无 TLS 终止的一次性 pass-through tap，捕获并解析脱敏 ClientHello 形态；支持通过继承的上级 HTTP CONNECT 代理链式出站，代理认证只在内存中使用并在 Debug 中脱敏。
- `controlled-h2-capture`：使用内存采集 CA 的受控 TLS 端点，按客户端实际协商接受 HTTP/1.1 或 H2；捕获 HTTP/1.1 请求形态，或 H2 Preface、SETTINGS、ACK、HEADERS。
- `claude-capture-runner`：隔离启动真实 Claude Code，自动配置临时 Base URL、合成认证和临时 CA；只持久化归一化证据。官方 TLS 路径支持随机无效认证，也支持用本机登录态执行真实订阅端到端验证；真实模式必须取得成功 `assistant/result` 且无 retry 才落盘。
- `subscription-response-probe`：研发专用的真实订阅响应语义探针；本地终止一次性采集 TLS，经原有 HTTP CONNECT 出口和证书校验后的 BoringSSL H1 连接转发到 Anthropic，只持久化响应 Header 的安全值/形态、CLI SSE 类型和 usage，不保存凭据、Prompt、请求/响应正文。其结果不作为 Transport Archetype 指纹证据。
- `transport-runtime-lab`：CONNECT/SOCKS5 之外的 SSE 字节透传、取消矩阵、H2 Stream 取消隔离、Pool Key 和 mocked 负载验证。
- `transport-matrix`：加载真实 Windows Bundle，以实际 BoringSSL/TLS/H1 socket 集中验证 20 次单连接复用、idle、resumption 安全基线、完整 Pool Key、direct/CONNECT/SOCKS5、错误归因和 C01–C06 取消矩阵。
- `capture-endpoint`：隔离采集端点，默认 Bearer Token 认证、4 MiB 请求上限、仅持久化归一化证据、幂等写入和 capture ID 冲突检测。
- `spike-cli`：生成合成双路/重放样本、校验与归一化、构建 verified Manifest、运行 wire diff，并执行 Bundle 能力审计、Replay Plan 编译和 20 次 fresh 稳定性矩阵。

当前已能直接捕获 Rust Replay 的实际 ClientHello、解密后 H2 帧，以及 Windows 上真实 Claude Code 的受控协议请求。Windows Claude Code 2.1.241 当前 cohort 已完成 20 组官方 TLS/受控端点配对：官方 ClientHello 稳定为 17 个 Cipher、14 个 Extension、`http/1.1` ALPN、512 字节 ClientHello/517 字节 Record；受控 Messages lane 稳定为 HTTP/1.1 和 15,347 字节 Body。旧 cohort 的 18 Cipher、10 Extension、空 ALPN、251/256 字节画像被矩阵确定性判为陈旧，说明 Claude Code 版本号和可执行文件哈希相同也不足以替代 capture cohort。Bundle v2 增加按 Profile 启用 OCSP stapling/SCT Extension，20/20 官方 reference 稳定性、20/20 受控 reference 稳定性、20/20 TLS Replay 和 20/20 H1 Replay 全部通过。当前 Bundle 联合 TLS/取消证据后的审计为 `ReadyForCanary / blockers=0`。新增 Transport Matrix 又以 17/17 通过 Windows 网关 Replay 的 pooled/idle、代理路径、多阶段取消、残余响应逐出和隔离域矩阵；真实 Claude Code 受控采集器修复 terminal TLS close 处理后连续 20/20 成功。Windows 本机主门禁已基本解除，仍保留单进程真实客户端 pooled/并发 reference 增强项；Linux 发布门禁和 macOS/Linux Archetype 按当前环境条件延后。

## 工程结构

```text
transport-poc/
├── crates/
│   ├── capture-schema/      # 原始采集批次契约与验证
│   ├── wire-normalizer/     # 落盘前的确定性归一化
│   ├── wire-diff/           # 结构化差异、等级和发布门槛
│   ├── archetype-bundle/    # Bundle schema、编译器与完整性校验
│   ├── transport-core/       # 能力审计、Replay Plan 与后端适配
│   ├── tls-tap/              # ClientHello pass-through 捕获
│   ├── controlled-h2-capture/# 受控 TLS/H2 观测端点
│   ├── transport-runtime-lab/# SSE/取消/池隔离/负载验证
│   ├── transport-matrix/     # pooled/代理/取消实际传输矩阵
│   ├── capture-endpoint/    # 隔离证据接收与查询服务
│   ├── claude-capture-runner/# 真实 Claude Code 自动双路采集器
│   ├── subscription-response-probe/# 真实订阅响应 Header 语义探针
│   └── spike-cli/           # fixture / validate / normalize 工具
├── Cargo.lock
├── Cargo.toml
└── rust-toolchain.toml
```

## 快速验证

在本目录运行：

```powershell
cargo run -p spike-cli -- sample --output var/e2e/raw.json
cargo run -p spike-cli -- validate --input var/e2e/raw.json
cargo run -p spike-cli -- normalize --input var/e2e/raw.json --output var/e2e/normalized.json
cargo run -p spike-cli -- sample-set --directory var/e2e-v2
cargo run -p spike-cli -- manifest --passive-tls var/e2e-v2/reference-official.normalized.json --controlled-http2 var/e2e-v2/reference-controlled.normalized.json --output var/e2e-v2/manifest.json
cargo run -p spike-cli -- diff --reference var/e2e-v2/reference-controlled.normalized.json --candidate var/e2e-v2/replay-controlled.normalized.json --output var/e2e-v2/diff-report.json
cargo run -p spike-cli -- bundle --manifest var/e2e-v2/manifest.json --passive-tls var/e2e-v2/reference-official.normalized.json --controlled-http2 var/e2e-v2/reference-controlled.normalized.json --output var/e2e-v2/bundle.json
cargo run -p spike-cli -- verify-bundle --input var/e2e-v2/bundle.json
cargo run -p spike-cli -- audit-bundle --input var/e2e-v2/bundle.json --mode probe --output var/e2e-v2/transport-audit-probe.json
cargo run -p spike-cli -- audit-bundle --input var/e2e-v2/bundle.json --mode canary --output var/e2e-v2/transport-audit-canary.json
cargo run -p spike-cli -- plan --bundle var/e2e-v2/bundle.json --target-kind controlled-capture --authority capture.invalid --port 9443 --mode probe --output var/e2e-v2/replay-plan.json
cargo run -p spike-cli --all-features -- capture-h1-diff --plan var/real-capture/windows-2.1.241.plan.json --reference var/real-capture/controlled-windows-2.1.241.normalized.json --output-capture var/real-capture/windows-2.1.241.h1-replay.normalized.json --output-diff var/real-capture/windows-2.1.241.h1-wire-diff.json --output-evidence var/real-capture/windows-2.1.241.h1-replay.evidence.json
cargo run -p spike-cli --all-features -- capture-tls-diff --plan var/real-capture/windows-2.1.241.official.plan.json --reference var/real-capture/official-windows-2.1.241.normalized.json --ca-bundle C:\path\to\ca-bundle.crt --output-capture var/real-capture/windows-2.1.241.tls-replay.normalized.json --output-diff var/real-capture/windows-2.1.241.tls-wire-diff.json --output-evidence var/real-capture/windows-2.1.241.tls-replay.evidence.json --output-canary-evidence var/real-capture/windows-2.1.241.tls-canary-evidence.json
cargo run -p spike-cli --all-features -- audit-bundle --input var/real-capture/windows-2.1.241.bundle.json --mode canary --probe-plan var/real-capture/windows-2.1.241.official.plan.json --tls-evidence var/real-capture/windows-2.1.241.tls-canary-evidence.json --output var/real-capture/windows-2.1.241.audit-canary-with-tls.json
cargo run -p spike-cli --all-features -- capture-h1-cancellation --plan var/real-capture/windows-2.1.241.plan.json --output-evidence var/real-capture/windows-2.1.241.h1-cancellation-evidence.json
cargo run -p spike-cli --all-features -- audit-bundle --input var/real-capture/windows-2.1.241.bundle.json --mode canary --probe-plan var/real-capture/windows-2.1.241.official.plan.json --probe-plan var/real-capture/windows-2.1.241.plan.json --tls-evidence var/real-capture/windows-2.1.241.tls-canary-evidence.json --cancellation-evidence var/real-capture/windows-2.1.241.h1-cancellation-evidence.json --output var/real-capture/windows-2.1.241.audit-canary-with-evidence.json
cargo run -p spike-cli --all-features -- fresh-stability-matrix --official-plan var/real-capture/windows-2.1.241-fresh-v1/windows-2.1.241.current.official.plan.json --controlled-plan var/real-capture/windows-2.1.241-fresh-v1/windows-2.1.241.current.controlled.plan.json --reference-directory var/real-capture/windows-2.1.241-fresh-v1/reference --iterations 20 --reference-collection-attempts 25 --ca-bundle C:\path\to\ca-bundle.crt --output-directory var/real-capture/windows-2.1.241-fresh-v1/replay --output-report var/real-capture/windows-2.1.241-fresh-v1/fresh-stability.report.json
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p transport-runtime-lab --bin runtime-load -- var/e2e-v2/runtime-load-current.json
cargo run -p transport-matrix -- --bundle var/real-capture/windows-2.1.241-fresh-v1/windows-2.1.241.current.bundle.json --output var/real-capture/windows-2.1.241-fresh-v1/windows-2.1.241.current.transport-matrix-v2.json --pooled-requests 20 --idle-millis 250
```

### 自动采集真实 Claude Code

Windows 下 BoringSSL/NASM 的中间构建路径使用 ASCII 目录。`controlled` 只连接本地合成 Messages 端点，不使用真实 Credential，也不产生 Anthropic 用量：

```powershell
$env:CARGO_TARGET_DIR = "C:\codex-targets\super-gateway-transport"
cargo run -p claude-capture-runner --features boring-backend -- `
  --claude-bin "C:\path\to\claude.exe" `
  --output "var\real-capture\controlled-windows.normalized.json" `
  controlled
```

Runner 为每次运行创建临时 Claude 配置目录、临时 CA 和随机合成认证，隔离用户/项目 settings 对 Base URL 的覆盖。受控端点会先应答已确定的会话标题后台请求，再继续等待主 Messages 请求；只有真实 Claude 子进程正常退出、产生 `assistant` 与 `result` 且没有 API retry 时才落盘证据。请求正文、合成认证、临时 settings、Claude stdout/stderr 均不落盘；输出文件只包含归一化协议形态和隐私安全的请求结构摘要，并采用原子新建语义拒绝覆盖已有证据。

批量稳定性入口每轮启动独立真实 Claude Code 进程，并按错误类别汇总而不记录秘密。Windows 2.1.241 修复完整响应后的 terminal TLS close 处理后，实测 20/20 成功、0 失败：

```powershell
cargo run -p claude-capture-runner --features boring-backend -- `
  --claude-bin "C:\path\to\claude.exe" `
  --output "var\real-capture\controlled-stability.report.json" `
  controlled-batch --iterations 20 `
  --output-dir "var\real-capture\controlled-stability"
```

Capture Manifest v2 只绑定两条 lane 共有的逻辑场景字段；`expected_protocol` 保留在各自 evidence 中。因而同一场景的官方被动 TLS lane 与受控 endpoint lane 可以分别观察到 H2 和 HTTP/1.1，而不会被错误判为场景不一致。

官方 TLS 被动采集通过本地受限 CONNECT tap 转发到 `api.anthropic.com:443`。推荐使用 `--synthetic-auth`：Runner 会移除继承的 Anthropic 认证环境变量并注入随机无效 token，TLS ClientHello 形成后即已取得所需证据；后续认证失败和有限重试不产生模型响应，也不要求本机登录订阅账号。

```powershell
cargo run -p claude-capture-runner --features boring-backend -- `
  --claude-bin "C:\path\to\claude.exe" `
  --output "var\real-capture\official-windows.normalized.json" `
  --capture-run-id "SHARED_RUN_UUID" `
  official-tls --synthetic-auth
```

`--execute-paid-request` 仅用于管理员明确需要验证真实账号端到端调用的场景，并与 `--synthetic-auth` 互斥。Runner 将本地 Tap 写入临时高优先级 settings；如果启动环境已有 `https_proxy|HTTPS_PROXY|http_proxy|HTTP_PROXY`，Tap 按 Claude Code 的优先顺序继承第一个 HTTP 代理，形成“Claude Code → 本地 Tap → 上级 CONNECT 代理 → Anthropic”的链式隧道，避免采集时意外改变 Credential 出口。支持 URL 中的 Basic 认证，凭据不进入输出、Debug 或归一化证据。

```powershell
cargo run -p claude-capture-runner --features boring-backend -- `
  --output "var\real-capture\official-windows-subscription-e2e.normalized.json" `
  --timeout-seconds 60 `
  official-tls --execute-paid-request --model claude-opus-4-6 `
  --prompt "Reply with exactly: OK"
```

Windows 2.1.241 已实测该模式：链式上级代理启用、真实 `claude.ai` Pro OAuth 请求完成、Claude Opus 4.6 返回成功、无 retry；CLI 流输出观察到 `message_start → content_block_start → content_block_delta → content_block_stop → message_delta → message_stop`，并得到 usage 与限流事件。Tap 保持 TLS pass-through，只验证官方 ClientHello 和 CLI 可见流事件。

原始响应 Header 已由独立语义探针补齐。该探针保留本机真实 OAuth 登录态，将 Claude Code 指向仅存活于本次进程的本地 TLS 端点，再通过继承的上级 HTTP CONNECT 代理和强证书校验转发到 `api.anthropic.com`。它会改变研发探针的 TLS/H1 路径，所以其证据只回答“Anthropic 返回了哪些响应 Header”，不参与 Archetype/ClientHello/HTTP2 判定。

```powershell
cargo run -p subscription-response-probe -- `
  --output "var\real-capture\subscription-response-headers-windows-2.1.241.report.json" `
  --execute-paid-request --model claude-opus-4-6 `
  --prompt "Reply with exactly: ok" --timeout-seconds 60
```

Windows 2.1.241 实测获得 HTTP 200、`text/event-stream`、chunked、gzip、哈希后的 `request-id`，以及订阅 `anthropic-ratelimit-unified-*` 的 5h/7d status、reset、utilization、representative claim 和 overage 状态。本次 200 未返回 `retry-after`；探针已为后续 429/5xx 样本保留该 Header 的安全原值采集规则。CLI 同时完成 6 类 SSE 事件且无 retry，usage 为 3,335 input / 4 output tokens。请求/响应正文、Credential、Prompt 和 completion 均不落盘。

同一环境的 controlled 与 official 两路应传入相同 `capture_run_id`，之后才可组装 Manifest。CONNECT tap 仅放行配置的 Anthropic authority；启动期其他 HTTPS 目标会收到 403，并在有界次数内继续等待目标连接。

合成原始样本故意含有 `authorization`、内部 authority、原始连接 ID、Session ID 和 runner label。归一化文件应只保留这些值的类别与长度，不出现原值。

## 启动隔离采集端点

```powershell
$env:CAPTURE_ENDPOINT_TOKEN = "replace-with-a-random-token"
cargo run -p capture-endpoint -- --bind 127.0.0.1:9443 --store var/captures
```

端点：

- `GET /healthz`：探活，不要求 Token，不读取采集数据。
- `POST /v1/captures`：提交 `CaptureBatch`；首次保存返回 `201`，相同批次重传返回 `200`，相同 ID 的不同内容返回 `409`。
- `GET /v1/captures/{capture_artifact_id}`：读取单个归一化证据。同一次双路采集共享 `capture_run_id`，但每路拥有独立 `capture_artifact_id`。

采集接口使用 `Authorization: Bearer <token>`。认证在 JSON 正文解析前执行。当前 Spike 版本只接受 loopback 监听；省略 Token 时，还需显式传入 `--allow-unauthenticated-loopback`。跨机器采集将在 mTLS listener 完成后开放。

## 隐私与证据边界

- 原始 `CaptureBatch` 只参与内存校验与归一化，不写文件、不进入日志。
- 认证 Header、Session/Request ID、billing 字段以及动态 TLS 值不保留原文。
- 内部采集域名统一为 `capture_endpoint`，原始 connection ID 映射为批次内稳定的 `conn-N`。
- Header 顺序、HTTP/1.1 请求形态、HTTP/2 SETTINGS 顺序、帧序、TLS 扩展顺序和尺寸保留，用于后续 wire diff。
- 持久化文件使用 `create_new`，已有 ID 不会被覆盖。
- 归一化制品回读和 diff 前都会重算完整性摘要；内容被修改后会拒绝进入比较。
- `normalized_sha256` 是归一化证据完整性摘要；后续 wire diff 会另行计算排除 run ID、观察时间等字段的可比性摘要。

## Wire Diff 判定

- `NORMALIZED_EXACT`：排除 artifact/run/time 等实验元数据后，线级投影完全一致。
- `BEHAVIORAL_MATCH`：只有时间桶等已定义行为差异，且处于配置容差或有证据的允许项内。
- `UNCLASSIFIED_DRIFT`：出现尚未归类的变化，结果为 `INCONCLUSIVE`，阻止进入 Canary。
- `HARD_MISMATCH`：TLS/H2/Header 固定字段、顺序、尺寸或协议行为不同，结果为 `FAIL`。

允许差异策略只可将 `UNCLASSIFIED_DRIFT` 降为有证据的行为匹配；硬字段不受 allowlist 影响。报告采用 JSON Pointer 路径定位每个差异，并按 TLS、HTTP/1.1、HTTP/2、Header、连接、SSE 与取消行为分层。

## Archetype Bundle candidate

Bundle Compiler 只接受状态为 `verified|canary|active` 的 Manifest，并逐项核对 Manifest 中的 artifact ID、run ID、lane、归一化哈希、事件数量、环境、场景和 normalizer 版本。Bundle Schema v2 以 `application.protocol=http1|http2` 判别应用层 Profile；Replay Schema v4 额外固化 Supported Groups、KeyShare 组，并在审计项中记录已消费的验证证据哈希；当前 candidate 包含：

- ClientHello 版本、Cipher 顺序、Supported Groups、KeyShare 组、扩展顺序、ALPN、长度与动态字段路径；
- HTTP/1.1 的请求方法、路径形状、版本、正文长度和 Content-Length framing，或 HTTP/2 的帧序、SETTINGS 顺序、连接窗口和 pseudo-header 顺序；
- Header 顺序、大小写和 `exact|shape|credential_derived_secret` 值规则；
- 已观察连接生命周期、协议、resumption 和并发 Stream；
- engine API、Linux x86_64/arm64 兼容目标、证据哈希和强制 Wire Diff 门槛。

Bundle 中的动态 TLS 值和 Credential/Session Header 只保留生成规则或形态。Bundle 自带 canonical SHA-256；加载前使用 `verify-bundle` 复核，重新计算哈希也绕不过隐私不变量。

## Transport Core 门禁

- `probe`：允许生成受控采集目标的 Replay Plan，但会在审计制品中标出所有需要 wire verification 或缺少证据的控制点。
- `canary`：任一控制点尚需 wire verification、需要补丁、缺少证据或未声明实现时，立即阻止 Plan 产出。wire verification 只接受由成功且未截断的官方 TLS Diff 构建的证据；证据必须同时匹配 Bundle、Probe Plan、后端、Anthropic authority 和 Engine 二进制哈希，TLS 硬字段不接受 allowlist。
- H2 公开 Builder 已映射 SETTINGS 1–6 和 connection-level WINDOW_UPDATE；顺序、帧序、pseudo-header 顺序及 HPACK 字节仍由 Wire Diff 门禁。
- H1 使用低层有序字节 writer，直接保留请求行、Header 顺序/大小写和 Content-Length framing；ALPN 严格来自具体 Bundle，空列表保持不发送，当前 Windows cohort 则发送 `http/1.1`。
- BoringSSL 可选后端已接入 ALPN、TLS 1.2 及以前 Cipher 顺序、Supported Groups/KeyShare 选择、OCSP stapling、SCT、GREASE 和扩展随机化开关；Windows ASCII 构建目录下已完成 C/ASM 全量编译、链接和真实 TLS/H1/H2 探针。

### 真实 TLS/H2 探针

`boring-backend` feature 会启用 `tokio-boring` 真实连接路径。探针会重新验证 Replay Plan 哈希，并强制证书链、主机名、SNI 和 ALPN；输出只包含目标、IPv4/IPv6 类别、TLS 版本、Cipher、证书 SHA-256、resumption 和耗时，不落盘本机/对端 IP。

Windows 下 BoringSSL/NASM 的中间构建路径应使用 ASCII 目录：

```powershell
$env:CARGO_TARGET_DIR = "C:\codex-targets\super-gateway-transport"
cargo run -p spike-cli --features boring-backend -- probe-tls --plan var/e2e-v2/replay-plan-anthropic.json --ca-bundle C:\path\to\ca-bundle.crt --output var/e2e-v2/tls-probe-anthropic.json
cargo run -p spike-cli --features boring-backend -- probe-h2 --plan var/e2e-v2/replay-plan-anthropic.json --ca-bundle C:\path\to\ca-bundle.crt --output var/e2e-v2/h2-probe-anthropic.json
```

`probe-h2` 只执行 TLS + H2 Preface/SETTINGS，不发送 Messages 请求或认证数据。它证明 SETTINGS 值可被后端消费；SETTINGS 线上顺序、服务端 SETTINGS、HPACK 及帧序仍要依靠受控 Capture Endpoint 与 Wire Diff 验证。

### 实际 TLS/H1/H2 捕获与运行时试验

`capture-tls-diff` 会启动 pass-through tap，捕获 Replay 实际 ClientHello 并与同目标 reference 比较。`capture-h1-diff` 会按 Bundle 生成等长合成 Messages Body，以低层 writer 重放有序 Header，再由受控端点捕获请求行、Header 和 framing；`capture-h2-diff` 捕获 SETTINGS、ACK 和 HEADERS。合成 Credential/Header 值只在内存中存活，落盘前置空。

Windows 2.1.241 的 H1 重放已验证 21 个 Header 名称/顺序完全一致、正文长度 `15,347` 字节一致、状态为 HTTP 200；Wire Diff 为 `PASS/BEHAVIORAL_MATCH`。本地握手时间桶差异按实验容差处理；透明 SSE 响应因合成正文不同产生的 2 字节差异由 `product-decision:transparent-response-body-sse` 显式归类，不放宽任何请求行、Header、Body framing 硬字段。

Windows 2.1.241 当前 cohort 的官方同目标 TLS 重放也已通过。Replay 实际 ClientHello 与 20 份官方 reference 在 17 个 Cipher 的集合及顺序、14 个 Extension 的集合及顺序、`X25519/P-256/P-384` Supported Groups、单个 `X25519:32` KeyShare、`http/1.1` ALPN、512 字节 ClientHello 和 517 字节 TLS Record 上完全一致。BoringSSL 按 Bundle 是否包含 Extension 5/18 决定是否启用 OCSP stapling/SCT；报告仅允许本地 CONNECT 建链时间桶差异，不放宽任何 TLS 硬字段。握手只连接 `api.anthropic.com:443` 并校验证书，没有发送 Messages Body 或 Credential。

当前结果已生成 `windows-2.1.241-fresh-v1/windows-2.1.241.current.tls-canary-evidence.json`。证据验证器会重算报告和证据摘要，限定 reference/replay official TLS lane，只允许有来源的连接时间桶差异，并固定声明 6 个 TLS 控制点。Canary audit 实际消费后，`tls_cipher_order`、`tls_extension_order`、`tls_client_hello_length`、`tls_record_framing` 四个原 wire blocker 均带证据哈希解除。

`capture-h1-cancellation` 使用同一真实 BoringSSL + 有序 H1 writer 向受控 TLS 服务发送 Bundle 对应的合成 Messages 请求。服务端提交 200 Header 与首段 SSE 后保持响应未结束，Transport Engine 随即取消并驱逐 H1 连接；服务端独立观察到 peer close，已收到的响应字节保持原样且不追加平台事件。取消证据绑定 controlled Probe Plan、Bundle、后端和 Engine 二进制哈希。与 TLS 证据联合消费后，`cancellation_behavior` 解除，当前 `windows-2.1.241.current.audit-canary.json` 为 `ReadyForCanary / blockers=0`。该探针验证网关南向取消动作，不冒充真实 Claude Code 客户端的 Ctrl+C 行为。

`fresh-stability-matrix` 要求至少 20 个成功的同 run ID 双路 reference，并同时比较 reference cohort 自身漂移和每轮 Replay。历史执行中 25 次受控采集启动取得 20 个成功配对，5 次在完整交换后的本地连接重置均失败关闭且没有落盘；汇总报告保留 `reference_collection_attempts=25` 和 `reference_collection_failures=5`。terminal TLS close 修复后的独立真实 Claude 受控批次为 20/20。旧 Bundle 的 20 次 TLS Replay 全部按硬字段失败，新 Bundle 的四条子门禁和总门禁均为 20/20 `PASS`。

`transport-runtime-lab` 的单测覆盖 CONNECT Basic、HTTP 407 归因、SOCKS5 local/remote DNS、SSE 字节透传、取消不追加、H2 双 Stream 取消隔离和 Pool Key 隔离。`runtime-load` 默认运行 1,200 条并发 SSE relay 和 2,500 个短请求，输出只代表 mocked endpoint 的可行性数据。

`transport-matrix` 使用当前真实 Windows Bundle 构造本地 Replay Plan，输出绑定 Bundle、Plan、Engine 和自身 SHA-256 的报告。当前 `windows-2.1.241.current.transport-matrix-v2.json` 为 17/17 `PASS`：T02/T04/T06/ISO01、P01–P07 和 C01–C06 全部通过。T02 是网关 Transport Engine 在一条实际 TLS/H1 连接上的 20 次 pooled 证据；它与“一个真实 Claude Code 进程发出 20 次 pooled reference”保持独立口径。

## 下一批实现

1. 增加单个真实 Claude Code 进程的 20 次 pooled reference 与 10 并发 reference；网关 Replay 的 T02、idle、resumption 安全基线和代理路径已完成。macOS/Linux 双目标采集延后到具备对应环境时执行。
2. 在出现真实 H2 cohort 后，将 HPACK header block、ACK 相对时序和 pseudo-header 线级证据扩展进 Bundle；H1 连接复用与 C01–C05、多 Stream C06 已完成。
3. 为每个后续真实 H1 Bundle 自动生成 TLS 与取消证据，并为 H2 Bundle补齐 `RST_STREAM`、其他 Stream 不受影响的同类证据。
4. 在 Linux CI 全量构建 BoringSSL，完成 x86_64/arm64 目标机 smoke、sanitizer 和 RSS/heap 负载试验。
5. 未来启用 TLS Session Resumption 前，以完整 Pool Key 隔离 Ticket Store，并用真实 resumed reference/replay 与 H1/H2 成对 diff 验证；当前默认关闭且无跨域恢复。
