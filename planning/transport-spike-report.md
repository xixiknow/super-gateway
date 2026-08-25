# Rust Transport Spike 最终验收报告

> 报告日期：2026-08-24  
> 实施基线：[Rust Transport Spike 计划](./transport-poc.md)  
> 工程：[`transport-poc`](../transport-poc/README.md)

## 1. 最终判定

| 项目 | 判定 |
|---|---|
| Spike 总结论 | `INCONCLUSIVE` |
| 南向方案决策 | `Blocked` |
| 是否解锁 Canary | 是，仅当前 Windows Bundle；生产流量仍未解锁 |
| 是否进入完整网关业务开发 | 可继续详细设计；生产传输仍需完成 Linux 发布门禁 |

`Blocked` 是生产南向方案的整体决策，不是对 Rust 或 BoringSSL 的否定。当前已证明 Linux Rust 单体所需的 TLS/H1/H2 执行链、代理隧道、SSE 透传、取消与池隔离可实现。Windows Claude Code 2.1.241 当前 cohort 已完成 20 组真实双路 reference 和 20 轮 TLS/H1 Replay：官方 reference 稳定性、受控 reference 稳定性、TLS Replay、H1 Replay 均为 20/20 `PASS`。TLS Diff 与 H1 streaming cancellation 已进入完整性绑定的 Canary 证据消费链，将当前 Windows Bundle 的 5 个 blocker 全部解除并得到 `ReadyForCanary`。新增 Windows Transport Matrix 又以 17/17 `PASS` 覆盖网关 Replay 的 20 次单连接复用、idle 复用、安全关闭 resumption、完整 Pool Key 隔离、direct/CONNECT/SOCKS5 内层一致、代理 TLS/认证归因和 C01–C06 多阶段取消/残余响应逐出。Windows 本机侧生产关键矩阵已经收口；单个真实 Claude Code 进程的 pooled/并发 reference 归为不阻塞 Windows Canary 的增强诊断。剩余生产关键缺口是 Linux CI/安全与负载门禁；macOS/Linux Archetype 按当前环境条件延后，因此 Windows-only Archetype v1 可继续验证，但跨 Archetype 的完整生产南向实现选择仍保持 `Blocked`。

`var/e2e-v2/reference-*` 文件是合成 fixture；其历史 `HARD_MISMATCH` 只证明 Wire Diff 门禁有效。Windows 当前结论以 `var/real-capture/windows-2.1.241-fresh-v1/reference/` 的 20 组真实 reference 为准；旧 `official-windows-2.1.241.normalized.json` 保留为版本内漂移历史证据，不再作为当前 Bundle 的编译输入。

## 2. 已完成交付

### 2.1 证据、Bundle 和门禁

- 实现版本化 `CaptureBatch`/Manifest、双路 lane 绑定与严格校验。
- 实现落盘前规范化：剔除认证、Session、目标地址和动态 TLS 值，保留顺序、尺寸与值形态。
- 实现 Wire Diff 的 `NORMALIZED_EXACT|BEHAVIORAL_MATCH|UNCLASSIFIED_DRIFT|HARD_MISMATCH` 分层和 `PASS|FAIL|INCONCLUSIVE` 决策。
- 实现 Archetype Bundle candidate 编译、canonical SHA-256、证据绑定和隐私不变式校验。
- 实现按 H1/H2 协议选择的 Probe/Canary fail-closed 能力审计，以及 Canary TLS/取消证据的构建、完整性复核和严格绑定消费。Windows H1 Bundle 的静态 audit 有 5 项 blocker；消费实测 TLS 和 H1 streaming cancellation 证据后 5 项均自动解除，审计制品逐项记录证据 SHA-256，结果为 `ReadyForCanary`。

### 2.2 TLS 真实执行和被动 Tap

- `cloudflare/boring 5.2 + tokio-boring 5.2` 已在 Windows ASCII target 目录完成 C/ASM 编译、链接与运行。
- 对 `api.anthropic.com:443` 的无凭据探针完成了证书链/主机名校验、SNI、TLS 1.3 和 ALPN `h2`。未发送 Messages 请求或 Credential。
- 无 TLS 终止的 pass-through tap 可捕获实际 ClientHello，仅保留 Cipher、Extension、ALPN、group/长度和 framing 形态；不保留 random、key share 字节、ticket/PSK 密文或 SNI 原值。
- 未应用真实 Bundle 时，BoringSSL 5.2 默认 ClientHello 会加入后量子混合 Group/KeyShare，与真实 Windows 2.1.241 reference 硬失配。Replay Schema v4 已将 TLS 1.2 及以前 Cipher 顺序、Supported Groups、KeyShare、ALPN 和 Extension 目标编译为连接器控制；当前 Profile 还按 Extension 5/18 启用 BoringSSL 原生 OCSP stapling/SCT。当前同目标 Replay 连续 20 次精确恢复 17 个 Cipher、14 个 Extension、512 字节 ClientHello 和 517 字节 Record。

证据：

- [`tls-probe-anthropic.json`](../transport-poc/var/e2e-v2/tls-probe-anthropic.json)
- [`h2-probe-anthropic.json`](../transport-poc/var/e2e-v2/h2-probe-anthropic.json)
- [`replay-official-live.normalized.json`](../transport-poc/var/e2e-v2/replay-official-live.normalized.json)
- [`tls-live-diff.json`](../transport-poc/var/e2e-v2/tls-live-diff.json)

### 2.3 受控 TLS 协议捕获与真实 Claude Runner

- 受控端点已从“强制 H2”修正为按真实客户端协商接受 HTTP/1.1 或 H2；H2 路径继续捕获 `SETTINGS → SETTINGS ACK → HEADERS`，HTTP/1.1 路径记录请求行、Header 顺序/大小写/值形态和正文长度。
- 新增 `claude-capture-runner`：每次运行自动创建隔离工作目录、Claude 配置目录、临时 CA、随机合成认证和最高优先级临时 settings；结束后自动销毁临时数据。
- Windows x86_64 上真实 Claude Code 2.1.241 已完成本地受控主请求闭环。实测协商协议为 `HTTP/1.1`，不是预设的 H2；主请求为 `POST /v1/messages?beta=true`，正文只记录 15,347 字节，不保存内容。2.1.220 的早期受控证据作为历史样本保留。
- 2.1.241 受控证据保留了 Header 顺序和形态，以及 Windows/x64、Claude Code/runtime 版本等可公开协议字段；Authorization 和 Session ID 均只保留 secret 类别与长度。
- 实测发现第一条 Messages 是会话标题后台请求，带 `json_schema` 且唯一必填属性为 `title`。受控端点先按该 schema 自动应答，再继续监听主请求；2.1.220 与 2.1.241 均提供了同类强结构候选证据，仍只进入 Background Traffic Catalog 的版本化候选和 Shadow。
- 主请求结构包含 `adaptive thinking`、`context_management` 和 `output_config.effort`。合成 SSE 只记录 1,390 字节及事件序列类别，不保存正文；Claude 子进程退出码为 0，输出包含 1 条 `assistant`、1 条 `result`，API retry 为 0。
- Runner 已改为失败关闭：子进程超时、非零退出、缺少 `assistant/result` 或出现 API retry 时不持久化受控证据。
- Capture Manifest 升级到 v2，只比较两条 lane 共有的逻辑场景字段；`expected_protocol` 保持 lane-local。回归测试已覆盖 official=`h2`、controlled=`http/1.1` 的合法配对。
- Rust Replay 的 H2 受控探针仍实测捕获 `SETTINGS → SETTINGS ACK → HEADERS`；SETTINGS 条目及顺序为 `1=65536, 4=6291456, 6=262144`。这与真实 Claude 当前受控 HTTP/1.1 证据是不同 lane/客户端事实，不再混为同一协议假设。
- 新增 `official-tls --synthetic-auth`：Runner 清除继承认证并注入随机无效 token，通过受限 CONNECT tap 取得发往 `api.anthropic.com:443` 的真实 ClientHello；认证失败发生在 TLS 证据形成之后，不产生模型响应，也不依赖订阅登录。
- Windows 2.1.241 当前矩阵包含 20 个独立 `capture_run_id`，每个 ID 绑定一份 official TLS 与一份 controlled reference；20 组的环境、版本、二进制哈希和逻辑场景均一致。Bundle Schema v2 / Replay Schema v4 已按受控证据选择 HTTP/1.1，并显式携带 Cipher、Supported Groups、KeyShare、ALPN 与 Extension 目标。
- H1 受控 Replay 使用等长合成 Messages Body 与内存合成认证，21 个 Header 名称/顺序、请求行、15,347 字节 Body 和 Content-Length framing 均与 reference 一致；端点返回 HTTP 200。Wire Diff 为 `PASS/BEHAVIORAL_MATCH`，只允许本地握手时间桶和透明 SSE 合成响应的 2 字节差异。
- 当前官方 ClientHello 的 ALPN 为 `http/1.1`；ALPN 由 Bundle 逐 cohort 固化，历史空 ALPN Profile 仍可表达，但不再用于当前 cohort。
- 官方同目标 TLS Replay 已连续 20 次通过 `PASS/BEHAVIORAL_MATCH`：17 个 Cipher 的集合与顺序、14 个 Extension 的集合与顺序、`X25519/P-256/P-384` Supported Groups、单个 `X25519:32` KeyShare、`http/1.1` ALPN、512 字节 ClientHello 和 517 字节 TLS Record 均与 reference 一致。唯一允许项是本地 CONNECT 建链时间桶；TLS 硬字段没有 allowlist。握手严格校验证书且没有发送 Messages Body 或 Credential。
- Fresh 矩阵在同一 Claude Code 2.1.241、同一 runtime、同一 OS build 和同一 Claude 可执行文件 SHA-256 下识别出两个稳定 cohort：历史 251/256 字节空 ALPN 与当前 512/517 字节 `http/1.1` ALPN。旧 Bundle 的 20/20 TLS Replay 全部 `FAIL`，新 Bundle 的四类子门禁全部 20/20 `PASS`；因此 Profile 选择必须绑定采集 cohort/epoch，不能只按版本号或二进制哈希命中。
- 历史参考采集共启动 25 次受控 pair，20 次成功、5 次在完整响应后的 Windows 本地连接重置失败；失败轮次没有持久化，汇总报告显式记录 `reference_collection_attempts=25`、`reference_collection_failures=5`。端点修复为只在完整交换之后接受 terminal TLS close 后，新 `controlled-batch` 以 20 个独立真实 Claude Code 2.1.241 进程完成 20/20、0 失败；每份证据仍含 4 个事件并保持原子落盘。
- 新增 Canary TLS Evidence v1：构建时重跑 Diff 语义校验，要求成功、完整、official TLS lane 配对、ClientHello 硬字段一致且候选与 Replay Plan 一致；持久化时绑定 Bundle SHA-256、Probe Plan SHA-256、后端、Anthropic authority、Engine 可执行文件 SHA-256 和报告 SHA-256。
- 新增 Canary Cancellation Evidence v1：真实 Transport Engine 在 200 Header/首段 SSE 已到达后取消 H1 请求，按合同关闭并驱逐连接；受控 TLS peer 独立观察到 close，已交付字节保持不追加。证据绑定 controlled Probe Plan、Bundle、后端和同一 Engine SHA-256。两类证据联合审计为 `ReadyForCanary / blockers=0`；Bundle、Plan、Engine 或证据内容漂移均失败关闭。
- 新增上级 HTTP CONNECT 代理链：Runner 在覆盖 Claude Code 代理为本地 Tap 前读取原有效代理，Tap 在内存中向该代理再次发出 CONNECT；支持 Basic 认证并对 Debug 脱敏。该能力修复了采集时绕过原代理出口导致的官方 `permission` 拒绝。
- Windows 2.1.241 的真实 `claude.ai` Pro OAuth 验收已通过：模型为 Claude Opus 4.6，CLI 退出码 0、`assistant/result` 成功、API retry 为 0；pass-through 验收观察到 6 个完整 SSE 生命周期事件、3,334 input token、4 output token 和 1 个限流事件。
- 新增研发专用 `subscription-response-probe` 并完成第二次真实 OAuth 语义验收。探针本地终止一次性 TLS，仅为读取响应 Header；上游仍通过原 HTTP CONNECT 出口，BoringSSL 显式导入 46 个 Windows 原生根并严格校验 `api.anthropic.com` 证书，ALPN 固定为 H1。实测 HTTP 200、`text/event-stream`、chunked、gzip、哈希后的 `request-id`，以及 `anthropic-ratelimit-unified-*` 的 5h/7d status、reset、utilization、representative claim 与 overage 状态；该 200 响应没有 `retry-after`。Claude 无 retry 完成六类 SSE，usage 为 3,335 input / 4 output token。
- 响应语义探针的证据范围固定为“Header 与 CLI 语义”，不参与 ClientHello、H2 或 Archetype 判定。报告只保存请求 Header 名称、Authorization 存在性/方案、响应 Header allowlist 值或形态/hash、SSE 类型和 usage；请求/响应正文、OAuth、Prompt 与 completion 均未持久化。

证据：

- [`h2-control-evidence.json`](../transport-poc/var/e2e-v2/h2-control-evidence.json)
- [`replay-controlled-live.normalized.json`](../transport-poc/var/e2e-v2/replay-controlled-live.normalized.json)
- [`h2-live-diff.json`](../transport-poc/var/e2e-v2/h2-live-diff.json)
- [`controlled-windows-2.1.241.normalized.json`](../transport-poc/var/real-capture/controlled-windows-2.1.241.normalized.json)
- [`official-windows-2.1.241.normalized.json`](../transport-poc/var/real-capture/official-windows-2.1.241.normalized.json)
- [`windows-2.1.241.manifest.json`](../transport-poc/var/real-capture/windows-2.1.241.manifest.json)
- [`windows-2.1.241.bundle.json`](../transport-poc/var/real-capture/windows-2.1.241.bundle.json)
- [`windows-2.1.241.plan.json`](../transport-poc/var/real-capture/windows-2.1.241.plan.json)
- [`windows-2.1.241.h1-replay.evidence.json`](../transport-poc/var/real-capture/windows-2.1.241.h1-replay.evidence.json)
- [`windows-2.1.241.h1-wire-diff.json`](../transport-poc/var/real-capture/windows-2.1.241.h1-wire-diff.json)
- [`windows-2.1.241.official.plan.json`](../transport-poc/var/real-capture/windows-2.1.241.official.plan.json)
- [`windows-2.1.241.tls-replay.normalized.json`](../transport-poc/var/real-capture/windows-2.1.241.tls-replay.normalized.json)
- [`windows-2.1.241.tls-replay.evidence.json`](../transport-poc/var/real-capture/windows-2.1.241.tls-replay.evidence.json)
- [`windows-2.1.241.tls-wire-diff.json`](../transport-poc/var/real-capture/windows-2.1.241.tls-wire-diff.json)
- [`windows-2.1.241.tls-canary-evidence.json`](../transport-poc/var/real-capture/windows-2.1.241.tls-canary-evidence.json)
- [`windows-2.1.241.audit-canary-with-tls.json`](../transport-poc/var/real-capture/windows-2.1.241.audit-canary-with-tls.json)
- [`windows-2.1.241.h1-cancellation-evidence.json`](../transport-poc/var/real-capture/windows-2.1.241.h1-cancellation-evidence.json)
- [`windows-2.1.241.audit-canary-with-evidence.json`](../transport-poc/var/real-capture/windows-2.1.241.audit-canary-with-evidence.json)
- [`official-windows-subscription-e2e.normalized.json`](../transport-poc/var/real-capture/official-windows-subscription-e2e.normalized.json)
- [`subscription-e2e-windows-2.1.241.report.json`](../transport-poc/var/real-capture/subscription-e2e-windows-2.1.241.report.json)
- [`subscription-response-headers-windows-2.1.241.report.json`](../transport-poc/var/real-capture/subscription-response-headers-windows-2.1.241.report.json)
- [`Windows fresh 稳定性矩阵 PASS`](../transport-poc/var/real-capture/windows-2.1.241-fresh-v1/fresh-stability-current-v4.report.json)
- [`Windows 当前 Bundle v2`](../transport-poc/var/real-capture/windows-2.1.241-fresh-v1/windows-2.1.241.current.bundle.json)
- [`Windows 当前 Canary TLS 证据`](../transport-poc/var/real-capture/windows-2.1.241-fresh-v1/windows-2.1.241.current.tls-canary-evidence.json)
- [`Windows 当前联合证据 Canary 审计`](../transport-poc/var/real-capture/windows-2.1.241-fresh-v1/windows-2.1.241.current.audit-canary.json)
- [`陈旧 Bundle 被矩阵拒绝的报告`](../transport-poc/var/real-capture/windows-2.1.241-fresh-v1/fresh-stability-stale-v1.report.json)
- [`Windows Transport Matrix 17/17 PASS`](../transport-poc/var/real-capture/windows-2.1.241-fresh-v1/windows-2.1.241.current.transport-matrix-v2.json)
- [`真实 Claude Code 受控稳定性 20/20 PASS`](../transport-poc/var/real-capture/windows-2.1.241-fresh-v1/controlled-stability-after-close-fix-v1.report.json)

最终 Transport Matrix 的 `report_sha256` 为 `de19e3548734459d81ca4053b542ba13cb575b69208364a9049df4dc60705503`，绑定的最终 Engine SHA-256 为 `85c14dcdfbe2c7e597dcfc0176d5fb755aafb09712ad94d295c32665b290f2a9`；两者已回读复算一致。真实 Claude 受控稳定性报告 SHA-256 为 `24a2c2b9030dbea8751fbf92e4f76317940d99a638cd0f829d3f0233d150ba88`，同样已回读复算一致。

### 2.4 Egress 代理隧道

`transport-core` 已实现统一的 TLS 前置建链接口：

- direct 或 dial override；
- HTTP CONNECT 无认证和 Basic 认证；
- SOCKS5 local DNS 和 remote DNS；
- SOCKS5 username/password 协商；
- 建隧道超时、协议错误、代理拒绝和认证拒绝分类。

自动测试已验证 CONNECT Basic Header 仅在代理握手中出现，目标端只收到隧道内容；HTTP 407 归因为 `proxy_authentication`；SOCKS5 两种 DNS 模式都能透明传输字节。TLS 仍由 BoringSSL 在隧道内与目标握手，代理没有证书绕过开关。

实际 Transport Matrix 进一步在 direct、CONNECT、CONNECT Basic、SOCKS5 local DNS 和 SOCKS5 remote DNS 五条路径捕获内层 ClientHello，全部与 direct 基线一致；Basic 认证只被代理观察到，origin 未见。CONNECT 后出现错误 TLS endpoint 时，`transport-core` 在代理隧道已建立的上下文中将握手/验证失败归为 `unhealthy_tls_passthrough`，且合成 Credential 请求未到达 origin；HTTP 407 保持 `proxy_authentication`，不污染 Credential 上游认证状态。

### 2.5 SSE、取消和连接池

- SSE relay 不解析 event，不重新序列化，不追加平台错误事件；测试按字节比较原始输入与输出。
- 默认 deadline 模型记录为非流式 300 s、流式 idle 30 s，调用者可配置。
- 取消决策按 `BeforeConnection|Uploading|EndStreamSubmitted|ResponseCommitted` 和 H1/H2 区分。
- 真实内存 H2 双 Stream 测试中，Stream A 收到 `RST_STREAM(CANCEL)` 后 Stream B 仍完整收到响应，连接没有被整体取消。
- Pool Key 精确包含 Credential ID、Profile epoch、Bundle version、Egress binding/epoch、authority 和 protocol；不含 Base Session/Agent ID，因此同 Credential 多会话可复用，任一隔离字段变化都不可取出原连接。
- Transport Matrix 在一条实际 BoringSSL/TLS/H1 连接上连续完成 20 个请求，并在 250 ms idle 后继续复用同一连接；Credential、Profile epoch、Bundle、Egress 或 Egress epoch 任一变化均无法命中原池项。
- C01–C05 以实际 socket 证明连接前零字节、上传中中止、完整提交后取消、响应已 commit 后保留已发送字节，以及残余响应连接逐出；C05 的后续请求通过第二条连接完成，旧响应字节没有流入新请求。C06 保留真实 H2 状态机的双 Stream 隔离结论。
- 当前 POC 默认关闭 TLS Session Resumption，未分配 Session Ticket Store，因而不会跨 Pool Key 恢复；功能开关保留，但启用前必须实现完整 Pool Key 分域 Ticket Store 并通过 resumed reference/replay 门禁。

### 2.6 Mocked 负载试验

[`runtime-load-current.json`](../transport-poc/var/e2e-v2/runtime-load-current.json) 记录：

| 指标 | 结果 |
|---|---:|
| SSE 连接请求/完成 | 1,200 / 1,200 |
| 同时活跃峰值 | 1,200 |
| 短请求完成 | 2,500 |
| 内存 mocked RPS | 206,109.1 |
| 未回收 task | 0 |
| RSS before/after | Windows 运行未采集，两项为 `null` |

该 RPS 只验证内存 relay 的功能余量，不包含 TLS、Anthropic、代理、带宽或数据库，不作为生产 SLO。“无持续内存增长”尚需 Linux RSS/heap 多轮试验。

## 3. 验收矩阵

| 计划门槛 | 状态 | 证据或缺口 |
|---|---|---|
| Windows/macOS/Linux verified Manifest | `PARTIAL PASS` | Windows 2.1.241 双路 verified Manifest 已生成；macOS/Linux 双路仍缺 |
| 三个 Archetype Bundle candidate | `PARTIAL PASS` | Windows H1 Bundle candidate 已生成并验证；macOS/Linux 证据仍缺 |
| 每场景 20 fresh + 20 pooled | `PARTIAL PASS` | Windows T01 fresh 已完成 20/20 reference 稳定与 20/20 TLS/H1 Replay；网关 Replay T02 已在同一实际连接完成 20/20。单进程真实 Claude Code pooled reference 和 macOS/Linux 仍待后续环境矩阵 |
| ClientHello 硬字段 `NORMALIZED_EXACT` | `PARTIAL PASS` | Windows 2.1.241 当前 cohort 的 20 次 fresh 全部精确一致；旧 Bundle 的 20 次硬失配被正确拒绝；direct/CONNECT/SOCKS5 的 Replay 内层 ClientHello 已一致。启用态 resumed reference 仍待后续矩阵 |
| H2 SETTINGS 值与顺序 | `PARTIAL PASS` | 受控 Rust Replay 端点上实测精确；Windows 2.1.241 当前 official 与 controlled lane 均为 HTTP/1.1，H2 结论只适用于独立 H2 候选 |
| ACK/帧序/pseudo-header/HPACK | `BLOCKED` | 已捕获 Replay 帧序；参考是不完整合成数据，HPACK 原始字节未进 Bundle |
| Header 顺序/动态值/零秘密落盘 | `PARTIAL PASS` | Windows 真实 reference 对 H1 Replay 的 21 个 Header 顺序完全一致并通过 Diff；macOS/Linux 仍待采集 |
| 同 Credential 多 Session/Agent | `PARTIAL PASS` | 完整 Pool Key、20 次实际 H1 同连接请求与 H2 双 Stream 已验证；10 并发真实客户端 reference diff 仍属增强矩阵 |
| 跨 Credential/Profile/Egress 零复用 | `PASS` | 实际池命中矩阵验证 exact key 可复用，Credential/Profile epoch/Bundle/Egress/epoch 任一变化均拒绝；当前 resumption 默认关闭且不分配 Ticket Store |
| direct/CONNECT/SOCKS5 内层一致 | `PASS` | 五条实际 BoringSSL 隧道路径的内层 ClientHello 与 direct 相同，CONNECT Basic 不泄漏到 origin，SOCKS5 ATYP 区分 local/remote DNS |
| TLS 终止代理识别 | `PASS` | P06 结构化证据归因为 `unhealthy_tls_passthrough`，无 Credential 请求到达 origin；P07 独立归为 `proxy_authentication` |
| SSE 字节透明/取消不追加 | `PASS` | 字节精确和取消测试通过 |
| H2 取消不影响其他 Stream | `PASS` | 双 Stream 实际 h2 状态机测试通过 |
| H1 残余响应禁止回池 | `PASS` | C05 实际 socket 证明部分响应连接被逐出，后续请求在第二条连接完成且没有读取旧残余字节 |

## 4. 工程与供应链结果

### 4.1 构建与平台

- Windows Rust 1.94.0：全 workspace 测试和严格 Clippy 可通过。
- Windows BoringSSL feature：在 `C:\codex-targets\super-gateway-transport` 中完成 native 编译、链接、单测和真实探针。
- `x86_64-unknown-linux-gnu` 与 `aarch64-unknown-linux-gnu` Rust target 均已安装；早期不含强制 BoringSSL 矩阵工具的默认 crate 集合通过 `cargo check --locked`。
- 当前全 workspace 的 `x86_64-unknown-linux-gnu` 交叉检查已实际运行并进入 `boring-sys 5.2.0`，随后因 Windows 主机没有 `x86_64-linux-gnu-gcc/g++` 与对应 CMake toolchain 失败；这条结果按失败记录，不沿用早期 Rust-only PASS。
- Linux BoringSSL C/ASM 原生构建、Linux x86_64 运行和 arm64 目标机 smoke test：本机没有 Linux runner/WSL distro/Docker，仍为发布 blocker。

### 4.2 `unsafe`/FFI

- 所有 workspace Rust crate 均使用 `#![forbid(unsafe_code)]`；工作区源码扫描没有 `unsafe` block。
- FFI 仅由外部 `boring`/`boring-sys`/`tokio-boring` 依赖提供，当前版本固定为 5.2.0。
- ASan/UBSan、Miri 可覆盖部分、FFI fuzz 和边界输入测试尚未在 Linux CI 运行，仍为工程 blocker。

### 4.3 许可证与安全公告

- workspace 直接/解析依赖主要为 MIT、Apache-2.0、BSD-3-Clause、Unicode-3.0、Unlicense 以及带 LLVM exception 的 Apache-2.0；未观察到 GPL-only 解析包。
- Boring 相关：`boring 5.2.0` Apache-2.0，`boring-sys 5.2.0` MIT，`tokio-boring 5.2.0` MIT OR Apache-2.0，`bindgen 0.72.1` BSD-3-Clause。
- 本机未安装 `cargo-audit`/`cargo-deny`，因此 RustSec 快照扫描、禁止许可证策略和重复版本策略尚未形成可重复 CI 制品。

### 4.4 秘密扫描

- 规范化 capture、Bundle、diff、probe 和 load 报告未发现 Anthropic token、refresh token、代理密码、真实 Session/Device ID 或业务正文；Windows 真实受控采集使用随机合成认证，Authorization/Session 仅保留类型和长度。
- `var/e2e*/**/*.raw.json` 含明确标识为 `SYNTHETIC_SECRET` 的合成负向测试值；它们不是真实 Credential，不得被当作 verified reference。
- 本轮为真实订阅验收执行了三次成功的 Claude Opus 4.6 最小 Messages 调用：直连 CLI 基线为 3,328 input / 4 output token，pass-through 验收为 3,334 input / 4 output token，响应 Header 语义验收为 3,335 input / 4 output token。响应探针的前三次调试均在 HTTP 请求提交前结束，模型 usage 为 0；此前失败的 pass-through 尝试同样没有 usage。真实 OAuth 只在进程内转发，正式证据未保存 token、Prompt 或 completion。

## 5. 已确认的技术事实

1. BoringSSL + Tokio 在 Rust 单体中可完成强证书校验的 h2 连接，无需外置 Transport Worker。
2. HTTP CONNECT/SOCKS5 可作为 TLS 前置透明隧道，不需要代理终止 TLS。
3. `h2::client::Builder` 可应用目前 Bundle 的 SETTINGS 值；本次观察顺序也与计划一致，但公开 API 仍不承诺任意顺序。
4. 当前 `h2` 会在首请求前发送 SETTINGS ACK；参考 fixture 必须记录这种真实行为，不能删除 Replay 帧来迁就样本。
5. 标准 `http::HeaderMap` + `h2` 只能证明解码后 Header 语义；任意 pseudo-header 顺序、HPACK 索引/Huffman 选择和压缩字节仍缺少可确定控制。
6. H2 目标 Stream 取消与其他 Stream 存活可通过现有 `h2` 状态机实现。
7. 真实 Claude Code 的连接协议必须按环境、capture cohort 和 lane 采集，不能先验设为 H2，也不能只按 Claude Code 版本或可执行文件哈希复用 Profile；Windows 2.1.241 当前 official 与 controlled lane 均使用 HTTP/1.1，历史同版本空 ALPN 样本作为独立漂移证据保留。
8. 官方 TLS 指纹采集只需要让真实客户端向官方 authority 发出 ClientHello；使用随机无效认证可在模型执行前结束，因此 TLS 参考采集与订阅账号登录解耦。
9. 真实订阅采集必须保持 Credential 原有 Egress。若本机已配置上级代理，本地 Tap 必须链式 CONNECT 而不是改为服务器 direct；否则出口变化可能先触发 `permission`，不能据此误判 OAuth token 或客户端协议。
10. TLS pass-through 用于 ClientHello、真实模型成功和 CLI 可见 SSE/usage；独立 TLS 解密转发探针已经补齐原始响应 Header 语义，但该探针改变客户端到本地端点及本地到 Anthropic 的 TLS/H1 实现，因此只形成语义证据，不形成 Transport Archetype 指纹证据。
11. 订阅响应已实证 `anthropic-ratelimit-unified-*` 不是传统 Console API Key 的 RPM/TPM Header 集合，而是包含 5h/7d status、reset、utilization、representative claim 和 overage 状态的订阅窗口语义。网关应按 Credential 消费这些字段，并继续向客户端暴露 Group 级限流视图。
12. Bundle/Replay 必须按证据判别 H1/H2；Windows 2.1.241 H1 可由低层有序 writer 保留请求行、Header 顺序/大小写和 Content-Length framing，ALPN 的空或 `http/1.1` 也必须按具体 cohort 重放。
13. BoringSSL 5.2 的默认后量子混合 Group/KeyShare 会显著改变 Claude Code 指纹；显式应用 reference 的 Cipher、Supported Groups、KeyShare、ALPN，并按 Extension 5/18 启用 OCSP stapling/SCT 后，Windows 2.1.241 当前 ClientHello 可由上游 bindings 连跑 20 次精确重放，本 fresh 样本不需要 fork 或手写 TLS。
14. 同版本、同 runtime、同 OS build、同可执行文件哈希仍可能出现稳定的 TLS cohort 漂移。Archetype 分配和升级必须依赖实际采集证据、Profile epoch 与显式 cohort 迁移，运行时不得静默把旧 Credential 切到新 Bundle。
15. Windows Replay 的实际 pooled、代理、取消和隔离矩阵可由上游 BoringSSL bindings、有序 H1 writer 与现有 H2 状态机完成；当前样本没有因这些场景产生必须 fork TLS 的证据。
16. TLS Session Resumption 默认关闭是当前 POC 的安全基线，不等于删除产品能力；未来启用必须把 Ticket Store 纳入完整 Pool Key，并以真实 resumed reference 与 replay 证明不会跨 Credential/Profile/Egress 复用。

## 6. 南向方案决策理由

当前选择 `Blocked`，不提前锁定 `Upstream libraries|Maintained fork|Dedicated thin transport`：

- 若真实 Claude Code 的 ClientHello/H2/HPACK 恰好在上游库稳定输出内，则 `Upstream libraries` 可能足够。
- 若仅缺 SETTINGS/帧/伪 Header 顺序暴露，则小型 `Maintained fork` 可能是最小补丁面。
- 若要求精确 HPACK 字节、帧分割和连接历史重放，则倾向 `Dedicated thin transport`。

在真实参考证据出现前，选择 fork 或 thin transport 只会把未知目标写成大量不可验证代码。

## 7. 解除 Blocked 的最小条件

1. 在 Linux x86_64/arm64 runner 运行生产二进制的 BoringSSL native 构建、测试、ASan/UBSan、RustSec/许可证门禁和多轮 RSS/heap 负载试验。
2. 在出现真实 H2 cohort 时执行 HPACK 原始编码、SETTINGS ACK 时序、pseudo-header 顺序和 resumed-path 门禁；H1 多阶段取消及 direct/CONNECT/SOCKS5 Replay 矩阵已完成。
3. 对每个新 capture cohort 自动运行 fresh 漂移门禁、Bundle 编译、协议配对 Diff、完整性证据和 Canary 审计，不以版本号代替 wire evidence。
4. 据实确定跨 Archetype 的上游库、最小 fork 或 thin transport；当前 Windows fresh、pooled、代理和取消结果均支持上游 BoringSSL + 有序 H1 路径，未来真实 H2/HPACK cohort 仍可能改变 H2 部分的最终选择。
5. macOS/Linux Archetype 双路采集在具备对应环境时恢复，不阻塞 Windows-only v1 的当前步骤。单进程真实 Claude Code 的 20 次 pooled 与 10 并发 reference 作为自动化增强诊断执行，不作为当前 Windows Canary blocker。

## 8. 下一步决策点

Windows 的 20 次 fresh 双路 reference、20 次同目标 TLS/H1 Replay、TLS/取消证据消费，以及网关 Replay 的 17 项 pooled/代理/取消/隔离矩阵均已完成，当前 Bundle 能力审计为 `ReadyForCanary`。本机后续只有不阻塞 Canary 的真实 Claude Code 单进程 pooled/并发增强诊断；需要新增环境的部分是 Linux x86_64/arm64 原生发布门禁与 macOS/Linux Archetype 双路采集。当前样本证明上游 BoringSSL bindings 足以精确重放该 Windows H1 cohort，同时也证明同版本会发生 cohort 漂移；是否最终锁定 H2 上游库仍由未来真实 H2/HPACK cohort 决定。
