# Claude Code Gateway Transport Engine 详细设计

> 状态：Detailed Design Baseline  
> 上位文档：[功能模块规划](./functional-modules.md)、[技术架构](./technical-architecture.md)、[请求管线](./request-pipeline.md)、[调度器设计](./scheduler-design.md)  
> 实证依据：[Transport POC](./transport-poc.md)、[Transport Spike 报告](./transport-spike-report.md)

## 1. 文档目的与权威顺序

本文冻结南向 Transport 的生产形态、Bundle 数据 ABI、TLS/H1/H2 执行、Egress、连接池、Attempt、取消、发布和证据门禁。Transport 负责“按已验证规格发出字节并返回原始响应”，不拥有业务调度、Credential 生命周期、重试选择或非流式 Reservation。

权威顺序：产品规划与协议合同 → 技术架构/领域不变量 → 真实 Spike 证据 → 本文实现细节。任何没有 wire evidence 的能力保持为代码能力或候选规格，不提升为 verified 指纹结论。

## 2. 总结、范围与证据边界

生产拓扑：单台 Linux 上一个 `super-gatewayd` Rust 进程、一个 `TransportCore`、多个进程内 `CompiledTransportEngine` 逻辑实例。Windows/macOS/Linux Capture Runner 只在研发/CI 离线采集，生产环境不部署三套 OS 或常驻跨 OS Worker。

已验证边界：

- Rust + BoringSSL + 有序 H1 writer 可以按 Bundle 显式重放当前 Windows Claude Code cohort；
- 默认 BoringSSL ClientHello 与参考存在硬差异，只有显式应用 cipher/group/keyshare/ALPN/OCSP/SCT 等才通过当前 paired diff；
- 当前 Windows `2.1.241` 的 paired Manifest 已 verified、Capability Audit 为 `ReadyForCanary`，但现有 POC Bundle artifact 仍为 `candidate`；生产签名 Bundle 需由正式 Engine build 重新生成后才能进入 `verified/canary`，更不是 Active/GA；
- 当前参考协议为 HTTP/1.1；独立 H2 probe 只证明执行能力，不等于真实 Claude H2 cohort 指纹；
- macOS/Linux 真实配对、Linux 原生生产构建/安全/负载门禁、H2/HPACK、TLS resumption 证据仍在后续验证队列；
- 现有 Bundle 覆盖用户态 TLS/HTTP/Header/连接行为，不声称模拟 Windows/macOS 内核 TCP 栈。

## 3. 术语与四层信号

| 层 | 示例 | 来源 |
|---|---|---|
| Environment metadata | OS/build、arch、runtime、Claude Code version | Archetype/Capture Manifest |
| Application identity | UA、X-App、Stainless、Metadata、Session、Attribution | Profile + Bundle templates |
| Wire cohort | ClientHello、ALPN、H1 header order/casing、H2 SETTINGS/frames/HPACK | Bundle + Engine |
| OS/TCP behavior | TCP options、拥塞控制、kernel timing | 当前无生产拟态合同 |

“Node/Bun 指纹”需要拆开表达。Header 中 `X-Stainless-Runtime: node` 是应用身份模板；Rust 进程本身仍运行 Rust/BoringSSL。当前没有 Bun wire cohort 证据，因此 Bundle Catalog 不把 Bun 标为 verified。

核心术语：

- `TransportCore`：进程内唯一 Transport 生命周期服务；
- `CompiledTransportEngine`：按 Bundle/hash/backend/ABI/protocol 编译的不可变逻辑实例；
- `TransportTask`：每个 Connection/Messages Attempt 的异步任务；
- `ConnectionPoolShard`：按完整 PoolKey 分片；
- `Transport Bundle`：签名、无 secret 的数据/执行规格，不是多 OS 二进制或原生插件。

## 4. 生产与采集拓扑

```text
Production Linux host
└─ super-gatewayd
   ├─ Edge / RequestTask
   ├─ GroupExecutor
   └─ TransportCore
      ├─ BundleLoader + TrustStore
      ├─ EngineCatalog<EngineKey, Arc<CompiledEngine>>
      ├─ PoolCatalog<PoolKey, PoolShard>
      ├─ EgressDialer
      └─ TransportTask per attempt

Offline evidence environments
├─ Windows Capture Runner
├─ macOS Capture Runner
└─ Linux Capture Runner
   → normalized evidence + signed Bundle
   → reviewed artifact repository
   → production Bundle loader
```

Capture Runner 是工具链，不是 Transport Engine 的运行依赖。生产只需要经过签名、ABI 与证据门禁的 Bundle。

## 5. 进程内组件与所有权

| 组件 | 职责 |
|---|---|
| Bundle Store/Loader | 读取、验签、hash/ABI/证据/隐私检查 |
| Engine Compiler/Catalog | 确定性编译并原子发布 CompiledEngine |
| Pool Catalog | 严格 PoolKey 隔离、drain、逐出 |
| Egress Dialer | direct、CONNECT、SOCKS5 |
| TLS Connector | BoringSSL 配置、SNI、证书校验、ALPN |
| H1 Engine | 有序 request writer、framing、连接复用 |
| H2 Engine | SETTINGS、stream、flow control、RST/GOAWAY |
| Observer | 单调 TransportEvent、wire metrics、错误归因 |
| Health Projector | 向 Credential/Proxy/Bundle runtime 投影 blocker |

GroupExecutor 仍是 Lease、Credential 可调度状态和 retry decision 的唯一 owner。Transport 只返回分类事实与连接处置建议。

## 6. Transport Port

```rust
trait TransportPort {
    async fn execute(
        &self,
        request: Arc<FinalUpstreamRequest>,
        identity: AttemptIdentitySnapshot,
        deadlines: AttemptDeadlines,
        cancellation: CancellationToken,
        sink: TransportEventSink,
    ) -> Result<RawUpstreamResponse, TransportError>;
}
```

输入冻结 Credential/attempt、token/profile/device/egress epoch、Bundle、authority、Body replay handle、deadline。输出包括单调事件、原始 response stream、连接处置、错误 domain、retry safety 和 health effect。Transport 不直接向客户端写数据，也不决定换 Credential。

## 7. 核心数据结构

```rust
struct TransportCore {
    engines: ArcSwap<EngineCatalog>,
    pools: PoolCatalog,
    egress: EgressDialer,
    trust_store: BundleTrustStore,
    health: TransportHealthSink,
    observer: Arc<dyn TransportObserver>,
}

struct EngineKey {
    bundle_id: BundleId,
    bundle_version: ArtifactVersion,
    bundle_hash: ContentHash,
    engine_abi: EngineAbiVersion,
    backend_id: BackendId,
    protocol: HttpProtocol,
}

struct CompiledTransportEngine {
    key: EngineKey,
    source: ArchetypeKey,
    tls: CompiledTlsProfile,
    application: CompiledApplicationProfile,
    headers: CompiledHeaderProfile,
    connection: CompiledConnectionPolicy,
    evidence: EvidenceBinding,
}
```

`CompiledApplicationProfile` 是 `Http1|Http2` 判别联合，协议特定字段不得混放。

## 8. Archetype、Cohort 与 Bundle

Archetype Key 至少包含：OS family/version/build、arch、runtime family/version、Claude Code/SDK version、capture cohort。一个 Archetype 版本可以被多个 Credential Profile 引用。

同版本、同 binary hash 若在重复真实采集中出现两个稳定 wire 集群，创建不同 cohort；不得用新字段覆盖旧 Bundle。Profile cohort migration 是显式、审计、分批操作。

Bundle 绑定一个具体 evidence set、source cohort、protocol 与 engine compatibility 范围。不同 OS 的 PASS 互不继承；Windows evidence 只解锁对应 Windows cohort 的下一状态。

## 9. Bundle 数据 ABI

生产 Bundle 最少字段：

```text
schema_version
engine_abi_version
bundle_id / artifact_version / canonical_hash
backend_id / required_capabilities
source_archetype / capture_cohort
application.protocol
tls profile
h1 or h2 profile
ordered application headers
connection/resumption policy
min_engine_build / max_engine_build
supported_rust_targets
evidence manifest/report hashes
created_at / signer_key_id / signature
```

首版 ABI 是版本化数据/语义 ABI，不加载任意 `.so`/动态执行插件。未知 schema、enum、control point 或 required capability 直接拒绝。Production Active Bundle 的 `min_engine_build` 必填，compatibility range 采用可比较的 release build ID。

## 10. Bundle 构建与规范化

```text
real client capture
→ passive TLS evidence + controlled application evidence
→ normalize dynamic fields
→ secret/privacy scan
→ paired manifest verification
→ protocol-discriminated Bundle compiler
→ canonical encoding + hash
→ ABI/capability audit
→ sign + provenance
→ shadow / canary / active
```

动态字段目录只能排除 request ID、trace、已识别 Session 和登记 nonce/timestamp；语义 Header、TLS 扩展、ALPN、H1/H2 framing 不以 allowlist 隐去硬差异。生产 Credential 不参与采集。

## 11. 签名、信任根与供应链

本设计冻结首版方案：

- Bundle payload 使用 RFC 8785 JCS canonical JSON；
- canonical bytes 计算 SHA-256；
- Ed25519 detached signature 覆盖 domain separator、schema/ABI、canonical hash、source evidence hash 和 engine compatibility range；
- production TrustStore 只含批准的 public key ID，private signing key离线/CI 受控保存；
- key rotation 允许旧 public key 在历史验证窗内只读，新的 active artifact 必须由当前 key签名；
- Bundle artifact、manifest、SBOM、build provenance 一起保存；
- release 二进制和 Bundle 使用不同 signing key domain，避免交叉签名。

Loader 验证 signature、hash、provenance、privacy scan、ABI、engine build、evidence references，任一失败进入 quarantined。签名算法后续变更通过 envelope version 演进。

## 12. 装载、编译缓存与原子发布

```text
read artifact
→ verify envelope/hash/signature/ABI/privacy/evidence
→ deterministic compile
→ self-test
→ Arc<CompiledTransportEngine>
→ atomic EngineCatalog pointer swap
```

编译缓存键是完整 EngineKey。运行中 Attempt 持有旧 `Arc` 并完成；新 Attempt 使用新 Catalog。编译失败不影响旧 active pointer。配置与 Bundle pointer 的一致快照在 Request 开始时冻结。

从 A→B→A 回滚时仍创建新的 activation generation，并 drain 第一次 A 的旧池，避免复用跨发布边界的残留连接。

## 13. 生命周期、Canary、隔离与回滚

```text
draft → verified → canary → active → retired
             \        \       \
              └──────────────→ quarantined (runtime state)
```

- `verified` 表示离线证据和构建门禁通过；
- `canary` 只给明确 cohort/credential cohort 使用；
- `active` 才进入新 Credential 自动分配；
- `retired` 停止新分配，存量按 cohort 计划迁移；
- `quarantined` 是正交运行态，立即阻止新 Attempt。

隔离后引用 Profile 获得 `transport_unavailable` blocker；在途 Attempt 使用冻结快照完成或按协议安全终止；旧池 drain。回滚只移动 active pointer到完整的前一 verified Bundle，不拼接局部字段。

## 14. TLS Profile 编译与执行

TLS Connector 使用 BoringSSL，并始终执行证书链、主机名、SNI 与系统/受控 CA 验证。Bundle 可配置已验证的：TLS version、TLS≤1.2 cipher、groups、key shares、扩展控制、ALPN、OCSP/SCT、padding/长度目标、session policy。

Rust/BoringSSL 只在显式控制这些参数后重放相应 cohort。控制 API 存在不代表 wire 已验证；ClientHello extension order、record framing、GREASE、resumption 等仍要以同目标 exact diff 门禁。

任何跳过证书校验、SNI 与 authority 不一致、proxy 替换证书或 ALPN 漂移都直接隔离路径。

## 15. ALPN 与 H1/H2 判别

Bundle 的 `application.protocol` 是判别字段：

- H1 Bundle 的 ALPN 必须协商 `http/1.1` 或符合其已验证的 no-ALPN 合同；
- H2 Bundle 必须协商 `h2`；
- 协商值与 Bundle 不一致返回 `alpn_mismatch`，连接不入池；
- fallback 不在同一连接内临时更换 H1/H2 profile；需要另一个已验证 Bundle和新 ConnectionAttempt。

当前 Windows cohort 明确为 H1。Rust H2 probe 证明 SETTINGS/stream/cancel 路径可实现，但真实 Claude H2 的 SETTINGS 顺序、frame ordering、pseudo-header ordering 和 HPACK raw encoding 仍是独立门禁。

## 16. HTTP/1.1 Engine

H1 使用低层有序 writer：

```text
request line
→ exact ordered/cased headers from Final Request + Bundle
→ CRLF
→ Content-Length framed replayable body
```

规则：

- authority/path 由固定 Anthropic endpoint 生成；
- Header order/casing、空格与 framing 由编译规格控制；
- body byte stream 来自请求管线，Transport 不重新序列化 JSON；
- response parser 保留 status、header value 与 raw body/content-encoding；
- 只有上传完整、响应边界完整、无取消/超时/解析歧义时连接才 `Reusable`；
- 任一残余字节或状态不确定都 `Evict`。

## 17. HTTP/2 Engine

H2 Engine 必须支持：

- SETTINGS 1–6 的有序发送与 ACK；
- connection/stream flow control；
- pseudo-header 顺序；
-普通 Header order 与 HPACK strategy；
- RST_STREAM、GOAWAY、graceful drain；
- 多 stream 取消隔离；
- pending/read backpressure 与上层 SSE pump联动。

在真实 H2 cohort 完成 paired capture/replay 前，H2 Bundle不得进入 active。代码路径可在实验/测试环境运行，生产 Profile 只能引用证据状态满足门槛的 protocol Bundle。

## 18. Egress Binding 与 Direct

固定出口的准确含义是：Credential 拥有唯一、稳定、带 epoch 的 Egress Binding，所有业务和认证维护都沿该 Binding；并不等于每个 Credential 独占公网 IP。

- `Direct`：服务器直连路径；观察到 IP 变化时记录漂移，但 dynamic/direct policy 可以继续；
- `ProxyStatic`：期望出口 identity/IP 固定，漂移时 Credential 退出调度；
- `ProxyDynamic`：固定 proxy 路径，允许其出口变化并审计；
- 一个 Proxy 可被默认最多 5 个 Credential Binding 引用；每个 Credential Binding 仍是独立对象；
- 已 active Binding 不按请求临时切换；重绑是显式 Command，增加 epoch。

Group `auto` 在无健康代理容量时创建 Direct Binding。`proxy_required` 则保持 pending/waiting。

## 19. CONNECT 与 SOCKS5 TLS Pass-through

支持：

- HTTP CONNECT 无认证/Basic；
- SOCKS5 无认证或 username/password；
- SOCKS5 local DNS 与 remote DNS 模式；
- 隧道建立后，由平台 BoringSSL 在内层与 Anthropic 完成 TLS。

Proxy 只传输 TCP 字节，不终止 TLS。这样 ClientHello、SNI、证书验证、ALPN 和内层 H1/H2 都由匹配 Bundle 的 TransportCore控制。若 Proxy 返回替换证书、改写 ALPN 或拦截 TLS，标记 `unhealthy_tls_passthrough`。

407/明确认证失败标记 `proxy_authentication`，首次即让 Proxy 进入 `unhealthy_auth`，其绑定 Credential 获得 transport blocker。Proxy 认证 Header只发给 Proxy，不进入 Anthropic request。

## 20. Proxy 容量、健康与重绑

Proxy 配置只限制活动 Credential Binding 数，默认 5；首版无 Proxy 级请求并发/RPM。

健康状态采用统一八态：`unknown|probing|healthy|unhealthy_dns|unhealthy_connect|unhealthy_auth|unhealthy_tunnel|unhealthy_tls_passthrough`。`disabled/archived` 属于 lifecycle，`degraded/unreachable` 由 circuit state 与 reason 表达。瞬时路径在 60 秒窗内连续三次失败打开 circuit；管理员更新认证后立即做全路径 probe，之后默认每 60 秒检测，连续两次完整成功自动恢复。

重绑：

1. 管理员选择新 direct/proxy target并确认影响；
2. 创建新 Binding version；
3. 原子增加 `egress_epoch` 与 `profile_epoch`；
4. 新请求只使用新 PoolKey；
5. 旧 Pool drain；
6. 旧 epoch 的认证/Transport callback 丢弃；
7. 写审计。

profile epoch 增加只用于强制完整池隔离，Device Identity 与 Session HMAC 保持。

## 21. Connection Pool 隔离

```rust
struct PoolKey {
    credential_id: CredentialId,
    profile_epoch: u64,
    bundle_id: BundleId,
    bundle_version: ArtifactVersion,
    egress_binding_id: EgressBindingId,
    egress_epoch: u64,
    authority: Authority,
    sni: ServerName,
    protocol: HttpProtocol,
}
```

任一字段变化都进入不同 PoolShard。TLS session/ticket cache、H2 connection、HPACK dynamic table、socket 与 protocol state 一律按同键隔离。Base Session/Agent 不入 PoolKey，因此同 Credential 不同会话可安全共享连接；Credential 即使共享 Archetype、Bundle或 Proxy，也不共享连接。

Pool entry 还携带 engine activation generation。Bundle A→B→A 或 egress/profile epoch变化时旧连接不回流到新 generation。

## 22. ConnectionAttempt 状态机

```text
Planned → PoolLookup
→ Resolving → TcpConnecting → ProxyTunneling?
→ TlsHandshaking → AlpnNegotiating → ProtocolReady
→ PromotedOnFirstByte
| FailedBeforeFirstByte
| CancelledBeforeFirstByte
```

健康池命中可直接从 PoolLookup 到 ProtocolReady。每 Request 最多 3 个 ConnectionAttempt。connect timeout 默认 5 秒、可按 Group 配置 1–30 秒，覆盖 DNS、TCP、proxy tunnel、TLS 与 ALPN。

纯建连失败不创建 Messages Attempt/usage。Transport 返回 failure domain；调度器据此决定同 Credential 全新连接或 Portable 请求换 Credential。

## 23. Messages Attempt 与事件顺序

TransportEvent 单调序列：

```text
connection_ready
→ first_upstream_request_byte
→ request_body_complete
→ response_headers
→ first_response_body_byte
→ response_complete
```

只有 `first_upstream_request_byte` promotion 创建 Messages Attempt。写前已有 submission intent；在首字节未知崩溃窗通过 `commit_unknown` 表示，不伪造 usage。

事件带 attempt ordinal、Credential、token/profile/egress/Bundle epoch、connection ID 与 monotonic timestamp。Transport sink拒绝倒序/重复 promotion。三次建连都失败时应是 3 ConnectionAttempt、0 Messages Attempt。

## 24. Deadline、Timeout 与 Cancel

- connect：默认 5 秒，范围 1–30 秒；
- non-stream upstream total：默认 300 秒，所有 attempt 共享；
- stream upstream idle：默认 30 秒，范围 5–600 秒；
- cancel grace：默认 2 秒；
- client delivery timeout 由 Response Pump 管理，不由 Transport重置。

每个 await 都检查 cancellation：pool acquire、DNS、TCP、proxy handshake、TLS、upload、header、body read、flow control。取消：

- 首字节前：终止连接任务，无 Messages Attempt；
- H1 上传/响应中：关闭并 Evict整连接；
- H2：RST_STREAM(CANCEL)，只有 connection-level 状态异常才关闭整连接；
- 2 秒内等待确认，超时强制关闭；之后通知 GroupExecutor释放 Lease；
- committed 响应保留已交付字节，Transport不触发 retry。

## 25. 污染判定与连接处置

```rust
enum ConnectionDisposition {
    Reusable,
    Evict,
    ResetStream,
    DrainConnection,
    CloseConnection,
}
```

H1：未完整上传、未完整消费响应、client cancel、timeout、framing歧义、unexpected bytes 均 Evict。H2：正常单 stream cancel只 ResetStream；GOAWAY 进入 DrainConnection；HPACK/SETTINGS/frame/TLS/IO connection error 关闭整连接。

处置在 TransportTask terminal 前确定并写事件。连接先从可借用集合移除，再异步 drain/close，避免另一请求借到待逐出的 socket。

## 26. 响应原字节与背压边界

“原字节”准确指 Anthropic Body/SSE 及 Content-Encoding 表现。Transport 向上层返回原始 status、headers 和 body stream；请求管线过滤 hop-by-hop、Cookie、连接实现与单 Credential 限流 Header。

- SSE 不拆分、合并、重排、解压重压或注入事件；
- 1 MiB pending window 满时 Response Pump 暂停 Transport read；
- 因背压暂停期间暂停 upstream idle timer；
- non-stream 完整原始 Body 写入内存/加密 spill，Transport 不解析重写；
- status/Header 尚未 client commit 时，上层可选择 retry；commit 后 Transport错误只终止交付。

因此 Body/SSE 透明与 Header 隐私过滤是一致的两个合同。

## 27. 失败分类、健康、观测与安全

错误 code 分层：

```text
resolver_*
direct_tcp_*
proxy_authentication | proxy_rejected | proxy_protocol | proxy_timeout
tls_certificate | tls_handshake | unhealthy_tls_passthrough
alpn_mismatch | protocol_mismatch
bundle_invalid_signature | bundle_hash_mismatch | bundle_abi_incompatible
bundle_quarantined | bundle_wire_conflict
h1_framing | h1_residual_response
h2_settings | h2_frame | h2_hpack | h2_goaway | h2_stream_reset
connect_timeout | upstream_total_timeout | stream_idle_timeout
cancel_grace_expired | cancelled_<phase>
```

每个错误附 `attribution_domain`、`retry_safety`、`health_effect`、`connection_disposition`。Transport 只给事实，不自行选择跨 Credential。

指标：连接池 hit/miss/wait、DNS/TCP/proxy/TLS/ALPN latency、protocol、Bundle/engine generation、bytes、first-byte、cancel、reuse/evict、H2 stream/GOAWAY、SSE backpressure。具体 Credential/connection/request ID只进入结构化日志/trace。

安全：authority/SNI 固定 allowlist；强证书校验；Proxy secret、token只在内存；wire capture 默认关闭且生产采样需审批/脱敏；Bundle fail-closed；内存与 dump 策略由安全设计冻结。

## 28. 测试、发布门禁、Reader Check 与开放项

### 28.1 必测矩阵

1. Bundle canonicalization、Ed25519、hash、ABI、privacy、unknown字段与 fuzz。
2. TLS ClientHello 同目标 exact diff、证书/SNI、ALPN 空/H1/H2。
3. H1 request line、Header order/casing、framing、20 次 idle reuse、残余隔离。
4. H2 SETTINGS/ACK/frame/pseudo-header/HPACK、GOAWAY、双 stream cancel；真实 cohort 前不激活。
5. PoolKey 每字段 mutation，TLS ticket/H2/HPACK 跨键零复用。
6. direct、CONNECT、Basic、SOCKS5 local/remote DNS；Proxy auth不泄漏 origin。
7. connect/total/idle/cancel grace 虚拟时钟与竞态。
8. 三次纯建连失败=3 ConnectionAttempt、0 Messages Attempt。
9. SSE byte exact、1 MiB背压；non-stream 8/64 MiB边界。
10. Bundle activate/quarantine/rollback、在途 Snapshot、旧 Pool drain。
11. Linux x86_64/arm64 native BoringSSL、sanitizer、RustSec/license/SBOM、RSS/heap/24h soak。
12. 每个 Active Archetype 独立双路 capture/replay/matrix，PASS 不跨 OS 继承。

### 28.2 当前门禁

- Windows 2.1.241 H1 Bundle：可继续 Windows-only Canary；
- Linux production build、安全、负载：实施 TransportCore 前必须完成；
- macOS/Linux真实 evidence：只阻断对应 Archetype 的 canary/active，不阻断核心编码与 Windows Canary；
- H2/HPACK 与 resumption：只阻断相应 Bundle capability；首版 Windows H1 可保持 resumption关闭；
- Production Active：要求 Bundle min engine build、签名/trust store、全门禁和回滚演练。

### 28.3 Reader Check

- 生产只有 Linux，为什么能加载 Windows Archetype？见第 4、8、10 章。
- 多个 Transport Engine 是否代表多个进程？见第 3、4、7 章。
- Rust 是否天然拥有 Node/Bun 指纹？见第 2、3、14 章。
- Bundle 是数据还是插件？见第 9、11 章。
- 当前 Windows 证据覆盖 H1还是H2？见第 2、15 章。
- 固定 Egress 是独占 IP吗？见第 18 章。
- 为什么 Proxy 必须 TLS pass-through？见第 19 章。
- 一个 Proxy 可绑定多少 Credential？见第 20 章。
- 为什么 Session 不进入 PoolKey？见第 21 章。
- 三次建连失败为何没有 Messages Attempt？见第 22、23 章。
- H1/H2 取消为何处置不同？见第 24、25 章。
- 响应透明是否包括未过滤 Header？见第 26 章。
- Windows ReadyForCanary 与 Active 有何区别？见第 13、28.2 节。
