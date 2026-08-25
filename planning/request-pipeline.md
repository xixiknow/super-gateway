# Claude Code Gateway 请求管线详细设计

> 状态：Detailed Design Baseline  
> 上位文档：[功能模块规划](./functional-modules.md)、[技术架构](./technical-architecture.md)、[领域模型](./domain-model.md)、[API 契约](./api-contract.md)、[调度器设计](./scheduler-design.md)  
> 核心原则：请求可显式解析、校验和调整；真正来自 Anthropic 的响应 Body 与 SSE 保持原始字节

## 1. 文档目的

本文把 `/v1/messages` 从接入到响应结束拆为可实现、可审计、可重放测试的阶段，冻结每阶段输入、输出、所有权和失败语义。它重点解决四类边界：

- 哪些是客户端原始语义，哪些是平台通用调整，哪些只能由 Credential Profile 注入；
- Group Enforcement、RuleSet、Capability 和 Profile 的固定优先级；
- retry 或跨 Credential 时哪些内容保持不变、哪些必须重新构造；
- 平台自身错误与 Anthropic 原始响应如何在 commit 前后分流。

## 2. 范围与非目标

覆盖：`POST /v1/messages` 的认证后数据路径、Messages 测活分类、System 策略、Capability、审计门闩、调度交接、Profile 应用、传输提交、非流式和 SSE 响应。

边界：

- `/v1/models`、health/ready 只复用认证、请求 ID、Header 安全等基础设施，不进入完整 Messages 调整管线；
- Count Tokens 仅是内部 token estimate projection，不是北向路径；
- 模型 ID保持客户端请求值，不自动改写或切换；
- 响应不做 JSON 字段重写、SSE 事件注入、usage 修正或协议转换；
- WebSocket 不属于首版南北向合同；
- 账号级资源的完整 Provider 语义目录持续通过 Capability 版本扩展，未知高风险扩展先按 pinned 处理。

## 3. 端到端对象模型

```text
InboundEnvelope
→ AuthenticatedEnvelope
→ ParsedRequest
→ ClassifiedRequest
→ GovernedRequest
→ GenericAdjustedRequest
→ ScheduleEntry
→ CredentialLease
→ AttemptPlan
→ FinalUpstreamRequest
→ UpstreamResponse
→ ClientDelivery
```

| 对象 | 关键内容 | 生命周期 |
|---|---|---|
| `InboundEnvelope` | Method、path、raw headers、raw body handle、peer info | 认证和限长前 |
| `AuthenticatedEnvelope` | RequestId、Key/User/Group、权限、Key snapshot | 请求全程 |
| `ParsedRequest` | lossless JSON tree、字段 presence、known projections | 通用调整前 |
| `ClassifiedRequest` | client/traffic/session/agent 结果与证据版本 | 请求全程冻结 |
| `GovernedRequest` | Group Enforcement 结果、audit policy、probe action | 请求全程冻结 |
| `GenericAdjustedRequest` | Credential 无关的稳定业务请求 | 所有 attempt 共用 |
| `CredentialLease` | token/profile/archetype/bundle/egress epoch | 单个候选/attempt |
| `FinalUpstreamRequest` | 可发送 Header、Body、连接描述 | 单个 attempt |
| `UpstreamResponse` | 原始 status/header/body byte stream | 透明交付 |

## 4. 所有权与单写者

- Edge request task 单写 `RequestState` 与客户端连接；
- `PolicyEngine` 是纯函数式编译/执行组件，不持有请求运行态；
- `GroupExecutor` 单写 Queue、CredentialRuntime 和 Lease；
- `ProfileFactory` 只消费冻结输入，返回 Final Request，不修改 Credential；
- `Transport Engine` 单写具体 upstream connection/stream；
- Audit Writer 对每个 request/attempt 使用幂等键和 append-only 事实；
- Response Pump 单写向客户端的 Header/Body；commit 后其它组件只能发终止信号。

任何跨组件回调都携带 `request_id`、`attempt_ordinal`、`executor_generation` 和必要 epoch，迟到结果不覆盖新状态。

## 5. 阶段总表

| 阶段 | 输入 | 输出 | 失败时资源 |
|---|---|---|---|
| Route/Auth | HTTP envelope | AuthenticatedEnvelope | 零业务资源 |
| Frame/Limit/Parse | raw body | ParsedRequest | 零业务资源 |
| Classify | headers + parsed projection | ClassifiedRequest | 零业务资源 |
| Snapshot Resolve | Key/Group/model/client | RequestSnapshotSet | 零业务资源 |
| Probe Gate | traffic class + Group policy | continue/throttle/reject | 零业务资源 |
| Capability Precheck | parsed + capability | validated semantic tree | 零业务资源 |
| Enforcement | validated tree | GovernedRequest | 零业务资源 |
| RuleSet | governed tree | adjusted tree + diff | 零业务资源 |
| Final Generic Validate | adjusted tree | GenericAdjustedRequest | 零业务资源 |
| Audit Original Latch | original + generic digests | durable audit fact | 零 Anthropic 调用 |
| Key/Group/Schedule | generic request | CredentialLease | 见调度器账本 |
| Profile Apply | generic + lease | FinalUpstreamRequest | 释放 Lease/permit |
| Attempt Audit Latch | final safe view | durable intent | 尚无上游字节 |
| Transport Submit | final request | upstream response | attempt/retry 合同 |
| Deliver | raw response | terminal | commit 后零 retry |

## 6. Route、认证与请求 ID

固定路由和认证合同见 [API 契约第 7、8 章](./api-contract.md#7-数据面-platform-key-认证)。管线在读取完整 Body 前完成：

1. 生成平台 `req_...`；
2. 解析 `x-api-key` 或 Bearer；
3. 加载 Key、User、Group 指针；
4. 校验 Key 状态、endpoint permission、IP allowlist；
5. 从工作 Header 集删除所有北向认证值。

同一平台 Request ID贯穿响应 Header、平台错误 Body、日志、trace、RequestRecord。Anthropic request-id 另存为 `upstream_request_id`，不覆盖平台 ID。

## 7. HTTP Framing、Body 限制与 JSON 解析

- 仅接受 `application/json` 及明确兼容参数；
- 同时出现冲突的 `Content-Length`/`Transfer-Encoding`、重复敏感 Header 或非法 framing 时按 400 结束并关闭/重置连接；
- Body 实际上限为 `min(platform_hard_limit, key_body_limit)`；
- 流式读取时同步计数，超限立即停止并返回 413，错误中不回显配置数值；
- JSON parser 保留对象字段 presence：缺失、显式 `null`、具体值严格区分；
- 重复 JSON key 默认拒绝，避免不同解析器产生歧义；
- 原始 Body 可保存为受控 handle/digest；未发生任何调整时优先用于字节复用。

## 8. Lossless ParsedRequest

```rust
struct ParsedRequest {
    raw_digest: Digest,
    raw_body: BodyHandle,
    tree: LosslessJson,
    known: KnownMessagesProjection,
    unknown_top_level: Vec<JsonPointer>,
    unknown_content_blocks: Vec<JsonPointer>,
    presence_map: FieldPresenceMap,
}
```

`KnownMessagesProjection` 至少提取 model、max_tokens、messages、system、stream、tools、tool_choice、thinking、temperature、top_p、top_k、stop_sequences、metadata、output_config、context_management。提取只用于校验与策略，compatible 模式不会丢弃未知字段。

## 9. Client Classification

客户端只分两类：

```text
claude_code_cli
non_claude_code_cli
```

分类使用版本化组合证据：UA、Claude Code Session/Agent Header、X-App/Stainless、Anthropic Version/Beta、`metadata.user_id` 结构与已识别 System Attribution。至少两项相互支持的结构信号才进入 `claude_code_cli`；证据不足落入 `non_claude_code_cli`。客户端自报类型不具有单独决定权。

原始 UA、客户端 Header 与来源网络只供平台内部观察。南向 Header/Metadata/System 由 Credential Profile 重建，不直接复制这些值。Group 的 `accepted_client_classes` 在分类后校验。

## 10. Session 与 Agent 归一化

分类器输出 canonical Base Session 和 Agent：

- 可信、格式合法的 Claude Code Session Header 优先；
- 关联 Header/Metadata 不一致时降级为 anonymous，并记录冲突；
- 缺失时，anonymous Base Session 的稳定键固定为 `(PlatformKeyId, ClientClass)`；来源 IP、连接、Request ID、Prompt 与随机值均不参与会话键；
- 该 anonymous 映射在默认 30 分钟活动窗内复用，身份/affinity 历史保留 24 小时，避免短测活持续创建临时会话；
- Agent 缺失时使用 `main`；已识别 subagent 得到独立 Agent ID；
- canonical 原值不直接发往 Anthropic，上游 Session 在 Profile 阶段按 Credential HMAC 派生。

## 11. Traffic Classification

输出：

```rust
enum TrafficClass {
    Normal,
    ExplicitProbe { template_id: ProbeTemplateId },
    SuspectedProbe { score: u8, signals: BitSet },
    InternalUpstreamProbe,
}
```

确定性 `ExplicitProbe` 只来自：专用端点、已授权显式标记，或与当前 `(Group, Key, client class, endpoint)` 绑定且已发布的请求模板。模板规范化只允许忽略安全目录中的 request ID、trace、已识别 Session 以及 Profile 登记的 timestamp/nonce。

model、messages 角色与正文、System、tools、thinking、生成参数、stream、beta 和 context management 必须参与匹配。模板需通过唯一性样本校验。短文本、`ping/hi`、低 max_tokens、周期性和新 Session 比例只能增加 `SuspectedProbe` 分数。

## 12. Probe Gate

Group 对 `ExplicitProbe` 配置 `observe|throttle|reject`：

- `observe`：进入普通 Messages 路径，只增加分类遥测；
- `throttle`：先过 `(Platform Key, template)` 默认 2 RPM/burst 2，再过 Group 聚合默认 30 RPM/burst 10；之后仍需普通 Messages RPM/并发；
- `reject`：立即返回 403 Anthropic 风格 `permission_error`，通用消息为 `This request is not permitted.`；
- `SuspectedProbe` 永远按普通业务请求继续，只记录和告警；
- 平台不生成合成 Messages 成功响应，也不周期性用生产 Credential 创建临时会话；
- 429 cooldown 的 half-open 使用一条原本就要执行的真实 Portable 请求。

Probe throttle 超限返回 429，`retry-after` 取两桶恢复等待的较大值并向上取整，至少 1 秒。响应不暴露模板、Group 或分类原因。

## 13. Snapshot Resolve

```rust
struct RequestSnapshotSet {
    group_config_version: ConfigVersion,
    enforcement_version: ArtifactVersion,
    ruleset_version: Option<ArtifactVersion>,
    capability_version: ArtifactVersion,
    background_catalog_version: ArtifactVersion,
    client_profile_catalog_version: ArtifactVersion,
    price_version: ArtifactVersion,
    serializer_version: SerializerVersion,
}
```

Snapshot 在首次业务调整前一次性解析并冻结。Shadow 版本可并行计算 diff，主路径结果保持原值。Canary 选择在请求开始时决定，retry 不切换版本。若 active pointer 热更新，队列中的旧请求继续使用旧 Snapshot，新请求使用新版本。

## 14. Capability Precheck

Capability 是数据驱动规则集合，描述字段路径、类型、枚举、条件、互斥、依赖和可选 transform。执行顺序：

1. 基础 Messages 结构校验；
2. 精确 model 可用性与 Key/Group scope；
3. 当前模型 Capability 展开；
4. 已知字段类型/范围/组合校验；
5. compatible 模式下登记未知扩展；
6. 生成稳定排序的 diagnostics，只向客户端返回第一个安全诊断。

模型 A 支持 `thinking.type`、模型 B 不需要或采用不同约束时，只更新 Capability version。模型值保持原值。路径展开超过上限时返回 400并记录内部 `CAPABILITY_PATH_EXPANSION_LIMIT`；运行期编译冲突返回 500并阻止该版本继续扩大。

## 15. Group Enforcement

Enforcement 是 Group 级不可下调约束，优先级高于 Key、Client Profile、普通 RuleSet 与 Credential Profile。当前冻结内容：

- accepted client class；
- Messages probe action；
- System policy；
- Content Audit effective policy；
- 严格失败行为和 Profile Attribution 兼容性。

```rust
enum SystemPolicy {
    Preserve,
    StripClient,
    Replace { platform_system_ref: ArtifactId },
    StripAll,
}
```

含义：

| 模式 | 客户端 System | 平台固定 System | Credential Attribution |
|---|---|---|---|
| preserve | 保留 | 无 | 按 Profile 规则允许 |
| strip_client | 删除 | 无 | 按 Profile 规则允许 |
| replace | 删除 | 使用固定内容 | 按已发布策略组合 |
| strip_all | 删除且最终省略字段 | 无 | 强制抑制 |

净化仅处理结构化顶层 `system` 和已识别 Attribution，不扫描 `messages[].content` 自然语言，也不联动删除 tools、thinking 或业务消息。严格纯净策略遇到不可可靠解析的 System 结构时按 400 失败关闭。`strip_all` 只调度 Attribution optional 的 Credential。

## 16. RuleSet 执行

普通 RuleSet 在 Enforcement 允许范围内提供：

- 字段设值、删除、默认、限幅；
- System 内容替换、删除、重排、合并；
- tools、tool_choice、thinking、cache、beta、metadata 的受控调整；
- 条件可引用 Group、Key、客户端类别、model、stream、已验证字段状态；
- 每个 action 产出 before/after digest、rule id、reason 和风险级别。

固定顺序是：结构修复 → 默认值 → 上限/范围 → System → tools → thinking/cache → beta/metadata → Enforcement 复核 → Capability 终检。模型字段不属于可改写 action。OS、Device Identity、TLS 和上游 Session 也不属于 RuleSet。

规则继承按平台基线 → Group → Key 叠加；下级只能在可覆盖字段上收窄或显式覆盖，不得放宽 Group Enforcement。高风险 System/删除动作需 simulate、Shadow、Canary、双人审批。

## 17. GenericAdjustedRequest

```rust
struct GenericAdjustedRequest {
    replay_body: Arc<RequestReplayBody>,
    body_digest: Digest,
    model_id: ModelId,
    stream: bool,
    portability: Portability,
    attribution_suppressed: bool,
    change_set: Vec<AppliedChange>,
    snapshot_set: Arc<RequestSnapshotSet>,
}
```

`RequestReplayBody` 是 RequestTask 内存生命周期内的独立、不可变 replay holder，封装终检后的语义树与确定性序列化字节；它不进入数据库、Content Audit 对象、Job payload、日志或导出。Generic 的持久事实只有 `body_digest`、Snapshot Set 引用和 change-set metadata。

构造前再次执行 Capability 与 Enforcement 终检。若 change set 为空、原始序列化满足当前 serializer 合同，replay holder 可引用原始业务 Body；否则持有版本化确定性 serializer 的结果。序列化器保证语义等价、字段 presence 正确，并保留 compatible 未知字段。

它不含 access token、Device ID、上游 Session、Credential Metadata、UA、TLS 或 Egress。所有 attempt 复用同一实例或同一 digest；内部 Count Tokens 也必须从该冻结结果生成 token-relevant projection，避免估算与实际请求采用不同 System/规则结果。

## 18. 请求可移植性

```rust
enum Portability {
    Portable,
    Pinned {
        credential_id: CredentialId,
        reasons: Vec<PinReason>,
    },
}
```

默认 Portable：

- 自包含的 Messages 历史；
- 普通 text/image/document 等已知内容块；
- 完整工具 Schema 与 tool use/result 历史；
- 不引用 Credential 私有上游对象的普通 CLI 请求。

默认 Pinned：

- continuation、Provider continuation token；
- file/container/batch 等账号绑定资源 ID；
- 与某个 Anthropic 账号创建的远端资源关联的引用；
- 明确要求原 Credential 上下文的扩展；
- 尚未分类、可能携带账号绑定语义的未知扩展。

CLI 常规 Messages 原则上为 Portable。Pinned 请求在原 Credential 暂时不可用时只进入现有有界短队列，deadline 后返回 503；平台不把资源 ID发送给其它账号试错。后续 Capability 证据确认某扩展为自包含后，可由新版本解除 pin。

### 18.1 Prompt Cache 与跨 Credential

- 除非命中管理员显式发布的 RuleSet，平台保留客户端的 `cache_control` 及所有影响 token 的正文，不为提高命中率而暗改请求；
- 平台不假设 Anthropic 不同 Credential 或不同账号之间共享 Prompt Cache；
- Agent affinity 尽量让同一 Agent 继续使用原 Credential，以提高复用概率，但这不是缓存命中承诺；
- spill 或 retry 切换 Credential 时，按“可能发生 cache miss”处理。它只影响时延与 token 成本，请求可移植性和业务正确性保持原值；
- `cache_creation_input_tokens`、`cache_read_input_tokens` 等结果只采用上游实际返回值；缺失时记为 `unknown`，不合成零值；
- 平台不为了预热或复制缓存而主动重放业务请求；使用记录须标记跨 Credential 切换及上游实际缓存结果，供管理员评估损失。

## 19. Content Audit 门闩

Content Audit 与普通请求/usage 遥测分离。启用全文审计时使用两个持久化阶段：

1. **Original latch**：调度前写入原始请求安全快照；Generic Adjusted Request 只保存 digest、Snapshot Set 和 change set metadata，不另建正文对象。失败时返回 503/5s，Anthropic 调用数为零。
2. **First Final latch**：Request 尚未写出过任何上游字节时，首次候选必须在首字节前写入脱敏 Final Request、Credential/Profile/Egress/Bundle epoch 和 submission intent；secret 值只存引用或 hash。
3. **Started side capture**：`upstream_ever_started=true` 后的 retry Final 与 Response 使用旁路 best-effort writer；失败产生 critical `audit_gap`，不阻止符合既定合同的 retry，也不触发上游重放。

状态建议：

```text
NotRequired
→ OriginalPersisted
→ AttemptIntentPersisted(attempt=n, upstream_ever_started=NeverWritten)
→ UpstreamStarted(attempt=n)
→ ResponseTerminalPersisted
```

在 `NeverWritten` 时，任何可能执行首次首字节写出的候选都必须完成 First Final latch。首字节之后若审计存储短暂失败，真实上游流量继续按 commit 合同完成，另记 `audit_gap` critical 告警；不得为补审计而重放 Anthropic 请求。

## 20. 调度交接

Generic Request 经 Key Gate 后构造 `ScheduleEntry`，交给 [调度器设计](./scheduler-design.md)：

```text
GenericAdjustedRequest
+ client/session/agent
+ model/stream/portability
+ frozen deadlines and snapshots
+ audit latch state
→ GroupExecutor
```

调度器不读取或改写 JSON tree，只使用投影字段判断资格与评分。返回的 Lease 冻结 token version、Profile epoch、Archetype/Bundle、Egress epoch 和 Session Claim。Lease 与当前 Request/attempt ordinal 不匹配时拒绝构造。

## 21. Credential Profile 应用

`ProfileFactory` 每次从 Generic Request 与当前 Lease 全量构造：

```rust
struct FinalUpstreamRequest {
    method: Method,
    authority: AnthropicAuthority,
    headers: OrderedHeaders,
    body: ReplayableBody,
    transport: TransportDescriptor,
    safe_audit_view: SafeFinalView,
    final_digest: Digest,
}
```

应用内容：

- access token 或 API Key 认证 Header；
- Credential 固定 UA、版本、X-App/Stainless 和协议 Header；
- Device/client identity；
- Profile 允许的 System Attribution 与 Metadata；
- 由 Credential Session HMAC 对 canonical Base Session 派生的真实格式兼容 UUID；Agent ID只用于公平队列和 affinity，不进入上游 Session UUID；
- 每请求独立 `x-client-request-id`；
- 匹配 Archetype 的 Transport Bundle 与固定 Egress Binding。

Profile 权限低于 Enforcement：`strip_all` 时 Attribution suppression 强制生效。Header 与 Metadata 中的派生 Session 必须一致。token refresh、同账号重认证、Archetype cohort 升级保留 Session HMAC，因此既有派生关系稳定；换 Credential 时从 canonical Session 用新 Credential 密钥重新派生。

## 22. Final Validation 与提交意图

Final Request 发送前验证：

- Header allowlist、重复敏感 Header、Content-Length/encoding；
- Anthropic authority 固定且 Gateway Base URL、Host、Forwarded、X-Forwarded-*、X-Real-IP、Via、Origin、Referer 均已剔除；
- token version、Profile/egress epoch、Bundle 与 Lease 一致且仍 active；
- 声明 OS、Bundle 证据、TLS/H1/H2 engine 一致；
- System Attribution 与 Enforcement 相容；
- Body digest 对应冻结 Generic Request；
- retry attempt 与总 deadline 仍有预算。

通过后先提交 Attempt Final audit 与 submission intent，再把 immutable Final Request 交给 Transport。真正写出第一个上游请求字节时将 intent promotion 为 Messages AttemptRecord；之前的 DNS/TCP/CONNECT/TLS 只记 ConnectionAttempt。

## 23. 连接与上传

连接阶段由 Transport Engine 执行，默认 5 秒、可按 Group 配置 1–30 秒，覆盖 proxy tunnel、TCP、TLS 与 ALPN。健康池连接直接复用时没有新建连计时。

上传合同：

- Body 必须 replayable；内存或加密 spill handle 的游标按 attempt 独立；
- 首字节原子 promotion 后才消耗 Messages attempt；
- 客户端取消时立即停止后续读取/写入；H2 reset stream，H1 关闭并逐出连接；
- 上传中失败意味着 attempt 已发生，usage 为 unknown；
- 第一个上游字节前失败可使用最多 3 个 ConnectionAttempt，依据 transport failure class 同 Credential 重连或在 Portable 条件下重新调度；
- 跨 Credential 先释放旧 Lease，再从 Generic Request 构造全新的 Final Request。

## 24. 上游 Header 与响应来源

Transport 收到 Header 后先做结构安全过滤：

- 保留安全的 content-type、content-encoding、缓存语义、Anthropic request-id、`x-should-retry`；
- 删除 hop-by-hop、连接实现、`set-cookie`、单 Credential 限流与配额 Header；
- 解析并内部消费 Retry-After、quota window、usage/plan 相关可信 Header；
- 上游 status 与 Body 不重新包裹；`response_source=anthropic` 只进入内部记录；
- 平台自产错误使用自己的 request ID 与固定包络；health/ready 可显式标记 gateway source。

在客户端尚未 commit 时，401/429/5xx 可进入调度器 retry decision。选定重试后丢弃该 attempt 的上游 Body，不向客户端发送任何 Header。

## 25. 非流式状态机

```text
AwaitingHeaders
→ ReceivingBody
→ BodyComplete
→ TerminalFactsQueued
→ ReadyToDeliver
→ HeadersCommitted
→ DeliveringBody
→ Completed

ReceivingBody → RetryDecision | FailedBeforeCommit
BodyComplete/ReadyToDeliver → Discarding on client cancel
DeliveringBody → WriteFailed | DeliveryTimedOut
```

规则：

- 完整接收原始 Body 后才释放 Credential Lease；
- 8 MiB 内存阈值后无损写入加密临时文件；单响应默认 64 MiB 硬上限；
- Body complete 后生成 status/header digest、bytes、usage和terminal audit事实并进入有界持久化旁路；该旁路失败记`audit_gap`/telemetry gap，不成为客户端commit门闩；
- 随后一次性提交过滤后的 Header，并逐字节发送原始 Body；
- Key/Group permit 与 Reservation 持有到交付完成或 Body/DEK 销毁；
- 客户端写 idle 默认 120 秒，交付总时限默认 300 秒；
- Header commit 后写失败只记 delivery failure，不重新调用 Anthropic；
- 客户端在 `ReadyToDeliver` 前取消时丢弃完整结果，但 Attempt success 与 usage 仍保留。

## 26. SSE 状态机与背压

```text
AwaitingHeaders
→ HeadersCommitted
→ Streaming
→ UpstreamEnded
→ Completed

Streaming → ClientCancelled | ClientWriteFailed | UpstreamInterrupted
```

规则：

- Anthropic 2xx Header 到达并通过过滤后立即向客户端 commit；
- SSE 数据不解析重写，收到原始字节即按顺序 flush；
- 默认 pending window 1 MiB，满时暂停读取 upstream；
- 仅 pending bytes 非空时计算客户端 write idle，默认 120 秒；
- 因平台背压主动暂停 upstream read 时暂停 30 秒 upstream idle 计时；恢复读取后继续；
- commit 后出现 upstream、transport、审计或客户端错误，只关闭连接并记录终态；
- 不追加 Gateway JSON、SSE error、伪造结束事件，不开启另一 attempt；
- 首版无 replay、断点续传或 WebSocket 转换。

原始字节透明不代表原始 Header 全透传；Header 仍执行第 24 章的隐私与 hop-by-hop 过滤。

## 27. 错误、取消与可观测性

### 27.1 错误归属

| 位置 | 对外结果 | retry |
|---|---|---|
| Auth/parse/classify/policy/capability | 平台 4xx | 无 |
| Key/Group/Reservation admission | 平台 429/503 | 客户端决定 |
| Final build/audit latch | 平台 500/503 | 平台仅在尚无首字节且合同允许时处理 |
| 连接阶段 | 503/504 或重新调度 | 最多 3 ConnectionAttempt |
| Anthropic 401/429/5xx，未 commit | 原响应或重新调度 | 总 Messages Attempt 最多 3 |
| Anthropic 最终响应 | 原 status/body | 无 |
| commit 后任意异常 | 关闭/结束交付 | 无 |

### 27.2 取消检查点

每个 await 边界都检查 cancellation token：读 Body、审计、Group queue、Reservation、Lease、connect、upload、response read、client write。取消时由 RequestTask 写唯一 terminal，再通知 GroupExecutor 和 Transport；资源释放遵循 [调度器第 26、27 章](./scheduler-design.md#26-requestcommit-与-cancel)。

### 27.3 遥测

每阶段记录 start/end、snapshot/version、input/output digest、change count、失败分类和资源状态。敏感字段只记录结构/长度/hash；原始 User/Key/Credential/Session ID不作为指标 label。重点指标：

- classification 结果、信号与版本；
- probe template 命中、疑似分数、throttle/reject；
- System policy、RuleSet action、Capability diagnostic；
- Generic/Final digest 与 Profile/egress/bundle epoch；
- audit latch latency/gap；
- first-byte promotion、retry/cross-Credential；
- response commit、SSE pending、spill bytes、client write latency。

## 28. 全局不变量、测试入口与 Reader Check

### 28.1 不变量

1. 北向 Platform Key 或 Gateway Base URL 永远不进入南向请求。
2. 客户端 UA/Session/Attribution 不直接上送，由 Profile 重建。
3. `GenericAdjustedRequest` 在所有 attempt 间具有同一 digest。
4. `FinalUpstreamRequest` 只属于一个 Lease/attempt；换 Credential 必须全量重建。
5. `strip_all` 后最终 Body 没有顶层 System，Profile 也不注入 Attribution。
6. 模型 ID保持原值；调度器不选择替代模型。
7. 未知扩展保留时默认影响 portability；未经分类不跨 Credential。
8. 未写出上游首字节时 Messages Attempt 为零；写出首字节后恰有一个对应记录。
9. client commit 后 retry 永久关闭。
10. Anthropic Body/SSE 字节内容与客户端收到的已交付前缀一致。
11. 单 Credential 限流 Header 不出现在客户端响应。
12. Content Audit Original latch 失败时 Anthropic 调用数为零。
13. 审计 gap 不触发请求重放。
14. 内部 Count Tokens 使用同一 Generic Snapshot，不重新解释规则。
15. `SuspectedProbe` 单独出现时对请求处理结果零影响。

### 28.2 必测 corpus

- JSON 缺失/null/value、重复 key、未知字段和未知内容块；
- Claude Code/Harness/SDK 分类正反样本；
- 显式 Probe 模板唯一性、两级限速和误报保护；
- System 四模式与不可解析结构；
- 模型 A/B 的 thinking、tools、cache、beta 差异；
- zero-change raw body reuse 与 deterministic serialization；
- Portable/Pinned 每类触发字段；
- audit latch 每个故障点；
- 连接首字节前后 cancel；
- 401 refresh、429、529 与跨 Credential；
- 非流式 8 MiB spill、64 MiB hard limit、完整后取消；
- SSE 1 MiB 背压、idle 暂停、commit 后中断；
- Header 泄漏扫描和 Body 字节对比。

### 28.3 Reader Check

- 客户端传来的 System 在哪里处理？见第 15、16 章。
- “完全纯净”Group 如何保证 Profile 不补回 Attribution？见第 15、21 章。
- 短 `ping` 为什么不直接判成测活？见第 11、12 章。
- 测活模板允许忽略哪些动态值？见第 11 章。
- 模型能力持续变化时是否改代码分支？见第 14 章。
- 跨 Credential 时哪些数据保持不变？见第 17、18、20、21 章。
- 上游 Session ID是否符合真实客户端格式？见第 21 章；具体派生证据由 Profile/Transport 文档定义。
- 为什么一个 Credential 可以同时有多个 Session？见第 10、21 章。
- 何时算一个 Messages Attempt？见第 22、23 章。
- 非流式为什么先完整缓冲？见第 25 章。
- SSE 为什么 commit 后只关连接？见第 26 章。
- Body/SSE 透明与 Header 过滤是否矛盾？见第 24、26 章。
- Content Audit 故障会不会让同一请求被 Anthropic 执行两次？见第 19、28 章。
