# Claude Code Gateway 调度器详细设计

> 状态：Detailed Design Baseline  
> 上位文档：[功能模块规划](./functional-modules.md)、[技术架构](./technical-architecture.md)、[领域模型](./domain-model.md)、[数据库设计](./database-schema.md)、[API 契约](./api-contract.md)  
> 适用范围：首版单实例 Rust Core，Anthropic 官方 API 单上游

## 1. 文档目的

本文冻结请求准入、公平排队、Credential 选择、Lease、重试、取消和资源核算的可实现语义。目标不是描述一个抽象“轮询器”，而是给出能直接映射到 Rust actor、状态机、测试模型和运行指标的详细合同。

调度器必须同时满足：

- Platform Key 的独立硬并发和 RPM；
- Group 的可选并发/RPM、有限队列和公平服务；
- Credential 的资格、容量、配额压力、冷却、Profile/Transport/Egress 一致性；
- Base Session 与 Agent 粘性，但不把一个 Session 的多个 Agent 串行化；
- 可移植请求的条件式跨 Credential 重试；
- 每份 permit、Lease、Reservation 和 Session Claim 恰好释放一次；
- 配置热更新、进程重启和迟到消息不会破坏新一代运行态。

## 2. 范围与非目标

首版范围：

- 单个 Linux 生产实例；
- Rust Core 内 `GroupExecutor` 单写者 actor；
- 内存态实时队列、permit、Lease、affinity 和 timer；
- PostgreSQL 保存配置、Credential 投影、请求结果与审计事实；
- Group 内订阅 Credential 为主，可按独立配置加入 Console API Key；
- User → Platform Key → Base Session → Agent 四级公平队列。

首版非目标：

- Redis 或分布式 Lease；
- 多实例共享同一 Credential；
- owner 自动故障转移；
- 多 Provider 与自动模型切换；
- PLAN、套餐等级、预估成本参与权重；
- 默认单 Session 并发上限；
- 独立的永久 Lease TTL；
- 队列状态在进程重启后续接。

## 3. 标识与层级

调度层固定使用以下标识：

```text
UserId
└── PlatformKeyId
    └── BaseSessionId
        └── AgentId
            └── RequestId FIFO
```

- `UserId` 来自 Platform Key owner，不接受客户端输入；
- `PlatformKeyId` 来自认证结果；
- `BaseSessionId` 优先使用通过格式校验的 Claude Code Session 标识，否则从稳定请求上下文生成；
- `AgentId` 来自可信可解析的 agent/session 子标识；缺失时使用 Base Session 的 `main` 叶节点；
- 每个请求都是最小 service unit，成本基线为 1；
- 一个 main 加九个 subagent 是同一 Base Session 下十个独立 Agent 叶节点，可并行取得 Lease。

原始客户端 Session 值只进入内部归一化和遥测。上游 Session ID 由选中 Credential 的 Device Identity 与会话映射生成，避免把北向值直接暴露给 Anthropic。

## 4. Group 所有权与单写者

每个 Group 在任一时刻只由一个 `GroupExecutor` generation 管理：

```rust
struct ExecutorIdentity {
    group_id: GroupId,
    owner_partition: u32,
    generation: u64,
}
```

它独占修改：

- Group permit 和 RPM bucket；
- Fair Queue Tree、QueueTicket 和 runnable ring；
- CredentialRuntime、cooldown、half-open budget；
- SessionActivityClaim 与 affinity；
- outstanding Lease；
- retry scheduling 与所有相关 timer。

HTTP task、Transport Engine、数据库 writer 只发送命令和接收不可变结果。旧 generation 的 grant、release、timer、refresh 或 transport 回调均按 generation 丢弃，并记录 stale event 指标。

## 5. 时间、版本与 Generation

- deadline 使用进程单调时钟；持久化时同时记录 UTC 时间用于审计；
- `pre_upstream_deadline` 在进入 Group RPM 等待前创建一次，默认 `accepted_at + 30s`；
- `upstream_total_deadline` 在第一次连接尝试前创建，非流式默认 300 秒，跨 attempt 不重置；
- 流式使用 30 秒 upstream idle，而非固定总时长；背压主动暂停上游读取时暂停 idle 计时；
- 每个 QueueTicket、Lease、Session Claim、timer 都携带 executor generation；
- 配置、Profile、token、egress、bundle 分别用 revision/version/epoch 标识，不复用一个全局版本号。

## 6. 冻结输入

通过解析、分类和通用调整后，调度器接收：

```rust
struct ScheduleEntry {
    request_id: RequestId,
    user_id: UserId,
    platform_key_id: PlatformKeyId,
    group_id: GroupId,
    base_session_id: BaseSessionId,
    agent_id: AgentId,
    client_class: ClientClass,
    model_id: ModelId,
    stream: bool,
    portability: Portability,
    generic_request: Arc<GenericAdjustedRequest>,
    snapshot_set: Arc<RequestSnapshotSet>,
    pre_upstream_deadline: Instant,
    upstream_policy: FrozenUpstreamPolicy,
    audit_latch: AuditLatchState,
}
```

`GenericAdjustedRequest`、`RequestSnapshotSet`、客户端类别和 portability 在整个请求生命周期固定。retry 只更换 Credential-scoped 的 token、Profile、上游 Session、Transport Bundle 和 Egress。

## 7. 固定 Gate 顺序

Messages 准入顺序固定为：

```text
Route
→ Platform Key authentication
→ endpoint permission / IP allowlist / Key status
→ body size and parse
→ client classification / probe policy
→ model scope / Capability validation
→ Key Messages RPM
→ Key concurrency permit
→ Group governance / content audit latch
→ Group RPM
→ Group concurrency + fair queue
→ non-stream Reservation
→ Credential eligibility and Lease
→ FinalUpstreamRequest
→ Transport
```

前一 Gate 未通过时，后续资源为零。Key permit 覆盖 Group 排队、上游执行和客户端交付；它是对单个 Platform Key 的真实硬上限。

## 8. Platform Key RPM

每个 Key、每个端点家族使用独立 token bucket：

```rust
struct TokenBucket {
    capacity: u32,
    refill_per_second: Decimal,
    available: Decimal,
    last_refill: Instant,
}
```

Messages 默认 60 RPM、burst 10。Models 使用另一桶，默认 60 RPM、burst 10。RPM 在 Key concurrency 之前消费；成功消费的 token 不因后续取消或失败退回。

不足时立即返回 429，`retry-after` 为下一 token 到达所需秒数向上取整，至少 1 秒。Key 配置可以由管理员按充值额度等外部流程调整，但额度自动联动首版不实现。

## 9. Platform Key 并发

每个 Key 默认硬上限 5，管理员可独立调整：

```rust
struct KeyPermit {
    key_id: PlatformKeyId,
    request_id: RequestId,
    generation: u64,
}
```

- 满载时立即返回 429，默认 `retry-after: 2`；
- 不进入 Group 队列，不等待其它 Key 释放；
- 不占 Group permit、Reservation、Credential Lease 或 Session Slot；
- permit 从通过 Gate 起一直持有到响应交付完成、丢弃完成或终态清理；
- release 使用唯一 token 和幂等状态，重复释放只记录 invariant violation。

不同 Platform Key 的硬上限相互独立。同一用户持有多个 Key 时，公平树的 User 层仍会约束其相对服务机会。

## 10. Actor 命令与事件

`GroupExecutor` 最小命令集：

```rust
enum GroupCommand {
    Admit(ScheduleEntry, ReplyTo),
    Cancel { request_id: RequestId, observed_phase: RequestPhase },
    ReservationGranted { ticket_id: TicketId, generation: u64 },
    TransportEvent(TransportEvent),
    ReleaseLease { lease_id: LeaseId, generation: u64, reason: ReleaseReason },
    RefreshCredential(CredentialProjection),
    ApplyConfig(CompiledGroupConfig),
    Tick(TimerKey),
    BeginDrain(DrainReason),
}
```

输出只包含不可变 decision：admitted、queued、lease granted、terminal error、retry plan 或 cancel instruction。外部 task 不直接读取并修改 actor 内部 counter。

## 11. GroupRuntime

```rust
struct GroupRuntime {
    identity: ExecutorIdentity,
    state: RuntimeGroupState,
    config: Arc<CompiledGroupConfig>,
    rpm: Option<TokenBucket>,
    concurrency_limit: Option<u32>,
    inflight_group_permits: u32,
    fair_queue: FairQueueTree,
    credentials: BTreeMap<CredentialId, CredentialRuntime>,
    affinities: HashMap<AgentAffinityKey, AffinityState>,
    session_claims: HashMap<SessionClaimKey, SessionActivityClaim>,
    tickets: HashMap<TicketId, QueueTicket>,
    leases: HashMap<LeaseId, CredentialLease>,
    timers: TimerWheel,
}
```

运行态为 `Loading → Serving → Draining`，任何态可进入 `OwnerUnavailable`。持久 Group 状态为 `active|disabled|archived`，不得用一个字符串覆盖运行态。

## 12. Group RPM 与并发

Group RPM、burst 和 concurrency 默认 `null`，表示该层不施加限制；启用后：

- Group RPM 可在共享提交前 deadline 内等待；到期返回 429，默认 `retry-after: 5`；
- Group concurrency 是所有 Key 的聚合上限；无 permit 时请求保留在公平队列中；
- effective concurrency 用于计算默认队列容量：配置 Group 并发存在时取该值，否则取当前可调度 Credential 并发能力和；
- 队列容量默认不超过 `2 × effective concurrency`；
- 队列满返回 503，默认 `retry-after: 2`；
- 队列等待耗尽共享 deadline 返回 503，默认 `retry-after: 5`；
- 以上结束路径都释放 Key permit。

## 13. QueueTicket

```rust
struct QueueTicket {
    id: TicketId,
    request_id: RequestId,
    path: FairPath,
    enqueued_at: Instant,
    deadline: Instant,
    state: TicketState,
    generation: u64,
}

enum TicketState { Queued, Granted, Cancelled, TimedOut }
```

合法转换仅为：

```text
Queued → Granted
Queued → Cancelled
Queued → TimedOut
```

grant、cancel 和 timeout 都在 actor turn 内 compare-and-transition。赢家负责从全部索引移除 ticket；迟到消息仅记录。Ticket ID 不复用。

## 14. 四级公平树

```rust
struct FairQueueTree {
    users: OrderedRing<UserNode>,
}

struct FairNode<K, C> {
    key: K,
    deficit: i64,
    quantum: i64,
    cursor: usize,
    children: OrderedRing<C>,
    runnable_children: usize,
}
```

层级必须是 User → Key → Base Session → Agent。每个 Agent 叶节点维护严格 FIFO 请求队列；同一 Base Session 内多个 Agent 是兄弟节点，不折叠成单 FIFO。

首版所有公平节点 `quantum=1`，单请求 `cost=1`。Credential 管理员 weight 不进入公平树；它只参与同一优先级候选 Credential 的最终选择。

## 15. Hierarchical DRR

```text
next_runnable(root, now):
    recursively visit only runnable children
    at each level:
        repeat at most current runnable_child_count times:
            child = cursor.next()
            child.deficit += child.quantum
            if child.deficit < 1:
                continue
            entry = recurse(child)
            if entry exists:
                child.deficit -= 1
                prune empty path
                return entry
    return none
```

规则：

- 叶节点只检查队首，保持 Agent 内 FIFO；
- 因 Credential、RPM、slot 等临时条件阻塞的队首离开 runnable ring，阻塞期间不积累 deficit；
- 节点重新 runnable 时 deficit 从 0 开始，首次只得到一个 quantum；
- 空节点立即裁剪；之后同名 Session/Agent 重建时不继承历史信用；
- 一次 pump 持续 grant，直到 permit、当前合格 Credential 或 runnable 队首耗尽；
- 存在空闲合格 Credential 与 runnable 队首时，pump 必须推进至少一个请求。

## 16. 非流式 Reservation 顺序

为了避免大量慢响应耗尽内存/磁盘，非流式请求在 Lease 前获取固定 Reservation：

```text
Key permit
→ Group permit / fair grant
→ Buffer Reservation
→ Credential Lease
```

默认：

- 单响应 hard limit 与 Reservation：64 MiB；
- 内存阈值：8 MiB，超过后无损切换到加密临时文件；
- 实例 Reservation budget：2 GiB，即 32 个 64 MiB 保障槽；
- Reservation wait queue：64；
- 排队与前序等待共用 30 秒绝对 deadline；
- admission 满立即 503/2s；等待到期 503/5s。

Lease 在完整接收上游非流式 Body 后释放；Reservation、Key/Group permit 保持到客户端交付或丢弃完成。流式请求跳过 Reservation。

## 17. Base Session 语义

Base Session 是公平和历史的聚合键，不是并发互斥锁。两个用户即使错开请求，也分别形成各自的 Session 历史；只有当前存在请求或开启可选 slot 时才占运行资源。

一个 Base Session 可包含多个 Agent。调度器在 Session 节点下按 Agent 公平服务，因此 `main + 9 subagent` 可同时使用多个 Credential 并发，不会被强制当作一个上游请求序列。会话历史记录用于 affinity、观测和后续请求映射，不自动预留 Credential 容量。

## 18. Agent 叶节点

Agent 的稳定键建议为：

```text
HMAC(session_hmac_key, normalized_client_agent_identity)
```

缺失可信 agent identity 时使用常量 `main`。规则：

- 每个 Agent 内严格 FIFO；
- 不在 Agent 层设置默认并发上限；
- 同一 Agent 的前一请求执行中，后续请求仍可调度，除非客户端语义被识别为 pinned continuation；
- Agent affinity 是 preferred，不是永久绑定；
- 大量新 Agent 不获得预装 deficit，避免以创建 Agent 抢占公平机会。

## 19. 可选 Session Slot

该能力完整保留，由管理员决定是否启用：

```rust
struct SessionActivityClaim {
    credential_id: CredentialId,
    base_session_id: BaseSessionId,
    active_request_count: u32,
    state: SessionClaimState,
    idle_deadline: Option<Instant>,
    generation: u64,
}
```

- 默认 `capacity_enabled=false`、`max_active_sessions=null`；
- 开启后，同一 Credential 上同一 Base Session 的多个 Agent 共占一个 slot；
- `active_request_count` 从 0→1 时获取 slot，从 1→0 时进入 idle countdown；
- 默认 idle TTL 30 分钟；期间新请求复用 Claim 并重置 timer；
- 没有空 slot 时最多等 5 秒，且受剩余提交前 deadline 限制；
- Session 历史和 affinity 留存不占 slot；
- spill 到第二个 Credential 时，会在第二个 Credential 上形成另一个 Claim。

Session Slot 只控制活动 Session 数，不等价于单 Session 并发上限。后者首版保持关闭且配置模型中没有该字段。

## 20. Affinity

Affinity Key 为 `(group_id, base_session_id, agent_id)`，值为 preferred Credential：

```rust
struct AffinityState {
    preferred_credential_id: CredentialId,
    status: AffinityStatus,
    last_success_at: Instant,
    expires_at: Instant,
    spillover_count: u32,
    migration_generation: u64,
}
```

默认 TTL 24 小时。选择语义：

- preferred 当前合格则优先；
- 仅因并发满而阻塞时，Portable 请求最多等待 2 秒；仍阻塞则可 spill 到同 Group 其它 Credential；
- 一次 spill 成功只记录事实，不立刻改写 preferred；
- preferred 出现持续 transport/auth/egress blocker，且替代 Credential 达到稳定成功门槛后才原子迁移；
- 迁移后原 Credential 恢复也不自动抢回；
- Pinned 请求始终等待原 Credential，直到共享 deadline 后返回 503；
- affinity 是内存态，进程重启后按新请求重新建立。

## 21. Credential Eligibility

资格判断先确定性、后临时性：

```text
evaluate(entry, credential, now):
    deterministic:
        Group serving and membership
        accepted client class
        auth-pool and credential purpose
        lifecycle active + attached
        auth usable, token still valid
        model and capability scope
        thinking/cache/system-attribution compatibility
        Profile active
        Bundle loaded and engine-compatible
        Egress binding healthy; static egress not drifted
        portability pin, if present, matches credential

    temporary:
        credential concurrent capacity
        credential RPM token availability
        known 5h/7d/model quota below 95%
        cooldown/reset/half-open probe budget
        optional Session Slot
```

确定性无候选时立即返回 503，不排队且无 `retry-after`，并触发高优先级管理员告警。存在确定性候选但受临时条件阻塞时，才在剩余 deadline 内等待。

`Expiring` 状态下旧 access token 仍有效时可继续承载；token 已失效、refresh/reauth 进行中、manual recovery、Profile/Egress/Transport blocker 均停止新 Lease。

## 22. Credential 评分与选择

规范顺序：

```text
1. 只保留 Eligible 候选
2. 选择最优管理员 priority layer
3. 在该层优先健康 affinity
4. 新请求或 spill：已知 quota observation 优先于 unknown
5. 最小化 max(5h, 7d, model-specific quota pressure)
6. 最小化 normalized concurrency/RPM pressure
7. 比较 Transport/Bundle/Egress health
8. 应用 Credential administrator weight
9. credential_id + stable request hash 确定性 tie-break
```

管理员 priority 是外层，affinity 不跨越更高优先级层。PLAN、套餐名、billing mode、estimated cost、User 角色不参与任何候选资格、排序或 weight。

全部候选处于可信 cooldown 时：若最早恢复点在请求 deadline 内，保留公平位置；若超出则立即 429，`retry-after` 为最早恢复秒数向上取整。未知恢复时间按临时阻塞排队至 deadline，而非伪造精确恢复时间。

## 23. Credential Lease

```rust
struct CredentialLease {
    lease_id: LeaseId,
    request_id: RequestId,
    credential_id: CredentialId,
    executor_generation: u64,
    token_version: u64,
    profile_epoch: u64,
    archetype_version_id: ArchetypeVersionId,
    transport_bundle_version: BundleVersion,
    egress_epoch: u64,
    session_claim_id: Option<SessionClaimId>,
    granted_at: Instant,
    state: LeaseState,
}
```

发放必须在一个 actor turn 内原子完成：

```text
assert current generation
assert eligibility still Eligible
consume Credential RPM token
increment credential.concurrent_inflight
acquire/increment SessionActivityClaim when enabled
insert outstanding lease
transition QueueTicket Queued → Granted
return frozen lease
```

Lease 是 Credential 并发计数的唯一增减凭证。数据库行不充当实时锁。同一 Request 同时最多一个业务 Lease；跨 Credential 前旧 Lease 必须进入 Released。重复 release 不再修改 counter，并产生 `resource_invariant_violation`。

## 24. ConnectionAttempt 与 Messages Attempt

两类 attempt 分离：

- `ConnectionAttempt`：DNS、TCP、proxy CONNECT、TLS、HTTP/2 建连；每 Request 最多 3 次；
- `Messages Attempt`：从第一个上游请求字节实际写出时创建；每 Request 最多 3 次。

三个连接都在零上游请求字节前失败时，结果为 ConnectionAttempt=3、Messages Attempt=0、usage 不存在。为覆盖“进程在首字节附近退出”的未知窗口，在写前先持久化 submission intent；恢复时可标记 `commit_unknown`，但不虚构成功 usage。

Attempt 记录包含 Credential、token version、Profile/egress epoch、Bundle、上游 request-id、状态、usage 来源、错误类别和 retry decision。一个 attempt 的 Credential-scoped 快照终身不变。

## 25. Retry 决策

```text
decide_retry(error, request, budget):
    deny if client committed
    deny if body not replayable
    deny if error category is final
    deny if messages attempts used >= 3
    deny if remaining upstream budget < 5s
    deny if no schedulable candidate
```

具体策略：

- 首个上游字节前的 DNS/TCP/TLS/CONNECT 失败只消耗 ConnectionAttempt；瞬时/未知错误优先同 Credential 新连接，明确路径故障且 Portable 时可换 Credential；
- 401：Attempt 1 后触发 singleflight refresh；以新 token version 重获同 Credential Lease形成 Attempt 2；再次 401 且 Portable、预算充足时释放原 Lease并用其它 Credential形成 Attempt 3；
- 429：消费可信 `Retry-After`/reset Header；缺失时按同 Credential 连续 429 采用 60/120/300/900 秒冷却，单次最长 15 分钟；Portable 可换 Credential；
- 500/502/503/504/529：在同一个绝对 deadline 内采用有界 jitter backoff；
- 非流式 upstream total timeout、流式已 commit 后中断、客户端交付失败均不重试；
- retry 重新从 `GenericAdjustedRequest` 构建完整 Final Request，不在上一份 Final Request 上替换 token。

## 26. Request、Commit 与 Cancel

请求核心状态：

```text
accepted → authenticated → parsed_and_classified
→ key_rate_accepted → key_permitted → governed
→ queued → reserved(non-stream) → leased
→ connecting → submitting → submitted → receiving
→ delivering(stream)
| ready_to_deliver → delivering(non-stream)
→ finished

any non-terminal → cancelling → finished
```

Commit 边界：

- SSE：Anthropic 2xx Header 向客户端写出即 committed；
- 非流式：上游完整 Body 已接收，并准备一次性发送 Header/Body 时 committed；terminal facts 与审计进入独立持久化侧路，不作为客户端响应门闩，失败时形成可告警的 `audit_gap`；
- committed 后 `retry_eligible=false` 永久成立。

取消由 Request terminal compare-and-set 与 actor 顺序共同裁决：

```text
cancel:
    win terminal CAS once
    cancel queued ticket by id + generation
    block future grant/lease/attempt
    release Key/Group permit and active Session reference immediately
    ask transport to cancel
    release Lease after transport confirmation or 2s grace force close
    destroy pending buffer and DEK
    release Reservation after destruction
```

普通准入/构造失败按获得资源的反序回滚；客户端取消使用上述阶段矩阵，因为 Lease 可能仍对应活跃 socket。

## 27. ResourceLedger

每个 Request 持有内存账本：

```rust
struct ResourceLedger {
    key_permit: Option<KeyPermit>,
    group_permit: Option<GroupPermit>,
    queue_ticket: Option<TicketId>,
    reservation: Option<Reservation>,
    session_claim: Option<SessionClaimRef>,
    credential_lease: Option<LeaseId>,
    connection_attempts: u8,
    messages_attempts: u8,
    terminal_written: bool,
}
```

不变量：

1. 获取顺序固定为 Key → Group/Queue → Reservation → Session Claim/Lease。
2. 任何 token 最多一次有效 release。
3. Credential `concurrent_inflight == outstanding_leases.count`。
4. 同一 Request 同时最多一个 Lease。
5. terminal 只有一个，terminal 后拒绝 grant/lease/attempt/chunk。
6. RPM token 一经消费不退还。
7. Reservation 在 buffer 与临时 DEK 销毁后释放。
8. 迟到的旧 generation 消息不触碰新资源。

Drop guard 只作为泄漏兜底，正常路径必须显式 release 并产生可追踪 reason。

## 28. 持久化与重启

持久化：

- Group/Key/Credential 配置与版本；
- token/profile/egress/bundle epoch 投影；
- cooldown、quota observation、PLAN 展示投影；
- Request、ConnectionAttempt、Messages Attempt、usage、审计和告警。

仅内存：

- QueueTicket 与公平树 deficit/cursor；
- permit、Lease、Session Claim；
- socket、SSE pending window、非流式 buffer handle；
- affinity；
- timer wheel 和 half-open 当前探针占用。

重启流程重新加载持久配置和 Credential 状态，创建新 generation；旧请求、队列、Lease、连接、buffer 和 affinity 都不续接。上次运行未闭合的 request/attempt 由恢复任务标记为 `interrupted|commit_unknown|usage_unknown`，不在新 actor 中恢复执行。

## 29. 错误与遥测

调度平台错误遵循 [API 契约第 16 章](./api-contract.md#16-数据面平台错误矩阵)。内部至少记录：

- 每个 Gate 的拒绝数与 latency；
- Key/Group/Credential 当前并发与 RPM 压力；
- 四级队列深度、等待时间、每层 service count 与 starvation detector；
- affinity hit、preferred wait、spillover、migration；
- deterministic/temporary ineligibility 原因；
- quota pressure、cooldown、half-open；
- Lease grant/release reason、持有时间和 invariant violation；
- ConnectionAttempt/Messages Attempt、retry reason 与 exhausted budget；
- cancel phase、transport cancel latency 和 2 秒 grace 命中；
- Reservation 使用、等待、spill file 和销毁时延。

标签必须使用受控低基数字段；User/Key/Session/Request/Credential 具体 ID 进入 trace 或日志字段，不直接成为 Prometheus label。PLAN 可以展示和记录 freshness，但任何调度 decision trace 中都应标明 `plan_influence=false`。

## 30. 场景、属性测试与 Reader Check

### 30.1 关键场景

1. **3 个 Credential × 并发 5，10 个 Key × 每 Key 4 请求**：40 个请求通过各自 Key；15 个执行、25 个进入 DRR。默认 effective concurrency=15、queue cap=30，可容纳全部 25。
2. **40 个请求共用默认 Key**：前 5 个取得 Key permit，后 35 个立即 429，Group 完全看不到它们。
3. **Group 队列满**：15 执行加 30 排队后，第 46 个已通过独立 Key Gate 的请求返回 503/2s。
4. **共享 deadline**：Group RPM 等 24 秒、permit 等 1 秒，Reservation 只剩 5 秒；总计 30 秒结束，不重新获得 30 秒。
5. **Group RPM 超时**：30 秒到期返回 429/5s，无 Lease/Attempt。
6. **确定性无 Credential**：全部 disabled/auth broken/profile/egress blocker，立即 503且不入队。
7. **全部 cooldown**：最早 12 秒恢复则等待；最早 45 秒恢复则立即 429/45s。
8. **preferred 仅并发满**：Portable 最多等 2 秒，再 spill 到 B；仍保留 A affinity。
9. **持续故障迁移**：A 长期 transport blocker、B 稳定成功后迁移 preferred；A 恢复不抢回。
10. **Pinned**：只等原 Credential，B 空闲也不切换，deadline 到期 503。
11. **main + 9 subagent**：一个 Base Session、十个 Agent；slot 关闭时仅受全局容量限制。
12. **quota 95%**：A 停止新 Lease；reset 后 HalfOpen 只允许一条真实 Portable 请求探测。
13. **OAuth 401**：A1→refresh→A2→再次 401→Portable 切 B 形成 Attempt3。
14. **三次纯建连失败**：ConnectionAttempt=3、Messages Attempt=0、usage 无记录。
15. **grant/cancel 竞态**：actor turn 唯一决定赢家，资源计数归零。
16. **Lease 后首字节前取消**：无 Attempt/usage，不处罚 Credential。
17. **上传中取消**：已有首字节，计 Attempt、usage unknown；H2 reset/H1 逐出连接。
18. **非流式完整缓冲后取消**：Attempt success、usage complete、Lease 已释放；销毁 Body/DEK 后释放 Reservation。
19. **SSE committed 后中断**：保留已交付字节并关闭流，零 retry。
20. **Group disabled**：尚未获得 Lease 的请求结束；已开始请求继续到既定终态。
21. **动态 Group owner 装配**：新 Group 事务提交后，本进程以 durable owner CAS 获得唯一 generation、创建 actor 并原子发布到 registry；disable/archive 排空并释放 owner，reactivate 重新申请更高 generation，不因 owner lease churn 修改业务 revision。

### 30.2 属性与模型测试

- `key_inflight <= key_limit`；
- Group 配置上限存在时 `group_inflight <= limit`；
- `credential.concurrent_inflight == outstanding_leases.count`；
- Reservation bytes 不超过 2 GiB，默认保障槽不超过 32；
- active request/session count 永不下溢；
- Request 恰好零或一个 terminal；
- Attempt 序号连续且 Messages/Connection 各自不超过 3；
- first-byte 事件与 Attempt promotion 一致，崩溃未知窗必须有 intent；
- committed 后 retry 永远为 false；
- 跨 Credential attempt 必须 Portable，且旧 Lease 已释放；
- Generic request 与 Snapshot Set 在 retry 中保持相同 hash；
- 新 attempt 的 token/profile/egress/bundle epoch 与新 Lease 一致；
- deadline 单调减少，任何等待或 retry 都不延长；
- 持续 capacity release 下四级 DRR 无饥饿；
- 新建大量 Session/Agent 不获得历史 deficit 优势；
- PLAN 投影任意变化时，candidate set、排名和选择结果完全相同；
- stale generation 任意事件对新 runtime 零影响；
- 在每个阶段注入 cancel 后所有资源最终归零；
- 24 小时 soak 后 ticket、Lease、Claim、Reservation、buffer 和 timer 无持续增长。

### 30.3 Reader Check

- 为什么 Platform Key 并发满不排队？见第 9 章。
- 10 个 Agent 是一个还是十个调度单元？见第 3、17、18 章。
- Session Slot 开启后它限制什么？见第 19 章。
- 为什么不设置单 Session 并发上限？见第 17、19 章。
- preferred Credential 满载时等待多久？见第 20 章。
- 什么情况下跨 Credential？见第 20、21、25 章。
- 跨 Credential 是否丢失整个请求调整结果？见第 6、25 章。
- PLAN 会不会改变权重？见第 22、29 章。
- Key、Group、Credential 三层默认值是什么？见第 8、9、12、21 章。
- 三次 TLS 连接失败为什么不算三个 Messages Attempt？见第 24 章。
- 非流式为什么先拿 Reservation 再拿 Lease？见第 16 章。
- 客户端取消时 Lease 为什么可能稍后释放？见第 26 章。
- 进程重启后是否恢复排队请求？见第 28 章。
