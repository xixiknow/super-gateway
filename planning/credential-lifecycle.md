# Claude Code Gateway Credential 生命周期详细设计

> 状态：Detailed Design Baseline  
> 上位文档：[功能模块规划](./functional-modules.md)、[技术架构](./technical-architecture.md)、[领域模型](./domain-model.md)、[数据库设计](./database-schema.md)、[API 契约](./api-contract.md)  
> 重点：Claude Code 订阅 OAuth/Setup Token 是首版主凭据，Console API Key 是受控兼容类型

## 1. 文档目的与权威顺序

本文冻结 Credential 从添加、验证、全局去重、Profile/Egress 初始化，到 refresh、静默重认证、人工恢复、迁移和终态清理的完整合同。

上位决策优先级为：功能规划 → 技术架构 → 领域模型 → 数据库设计 → API 契约 → 本文实现细节。本文对已发现空白作出可实现裁决；涉及客户端合同的部分同步回写 API 契约，涉及物理结构的部分列入数据库修订清单。

## 2. 首版范围与非目标

首版认证类型：

- Claude Code 订阅 OAuth PKCE；
- Setup Token 作为一次性 bootstrap；交换结果进入 `setup_token_subscription` 自身的 token-version 与 refresh 生命周期，只有显式的同账号认证迁移才会改变 auth kind；
- 已有 OAuth material 导入；
- Console API Key，可用于内部 Count Tokens，也可在 Group 显式启用后进入业务 fallback 池。

首版边界：

- 普通新增流程遇到全平台同账号时只提示既有对象，既不重复创建，也不自动重认证；
- 同账号恢复必须从原 `ManualRecoveryRequired` Credential 的恢复入口发起，可复用同一六步向导；
- 不同账号材料不会覆盖原 Credential；另走普通新增流程；
- PLAN 只展示；
- OAuth/Browser 自动维护不占 Messages RPM、Key 并发、Group 队列或业务 Lease；
- 多实例 Job 接管、跨实例 Credential owner 与商业计费留在演进范围。

## 3. 标识、Revision、Version、Epoch 与 Generation

| 名称 | 语义 |
|---|---|
| `CredentialId` | 平台内稳定对象 ID；同账号恢复保留 |
| `account_uuid` | Anthropic 稳定账号标识；全平台非空唯一 |
| `revision` | 聚合乐观并发版本，每次业务变更 +1 |
| `token_version` | 成功提交的新认证材料版本 |
| `profile_epoch` | Profile 可见/传输组合变更的池隔离世代 |
| `device_epoch` | Device Identity 重建世代 |
| `egress_epoch` | Egress 重绑世代 |
| `strategy_revision` | 自动重认证策略版本 |
| `operation_generation` | 防止迟到维护 Job 提交 |

时间持久化为 UTC；运行 deadline 使用单调时钟。Typed ID 不互换，secret reference 与业务 ID 也不共用类型。

## 4. 组件与所有权

```text
CredentialLifecycleService
├─ EnrollmentCoordinator
├─ AuthAdapterRegistry
├─ AccountVerifier
├─ GlobalDeduplicator
├─ ProfileProvisioner
├─ EgressBindingService
├─ ManagedBrowserService
├─ MaintenanceCoordinator
├─ PlanCollector
├─ QuotaProjector
├─ SecretStore / KeyProvider
└─ Audit + Outbox
```

- `CredentialLifecycleService` 单写持久聚合；
- `GroupExecutor` 只消费 Credential projection，停止/恢复新 Lease；
- 网络、OAuth、Browser 和 Proxy 工作发生在数据库事务之外；
- 提交候选结果时用 revision/token version/egress epoch/generation CAS；
- Auth Adapter 不选择 Group、Profile 或调度权重；
- Transport 只执行冻结 Egress，不拥有 token 生命周期。

## 5. 聚合关系

```text
CredentialEnrollment ── creates/recovers ──> AnthropicCredential
AnthropicCredential 1 ── N CredentialAuthVersion
AnthropicCredential 1 ── 1 CredentialProfile
CredentialProfile 1 ── 1 CredentialDeviceIdentity
CredentialProfile N ── 1 EnvironmentArchetypeVersion
CredentialProfile 1 ── 1 CredentialEgressBinding
AnthropicCredential 1 ── 0..N AutoReauthStrategy
AutoReauthStrategy 1 ── N ManagedBrowserMaterialVersion
AnthropicCredential 1 ── N CredentialMaintenanceOperation
AnthropicCredential 1 ── N PlanObservation / QuotaObservation
```

Enrollment、Maintenance Operation 和 Job 是过程聚合；Credential 是长期身份聚合；PLAN/Quota 是只读投影；secret 始终存于独立加密存储，通过 reference 关联。

`AutoReauthStrategy` 采用 0..N 建模，以支持未来按优先级增加策略；首版唯一允许启用的策略类型为 `managed_browser_session`。同一 Credential 同时最多有一个该类型的 active 策略，其他策略类型在对应合同发布前不得进入 active。

## 6. Secret 分类与最短明文生命周期

Secret 类型：Platform Key、Anthropic access/refresh token、Setup material、Console API Key、PKCE verifier、Browser Cookie/Storage、Proxy password、Device seed、Session HMAC、数据加密密钥。

通用合同：

- API 只在专属 submit/reveal/replace action 接受或返回 secret；
- 数据库业务表保存 ciphertext/ref、key id、version、digest，不保存 plaintext；
- 解密只在所属 operation 的受限内存完成；Debug/Display 固定 redact；
- 日志、trace、错误、Job payload/result、普通审计、导出均执行 secret scanner；
- 临时 PKCE、callback、提交材料在终态后安全销毁；
- CAS loser 的候选 token/Cookie 立即销毁；
- 历史 Attempt 只引用 token version，不依赖旧 secret 保留。

## 7. CredentialEnrollment 聚合

```rust
struct CredentialEnrollment {
    id: EnrollmentId,
    mode: EnrollmentMode, // Create | Recover
    target_group_id: GroupId,
    auth_method: EnrollmentAuthMethod,
    pending_credential_id: Option<CredentialId>,
    recovery_credential_id: Option<CredentialId>,
    expected_credential_revision: Option<Revision>,
    state: EnrollmentState,
    next_action: EnrollmentNextAction,
    egress_snapshot: Option<EgressBindingSnapshot>,
    pkce_state_digest: Option<KeyedDigest>,
    pkce_verifier_secret_id: Option<SecretId>,
    callback_nonce_digest: Option<KeyedDigest>,
    identified_account_uuid: Option<AnthropicAccountUuid>,
    material_secret_refs: Vec<SecretId>,
    attempt_count: u32,
    expires_at: DateTime<Utc>,
    revision: Revision,
}
```

状态：

```text
created → resolving_egress → awaiting_user_action
→ exchanging_material → verifying_account → deduplicating
→ provisioning_identity → configuring_reauth
→ activation_check → succeeded

any non-terminal → cancelled | expired | failed
recover mode includes recovering_existing
```

`next_action` 为闭集：`wait_for_egress|open_authorization_url|submit_setup_material|submit_existing_oauth_material|complete_oauth_callback|complete_browser_login|retry|manual_recovery|none`。

Enrollment 默认 TTL 30 分钟；OAuth callback 一次性 code 接受窗默认 10 分钟，且不超过 Enrollment TTL。均可由管理员在系统安全范围内配置。

## 8. 普通新增账号总流程

```text
选择 Group 与 auth method
→ 创建 Enrollment + pending Credential
→ 按 Group egress policy 建稳定 Binding
→ 用冻结 Egress 完成授权/token/account verification
→ 取得 account_uuid
→ 全平台去重
→ 创建 Device Identity + 分配 Archetype + Profile
→ 配置 AutoReauthStrategy / PLAN adapter
→ 激活检查
→ Active
```

创建 pending Credential 的目的，是为 Egress、secret 和审计提供稳定 owner；它在全局去重失败时整对象清理，不进入业务候选。一个步骤失败时向 API 返回 typed `next_action`，管理员可在 TTL 内重试；取消/过期销毁临时材料、Browser context 和未提交的 Egress 预分配。

## 9. OAuth PKCE

流程：

1. 生成高强度 `state`、PKCE verifier、S256 challenge 和 callback nonce；
2. verifier 加密保存，state/nonce 保存 keyed digest；
3. authorization URL 绑定 Enrollment、redirect URI、challenge 与冻结 Egress；
4. callback 同时验证 Enrollment、state、nonce、过期、revision、未消费；
5. 一次性消费 callback；
6. 通过同一 Egress 交换 token并验证账号；
7. 成功候选进入去重/CAS，失败或重放销毁材料。

任何 callback mismatch、重复消费、过期或取消都形成安全审计。token endpoint 的 429/5xx 使用维护域退避，不复用 Messages retry budget。

## 10. Setup Token

Setup Token 在首版被定义为 bootstrap material：

- 管理员在专属 no-store action 提交；
- Adapter 通过冻结 Egress 交换/验证为 `CredentialAuthVersion`；
- 若返回 access + refresh，则复用 OAuth 相同的 refresh/CAS 维护机制，但 Credential 的 auth kind 仍为 `setup_token_subscription`；
- Setup Token 原文在交换终态后销毁，不作为长期刷新凭据；
- 若上游只返回不可自动刷新的 access material，则 management class 为 `NonManaged`；
- `fully_managed_required=true` 的 Group 会让该 Credential 停在 `PendingReauthStrategy`，直至具备健康策略。

PLAN adapter 固定为 `claude_cli_bootstrap`，失败时不跨用 `oauth_profile` adapter。

## 11. Existing OAuth Material

只接受 typed one-of：

```rust
enum SubmittedAuthMaterial {
    OAuthTokens {
        access: SecretRef,
        refresh: Option<SecretRef>,
        expires_at: Option<DateTime<Utc>>,
    },
    BrowserSessionImport {
        cookie_jar: SecretRef,
        web_storage: Option<SecretRef>,
    },
}
```

导入后仍须通过冻结 Egress 调用账号验证，取得可信 account UUID。access/refresh 没有健康自动重认证策略时标记 `NonManaged`；Browser material 导入要建立 Credential 独占 context，并验证网页登录账号与 token 账号一致。

任意自由组合 JSON、未知 secret 字段或账号验证失败都停留在 Enrollment 失败态，不进入 Active。

## 12. Console API Key

Console API Key 是独立认证种类：

- `purpose=count_tokens` 时只进入内部 Token Estimate Service；
- `purpose=business` 时只有 Group 显式启用 Console fallback 才具备候选资格；
- PLAN 为 `not_applicable`，billing mode 展示 `api_payg`；
- 默认同样拥有 Profile、Device Identity 与 Egress Binding；
- API Key material 只可覆盖，常规管理接口没有 reveal；
- Count Tokens 独立默认 60 RPM，不占 Platform Key 或 Messages 资源。

## 13. Egress 预分配与冻结

每个 Credential 始终有一条 Binding；未使用代理表达为 `Direct` Binding，而非 Binding 缺失。

Group policy：

- `auto`：从允许且健康的 Proxy 中选择 `active_bindings/max_active_bindings` 最小者，比例相同时以稳定 Proxy ID 决胜；无容量时创建稳定 Direct Binding；
- `proxy_required`：无健康容量时 Enrollment 停在 `wait_for_egress`；
- `direct`：直接创建 Direct Binding；
- 一个 Proxy 默认最多 5 个活动 Credential Binding，无 Proxy 级总请求并发/RPM。

以下全链路冻结 `egress_binding_id + egress_epoch`：authorization、browser consent、code exchange、account verification、Profile bootstrap、refresh、silent reauth、manual recovery。Proxy 临时故障进入 `WaitingEgress`；原 Binding 不临时切 direct、公共代理或其它 Credential 代理。

运行中 Egress rebind 时，旧 epoch operation 的提交 CAS 失败，候选 secret 作废；新 operation 从新 Binding 重新开始。

## 14. Account UUID 与全局去重

网络验证完成后再进入短事务：

```text
BEGIN
lock Enrollment/pending Credential; verify revision/TTL/state
lookup account_uuid across all Groups and lifecycle states

Create mode, no match:
    conditionally set account_uuid
    global unique index decides concurrent winner

Create mode, match:
    Enrollment → failed(credential_account_exists)
    clean pending object/material
    return 409 + masked existing Credential reference

Recover mode, match == recovery_credential_id
and original is ManualRecoveryRequired:
    lock original and enter recovering_existing

all other recovery matches:
    discard candidate material; retain original state

write Audit + Outbox
COMMIT
```

两个并发新增流程都可先完成外部验证，但唯一索引只有一个赢家；败者不得把 unique conflict 转为隐式 reauth。Archived 继续占用 account UUID，防止已终结身份被当成新账号悄然复活；重新接入须在 revoke/archive 前通过原 Credential 恢复。

## 15. Device、Archetype 与 Profile 自动实例化

去重成功后自动执行：

1. 生成 Credential 唯一 Device/client ID、Profile seed 与 Session HMAC；
2. 从兼容、Active、有容量的 Archetype 中做确定性加权分配；
3. 创建一对一 Credential Profile；
4. 关联已冻结 Egress Binding；
5. 验证 Bundle 在当前 Rust Engine 可装载；
6. 根据 Group 的 System Attribution 与 management class 做兼容检查；
7. 进入 activation check。

无需逐 Credential 人工采集。100 个 Credential 可以共享有限 Archetype/Bundle，但 Device ID、Profile seed、Session HMAC、Browser context 和 Egress Binding 均逐 Credential 唯一。

## 16. Managed Browser Session 初次建档

每个 fully managed Credential 可建立独占 Auto Reauth Strategy：

```text
Pending → Healthy ↔ Degraded → Invalid
                      └→ Disabled
```

独占内容包括 browser profile/context、Cookie Jar 全属性、必要 Local/Session Storage、browser adapter/version、material active pointer、临时目录与认证连接。Browser identity 与 Messages Profile 分开建模，但使用同一固定 Egress。

初次建档允许管理员完成一次交互登录。以后 silent authorize 全自动运行。任何新 `Set-Cookie`/Storage 都创建新 material version；只有 token、账号验证和策略 CAS 同时成功时才推进 active pointer。

## 17. 激活检查与状态投影

Credential 只有同时满足以下条件才进入业务候选：

- lifecycle 为 active、attachment 为 attached；
- account UUID 已验证且全局唯一；
- auth material 当前可用；
- Group 需要时 Auto Reauth Strategy 为 Healthy；
- Profile、Device、Archetype、Bundle active 且一致；
- Egress Binding 健康；
- purpose 与 Group auth pool 相容。

Canonical status 只用于 UI 摘要，投影顺序固定为 archived/revoked/disabled → pending → attachment → auth → transport → capacity → active。真实领域仍保留 lifecycle、attachment、auth、capacity、transport 五类正交状态和 `blockers[]`。

Management class：

```text
FullyManaged
NonManaged
PendingReauthStrategy
ManualRecoveryRequired
```

PLAN stale/unknown 与 Credential auth/transport 健康完全分离。

## 18. CredentialMaintenanceOperation

```rust
struct CredentialMaintenanceOperation {
    id: MaintenanceOperationId,
    credential_id: CredentialId,
    kind: MaintenanceKind,
    trigger: MaintenanceTrigger,
    conflict_class: ConflictClass,
    state: MaintenanceState,
    expected_revision: Revision,
    expected_token_version: u64,
    expected_egress: EgressBindingSnapshot,
    generation: u64,
    attempt_count: u32,
    next_retry_at: Option<DateTime<Utc>>,
    result_summary: RedactedResult,
}
```

闭集定义：

```text
MaintenanceKind = verify | refresh | reauthenticate | manual_recovery
                | auth_method_migration | plan_collect | browser_health
MaintenanceTrigger = enrollment | scheduled | expiry_guard | upstream_401
                   | admin | manual_recovery | strategy_health
ConflictClass = auth_material_write | plan_collect | browser_health
```

冲突域：

- `AuthMaterialWrite`：Refresh、Reauthenticate、ManualRecovery、AuthMethodMigration；
- `PlanCollect`：PLAN refresh；
- `BrowserHealth`：Browser material rotate/health check。

同 Credential、同冲突域 singleflight；PLAN 与 token refresh 可并行，因为写入版本和 CAS 字段不重叠。状态闭集为 `planned|leased|running|verifying_account|committing|waiting_backoff|waiting_egress|needs_attention|succeeded|failed|cancelled|expired`。

## 19. 提前 Refresh、401 Refresh 与 Messages Replay

提前 refresh 调度点：

```text
refresh_at = expires_at - clamp(token_lifetime × 10%, 5m, 4h) + bounded_jitter
```

管理员可调整比例、上下界和 jitter；任何结果都不得晚于 token 到期。提前 refresh 期间旧 access token 仍有效则继续承载流量。401 或 token 已失效时暂停新 Lease。

Refresh 状态：

```text
planned → running through frozen Egress → verifying_account
→ committing CAS → succeeded
                  ├→ waiting_backoff
                  ├→ waiting_egress
                  └→ failed
```

401 并发请求共享一次 refresh。refresh endpoint 调用只记 MaintenanceOperation。Messages 语义为：Attempt 1 → refresh → 同 Credential 新 token Attempt 2；第二次 401 标记认证异常，Portable 且仍有预算时 Attempt 3 可换其它 Credential。每次 Messages 提交独立记账。

## 20. Refresh 失效后的静默重认证

```text
refresh token invalid
→ 检查 Managed Browser Strategy Healthy
→ 冻结当前 Egress
→ 用当前 Cookie/Storage silent authorize
→ 网页登录态有效则自动完成 authorization/consent
→ exchange code
→ verify same account_uuid
→ CAS token + browser material version
→ Healthy
```

这不是在后台重新输入用户名密码，而是复用仍有效的网页登录 Session 完成新的授权/consent。绑定 Proxy 时整个浏览器和 token 链路走原 Proxy；Direct Binding 时直连。

页面一旦进入登录、验证码、账号选择、Passkey、TOTP 或 SSO，自动流程立即结束，Credential 进入 `ManualRecoveryRequired`、退出新 Lease并通知管理员。账号 UUID 不一致时新 token、Cookie 与 Storage 全部丢弃。

## 21. Manual Recovery

access、refresh 与 Managed Browser Session 全部失效后，系统停止自动处理。管理员在原 Credential 详情点击“恢复账号”，启动与新增账号相同的六步 UI，但 Enrollment mode 为 `Recover` 且绑定 `recovery_credential_id`。

- 验证为同 account UUID：原 Credential 更新 auth/browser strategy，保留 Credential ID、Group、Profile、Device、Session HMAC、Archetype、Egress、affinity、quota、usage 和审计；
- 验证为其它 account UUID：本次材料全部销毁，原 Credential 继续保持待恢复；新账号需另启 Create Enrollment；
- 从普通“新增账号”入口遇到同账号仍返回 409 提示，不自动切换为恢复；
- Recovery 不顺带迁移 Group 或重绑 Egress。

## 22. PLAN 采集与 Mapping

Adapter 固定映射：OAuth → `oauth_profile`；Setup bootstrap → `claude_cli_bootstrap`；Console API Key → `not_applicable/api_payg`。一个 Adapter 失败时保持该 Adapter 的失败结果，不尝试另一个接口。

- 默认每 24 小时采集；
- 最近成功不超过 48 小时为 fresh，超过为 stale；
- 从未成功或该类型不适用为 unknown/not_applicable；
- 一次失败保留最后成功 raw/normalized 值并记录 last failure；
- Mapping 是不可变 Artifact + Active Pointer；发布/回滚只对已保存 raw 幂等重算，不访问上游；
- PLAN 页面固定标识“仅展示”；候选、排序、并发、RPM、quota guard、路由结果对 PLAN 变化保持零影响。

## 23. Quota、Usage、Cost 与内部 Count Tokens

Quota 保存 5h、7d 和 model-specific window：utilization、reset、rate-limited-until、source、confidence、observed-at。调度压力取最大已知窗口，默认达到 95% 时停止新 Lease；过 reset 后由一条真实 Portable 请求 HalfOpen。TPM 首版只观察。

Usage：

```text
source = official | local_estimate | console_count | cancel_estimate
completeness = complete | partial | unknown
```

partial/unknown 保持原语义，不显示成 0。Cost 使用请求接受时冻结的 Price Snapshot；订阅 Credential 的金额字段称 `estimated_api_value`，表达按 token × 模型公开价格估算的 API 等价值，不代表订阅账单。

内部 Count Tokens 从同一 `GenericAdjustedRequest`/Snapshot 构造，可选 local estimate 或独立 Console API Key，默认内部 60 RPM。它没有北向路由，不占客户端 Key、Group queue、业务 Lease 或 Messages Attempt。

## 24. Credential Group 迁移

```text
Attached(source)
→ Draining(source,target,deadline)
→ Detached → Attaching(target) → Attached(target)
```

前置：target 存在且未归档、接受 auth class、fully-managed 门槛满足、配置 revision 已冻结、Credential 不在 revoke/archive 或其它 migration 中。

Begin 后 source GroupExecutor 停止发新 Lease；在途请求自然完成。默认 drain 最长 5 分钟。全部 Lease 归零后，一个事务更新 Group/attachment/migration、Audit、Outbox并清理 source affinity。ID、account、Profile、Device、Session secret、Egress、quota、usage 和所有 epoch 保持。

5 分钟到期仍有 Lease 时回滚迁移、恢复 source eligibility，并告警；不强制取消在途请求。失败 checkpoint 都回到 source。

## 25. Cohort、Egress 与 Device 变更

连续性矩阵：

| 操作 | Profile | Device | Egress | Epoch |
|---|---|---|---|---|
| access refresh | 保留 | 保留 | 保留 | 全保持 |
| 同账号 reauth/recovery | 保留 | 保留 | 保留 | 全保持 |
| Group 迁移 | 保留 | 保留 | 保留 | 全保持 |
| Archetype cohort 迁移 | 同 Profile | 保留 | 保留 | `profile_epoch + 1` |
| Egress rebind | 同 Profile | 保留 | 替换 | `profile_epoch + 1`、`egress_epoch + 1` |
| Device rebuild | 同 Profile | 重建 | 保留 | `profile_epoch + 1`、`device_epoch + 1` |
| 不同账号 | 新 Profile | 新 | 新 | 新对象 |

Egress rebind 增加 profile epoch 的目的只是强制完整 PoolKey 失效，不表示 Device Identity 改变。上述三类显式变更都需审计；Device rebuild 还需双人审批。旧 Pool 进入 drain，新请求只使用新 epoch。

## 26. Disable、Reactivate、Revoke 与 Archive

```text
pending_* → active
active ↔ disabled
pending_*/active/disabled → revoked
disabled/revoked → archived
archived terminal
```

- Disable：立即停止新 Lease，已开始请求自然完成；自动 refresh/PLAN/browser health可继续，但成功后仍保持 disabled；
- Reactivate：重新验证 auth、management class、Profile/Bundle/Egress 与 Group attachment，全部满足才回 active；
- Revoke：终态停止新 Lease，已开始请求自然完成；排空维护操作后销毁可用 auth/browser secret，不调用未经确认的上游 revocation；
- Archive：只允许 disabled 或 revoked、零 Lease、零运行维护、零迁移时执行；终态、只保留法定/审计所需脱敏事实；
- Archived 保留 account UUID 唯一占位，避免身份重建绕过历史；
- 所有动作要求 reason、If-Match、Idempotency-Key，并在同事务写 Audit/Outbox。

## 27. Singleflight、CAS、锁序与 Timer

```rust
async fn maintain(key: (CredentialId, ConflictClass), trigger: Trigger) {
    singleflight.do(key, async move {
        let snapshot = repo.load_snapshot().await?;
        let op = repo.create_or_get_operation(snapshot, trigger).await?;
        let candidate = adapter.execute_bounded(op.egress_snapshot).await?;
        verify_account(candidate.account_uuid, snapshot.account_uuid)?;
        repo.commit_candidate_cas(op, candidate).await
    }).await
}
```

等待者取消只结束自身等待，共享 worker 使用独立 timeout。singleflight 解决进程内合并，持久 Operation、partial unique index 与 CAS 解决重启/并发 worker。数据库事务内禁止等待网络或 Browser。

统一锁序：Credential → Enrollment/Operation → Auth active pointer → Browser strategy/material pointer → Profile/Egress pointer → Audit/Outbox。CAS 至少校验 lifecycle、account UUID、expected token version、Credential revision、egress binding/epoch 和 operation generation。

Timer 默认：PLAN 24h、freshness 48h、Group drain 5m、Proxy health 60s且连续两次完整成功恢复、429 cooldown 60/120/300/900s且单次不超过 15m、Enrollment 30m、callback 10m。维护网络退避默认 30s/2m/10m/30m并施加 bounded jitter；可配置最大总时长。Durable Job 默认 lease 60s、heartbeat 20s。

## 28. 失败、审计与可观测性

| 失败 | 聚合结果 |
|---|---|
| callback state/nonce mismatch、replay | Enrollment failed，销毁临时 secret，安全告警 |
| 缺失/畸形 material | 可重试 field error 或终止，不激活 Credential |
| Egress unavailable | WaitingEgress，保持原 Binding |
| Auth endpoint 429 | WaitingBackoff，尊重可信 Retry-After |
| 5xx/瞬时网络 | 有界退避，ReauthRetrying |
| refresh invalid | Healthy Browser 时 silent reauth，否则 ManualRecoveryRequired |
| Browser login/OTP/chooser/Passkey/TOTP/SSO | ManualRecoveryRequired |
| account mismatch | 丢弃全部候选材料，critical alert |
| CAS/revision/epoch conflict | 丢弃候选，重读最新状态 |
| PLAN 失败 | 保留 last success，只产生 PLAN warning |
| Proxy/TLS/Bundle 故障 | transport blocker，auth 状态保持 |
| SecretStore/KeyProvider 写失败 | 无 active pointer commit，operation failed |

审计记录 Enrollment/Operation 状态、触发器、账号掩码、adapter/version、Egress epoch、token version、Profile epoch、结果分类、管理员动作与 outbox delivery；不含 token/Cookie/verifier/password。指标采用受控标签，具体 Credential/Enrollment ID进入日志/trace。

## 29. 竞态、不变量与测试

关键竞态：同账号双 Enrollment、Create 与 Recover 竞争、定时/401/管理员 refresh并发、refresh 与 silent reauth、Browser rotate 与 token commit、Egress rebind 与 auth operation、disable/revoke 与迟到 commit、Group drain 与 Lease grant、cancel/expire 与 callback、Job lease 被接管后旧 worker 迟到。

核心不变量：

1. 全平台非空 account UUID 唯一。
2. Create 重复永远是 409；Recover 只更新明确绑定的原 Credential。
3. 新 token 只有账号相同且所有 CAS 条件成立才激活。
4. 每个 Credential 恰有一个 Profile、Device 与 Egress Binding。
5. OAuth/Browser/account verification 全链路使用冻结 Egress。
6. refresh、同账号 recovery 和 Group 迁移保持 Device/Profile/Egress identity。
7. 每个 Credential 的 Browser context、Cookie、Storage、Session HMAC 和连接池隔离。
8. PLAN 变化对调度结果零影响。
9. Count Tokens 不产生外部路由、业务 Lease 或 Messages Attempt。
10. 每个 Enrollment/Operation 恰好一个终态，终态后临时 secret 已销毁。
11. 外部工作期间无数据库长事务。
12. Revoked/Archived 永远无调度资格。

必测场景包括 OAuth success/state mismatch/replay/cancel/expire；Setup bootstrap；NonManaged import；proxy_required 等待与 auto direct；同账号并发唯一赢家；silent reauth 经 Proxy/Direct；Browser 页面转人工；CAS loser；Egress epoch 变化；迁移成功/超时回滚；PLAN freshness 与 mapping；Count Tokens 内外边界；重启后的 Job/cooldown；全链路 secret 扫描。

## 30. Reader Check 与实现准入

- Enrollment 为什么独立于 Credential？见第 7 章。
- Egress 在授权前还是授权后确定？见第 8、13 章。
- 普通重复账号与恢复如何区分？见第 14、21 章。
- Setup Token 后续如何 refresh？见第 10、19 章。
- refresh token 失效但 Browser Session 有效时做什么？见第 20 章。
- 何时需要管理员重新登录？见第 20、21 章。
- 未配置 Proxy 时是否仍有 Egress Binding？见第 13 章。
- 同账号恢复保留哪些身份？见第 21、25 章。
- PLAN 与 quota 为什么分离？见第 22、23 章。
- Group 迁移超时是否取消在途请求？见第 24 章。
- Egress rebind 为什么同时增加 profile epoch？见第 25 章。
- revoke 后 secret 如何处理？见第 26 章。
- singleflight 与 CAS 各解决什么？见第 27 章。

实现开始前的合同闭环已同步至领域模型、数据库与 API 契约：Enrollment 持久表与领域聚合、统一 Maintenance kind/state/trigger、recovery 例外、Browser Strategy、PLAN Mapping typed API、Proxy archived 状态，以及拆分后的 Usage source/completeness。实现阶段须以这些冻结定义为准；它们不依赖 macOS/Linux 外部采集。
