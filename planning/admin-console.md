# Claude Code Gateway 管理控制台详细设计

> 状态：Detailed Design Baseline  
> 上位文档：[功能模块规划](./functional-modules.md)、[API 契约](./api-contract.md)、[领域模型](./domain-model.md)、[数据库设计](./database-schema.md)  
> 首版角色：Platform Admin、Key Owner

## 1. 文档目的与术语

本文冻结管理控制台的信息架构、角色、页面、表单、状态、动作确认、审批、导出和 API 依赖。控制台是管理 API 的客户端，不直接访问数据库、Secret Store、Transport 或 Browser context。

资源术语保持：User 拥有 Platform Key；Platform Key 固定绑定一个 Credential Group；Group 包含多个 Anthropic Credential；每个 Credential 拥有一个 Profile、Device Identity 和 Egress Binding；Archetype/Bundle 可以共享。

## 2. 首版范围与非目标

首版外部角色只有：

- `platform_admin`：平台、User、Key、Group、Credential、策略、安全和运维；
- `key_owner`：本人身份、本人 Key、本人请求/usage/导出。

首版无 Viewer、AccessSubject、应用主体、Tenant、自助注册、自定义 RBAC、Key 转移、Key 原位换 Group、Key secret 轮换、管理员密码/MFA 重置。需要换 owner、Group 或 secret 时创建新 Key，并按原 Key 生命周期处理。

## 3. 用户心智模型

```text
User
├─ Platform Key A ──固定──> Group X
└─ Platform Key B ──固定──> Group Y

Group X
├─ Credential 1 ──> Profile/Device/Egress
├─ Credential 2 ──> Profile/Device/Egress
└─ shared Archetype/Bundle/Proxy capacity
```

控制台必须区分：

- Key 限制与 Group/Credential 容量；
- Group persistent status 与实时 availability；
- Credential lifecycle/auth/capacity/transport 正交状态；
- Profile identity 与 Egress；
- PLAN 展示、Quota 调度压力和 Usage/Cost；
- 请求记录与 Content Audit 正文。

## 4. 应用壳与导航

Platform Admin 导航：

```text
首页
用户
Platform Key
Credential Group
Credential
Proxy / Egress
模型与能力
规则与治理
Archetype / Bundle
请求与用量
审批与内容审计
告警与通知
运维与系统
```

Key Owner 导航：

```text
首页
我的 Platform Key
我的请求与用量
我的导出
账号安全
```

顶部提供全局搜索、告警/Job、面包屑、当前角色、Session 和安全设置。隐藏路由只是体验裁剪，服务端始终再次授权。

## 5. RBAC、字段脱敏与范围

| 能力 | Platform Admin | Key Owner |
|---|---|---|
| 本人密码/MFA/Session | 是 | 是 |
| User 管理 | 是 | 隐藏/404 |
| Key | 任意 owner | 仅本人 |
| Group/Credential/Profile/Proxy | 是 | 隐藏/404 |
| Model/Artifact/Bundle | 是 | 隐藏/404 |
| Request/Usage | 全平台 | 本人全部 Key |
| 普通导出 | 全局/指定范围 | 服务端强制本人 |
| Credential/Attempt 内部字段 | 脱敏可见 | 不返回 |
| Content Audit metadata | 是 | 仅本人记录完整性摘要 |
| Content Audit Body | step-up + Case + 第二 Admin | 隐藏/404 |
| 高风险生产动作 | 双人审批 | 隐藏/404 |

Owner scope 必须绑定列表、filter、search、cursor、详情、聚合和导出；服务端固定其最大范围。越权 ID按当前角色范围内 404 响应，避免泄露存在性。

## 6. 登录、Session 与 CSRF

- 同源 UI 使用 `Secure; HttpOnly; SameSite=Strict` Session Cookie；
- 默认 idle 30 分钟、absolute 12 小时；
- 所有非 GET/HEAD 请求要求 `X-CSRF-Token`；
- 登录、密码、MFA、step-up 和 secret/material 响应都带 `Cache-Control: no-store`；
- 密码修改撤销其它 Session；User disable/locked/archived 使旧 Session 失效；
- 登录失败采用统一消息与独立限速；
- Session 临近 idle/absolute 到期时 UI 提前提醒，允许时可续期；
- Session 列表显示设备摘要、创建、最近活动、到期和当前标记，不显示 Cookie。

## 7. 首次初始化、User 创建与 MFA

空数据库首次启动要求环境变量：

```text
GATEWAY_BOOTSTRAP_ADMIN_USERNAME
GATEWAY_BOOTSTRAP_ADMIN_PASSWORD
```

缺失时实例保持 not-ready 并给出不含 secret 的配置诊断；不生成或打印随机管理密码。首次事务创建唯一初始 Admin，状态 `mfa_pending`、`password_change_required=true`。首次登录只能修改密码、绑定/确认 TOTP、查看本人状态和登出；完成后转 active。

普通 User 由 Admin 创建，状态 `invited`，使用一次性临时密码，首次登录同样完成改密与 TOTP。用户名和角色创建后只读。首版没有“忘记密码”、Admin 重置密码或 MFA 重绑入口；丢失时按离线运维恢复流程处理。

## 8. Step-up 与动作确认

Step-up 要求当前密码 + TOTP + 明确 purpose，默认有效 5 分钟。purpose 至少区分：

```text
key_secret_reveal
irreversible_lifecycle
content_audit_access
approval_decision
key_provider_change
backup_restore_security
bundle_activation
```

UI 显示用途和剩余时间。不同高风险域不可默认共享授权。服务端执行时仍检查当前 Session、role、resource revision、审批和动作 payload digest。

## 9. Platform Admin 首页

首页卡片与深链：

- 当前 Key/Group/Credential 并发、RPM、排队与 Reservation；
- Group available/degraded/unavailable；
- Credential active/pending/disabled/auth/transport/quota；
- 今日请求、成功率、平台 5xx、TTFT、流式并发；
- 今日/月 input/output/cache token 与 estimated API value；
- 5h/7d/model quota 高压 Credential；
- Proxy/Bundle/审计链/备份/通知状态；
- 当前 release、DB schema、active Bundle/Artifact 版本；
- 未确认 critical/high 告警、待审批、失败 Job、演练时效。

局部 Widget 失败不清空整页；显示数据时间、错误摘要和重试。实时容量是管理视图，不形成公开 Availability API。

## 10. Key Owner 首页

- 本人 Key 数量与 active/disabled/expired/revoked；
- 每个 Key 默认并发/RPM使用、到期和最近使用；
- 今日/月请求、token、estimated value；
- 最近请求错误和客户端类别观察；
- 即将到期、被禁用或模型范围受限的 Key；
- 导出 Job 和下载到期提醒。

所有深链携带 owner scope。首页不出现 Credential 数量、Profile、Proxy、单 Credential quota 或内部 attempt topology。

## 11. User 管理

列表字段：username、display name、email、role、status、Key 总数/active 数、最后登录、创建/更新时间。筛选 q、role、status、时间。

动作：创建、修改 display name/email、disable、reactivate、unlock、撤销全部 Session、archive。规则：

- disable 先展示名下 Key 数量与影响；确认后同步禁用 Key；
- reactivate User 不自动恢复 Key；
- archive 前必须 User 已 disabled 且全部 Key revoked；
- username/role 保持只读；
- 锁定是登录安全状态，不等价于业务 disable；
- 所有 lifecycle action要求 reason、If-Match、Idempotency-Key。

## 12. Platform Key 列表与创建

列表：name、ID/prefix、owner、Group、status/expiry、endpoint permission、model scope、并发、Messages/Models RPM、IP allowlist摘要、请求/usage、最后使用、观察到的客户端类别。

创建默认：

| 字段 | 默认 |
|---|---|
| endpoint | messages + models |
| concurrency | 5 |
| Messages RPM/burst | 60/10 |
| Models RPM/burst | 60/10 |
| model scope | inherit Group |
| expires at | null |
| IP allowlist | empty |
| content audit request | metadata_only |

首版仅 Admin 创建 Key，并选择 owner 与固定 Group；Owner 只管理本人既有 Key 的名称、过期时间、生命周期与 secret reveal。表单没有客户端类型和 secret 自定义字段。创建完成只显示 prefix；完整 secret 通过独立 reveal 获取。

## 13. Platform Key 详情与 Secret Reveal

详情分三区：

1. 基础：ID/prefix、owner、Group、状态、时间；
2. 权限与限制：endpoint、model、body、RPM、并发、IP、RuleSet、audit；
3. 安全与生命周期：reveal、disable/reactivate/revoke、配置历史、审计、客户端配置。

owner、Group 与 secret ref 不可编辑；Key 不支持转移和轮换。reveal 流程：step-up → 填用途 → no-store response → 60 秒倒计时 → 允许复制 → 自动隐藏。前端持久存储、日志、analytics 与 crash report 全部排除 secret。

Credential token、Browser material、Proxy password、Device seed 与 Session HMAC 只有覆盖/使用，没有 reveal UI。

## 14. Group 列表与创建

列表：name/status、accepted client classes、Credential 总/可用/异常数、effective concurrency/queue、RPM、月 token/value、egress mode、模型范围、错误和最后成功。

创建仅名称必填，其余默认：

- 同时接受 `claude_code_cli`、`non_claude_code_cli`；
- `egress_mode=auto`；
- System `preserve`；
- Token Estimate `local_estimate`；
- Group concurrency/RPM unlimited；
- shared pre-upstream deadline 30s、queue capacity 2× effective concurrency；
- model scope `all_published`；
- Session Slot关闭；
- OAuth/Setup 主池，Console business fallback关闭；
- Content Audit policy `allow`，默认 effective metadata-only。

允许创建没有 Credential 的 Group，显示 persistent active / runtime unavailable，并引导添加 Credential。

## 15. Group 详情六页签

1. **概览**：persistent lifecycle、runtime serving、availability、容量、排队、健康趋势、错误、最近成功。
2. **Credential**：成员正交状态、添加、迁入/迁出、影响预览。
3. **调度与限流**：Group/Credential 并发与 RPM、队列、公平树、Session Slot、affinity、attempt、timeout。
4. **请求治理**：客户端类别、System 四模式、Probe/Background、RuleSet、Enforcement、Content Audit。
5. **能力与出口**：all_published/allowlist、内部 Token Estimate、auth pool、auto/proxy_required/direct、可选代理池。
6. **用量与审计**：token、estimated value、usage completeness、配置版本、diff、发布/回滚与操作审计。

配置修改先创建 immutable candidate，经 validate/simulate，再按 Shadow → Canary → Active 发布；相应页签提供版本抽屉。高风险变更进入双人审批。

## 16. Credential 运维列表

默认排序优先：manual recovery/auth broken → transport unavailable → pending profile/egress → quota/cooldown → disabled → active。字段：账号掩码、Group、auth kind、canonical status、lifecycle/auth/capacity/transport、blockers、PLAN、priority/weight/并发/RPM、5h/7d/model、maintenance、Egress、Archetype/Profile、最后成功/错误。

筛选：q、Group、status/substate、auth kind、management class、PLAN/freshness、egress/proxy、OS/Archetype、quota pressure、cooldown、maintenance、model compatibility。PLAN 筛选区固定显示“仅展示，不影响调度”。

## 17. Credential 创建与恢复向导

六步向导：

```text
1. 选择 Group / Create or Recover context
2. 选择 OAuth PKCE / Setup Token / Existing OAuth / Console API Key
3. 解析并冻结 Egress
4. 完成授权或提交材料
5. 验证账号、全局去重、自动 Profile/Device/Archetype
6. 配置 Reauth Strategy、展示 PLAN 初值并执行激活检查
```

每一步显示 Enrollment 状态、过期时间、可安全重试动作和取消。普通 Create 命中同账号时展示掩码既有 Credential/Group并结束，不自动重认证。`manual_recovery_required` 的详情页“恢复账号”打开同一向导，但 mode 为 Recover；只有验证同一账号才更新原对象。

Proxy pool为空且 Group auto 时明确显示“将使用稳定 Direct Binding”；proxy_required 无容量则显示等待 Egress，界面无临时直连按钮。OAuth/Browser 弹窗和 token exchange 均展示将使用的 Egress 摘要。

## 18. Credential 详情五页签

1. **概览**：canonical 状态、所有正交子状态、blockers、Group、认证、PLAN、Profile、Egress。
2. **用量与配额**：5h/7d/model、RPM、token 类别、estimated value、source/completeness。
3. **会话与调度**：Base Session/Agent、affinity、并发、排队、priority、weight、Session Slot。
4. **身份与传输**：掩码 Device、Archetype/Bundle、profile/device/egress epoch、出口、transport blocker。
5. **维护与审计**：refresh/reauth/PLAN operation、错误、迁组、重绑、cohort、Device rebuild、disable/revoke/archive。

恢复、Group 迁移、Egress rebind、cohort migration 和 Device rebuild 只在详情页发起。每个动作展示 before/after、epoch、旧连接 drain、在途请求与回滚语义。

## 19. Profile 与 Device Identity

Profile 独立页以只读诊断为主：Credential、Archetype/cohort、Bundle、application identity模板版本、profile/device epoch、掩码 Device ID、Session derivation version、Attribution requirement、证据与 drift。

Profile 没有自由编辑表单。变更只有：

- Archetype cohort migration；
- Egress rebind；
- Device Identity rebuild。

UI 明确：cohort 升级保留 Device/Session/Egress；rebind保留 Device但增加 profile+egress epoch；Device rebuild 增加 profile+device epoch且需要双人审批。Device seed、Session HMAC 与完整 ID不显示。

## 20. Proxy 与 Egress

Proxy 列表/详情显示 type、host/port、auth presence、allowed Groups、lifecycle、health、stability、活动绑定/上限、最近 probe、出口摘要和失败分类。

创建默认：dynamic、绑定上限 5、probe interval 60s、初始 `pending_check`，allowed Groups 默认全部。支持 CONNECT、CONNECT Basic、SOCKS5 local/remote DNS。密码只能提交/覆盖。

动作：probe、replace secret、disable/reactivate、drain/archive、查看 bindings。禁用 Proxy 不会把既有 Credential 自动切 direct；管理员需逐个/批次显式 rebind。空 Proxy 列表是合法状态，说明 auto Group使用 Direct。

Egress Binding 详情区分 `Direct|ProxyStatic|ProxyDynamic`。固定代表稳定 Binding，不保证每 Credential 独占公网 IP；Static 出口漂移是 blocker，Dynamic/Direct 漂移记录审计。

## 21. Model Catalog

Model 状态：`discovered|reviewing|published|deprecated|disabled`。列表展示 ID、display name、发现时间/来源、能力版本、价格版本、授权 Group、近期请求、review overdue 与上游消失状态。

- 新模型自动发现后进入 reviewing，管理员确认官方能力和 evidence后 publish；
- `all_published` Group 自动获得新 published 模型；allowlist Group仍需显式加入；
- deprecated/disabled 不接受新请求；
- 已消失模型自动 disabled并通知管理员；再次出现重新进入 reviewing；
- 页面提供 Capability/Price diff、受影响 Group/Key和近期相关请求量。

模型 ID永远不是 RuleSet 自动改写目标。

## 22. Capability、Rule、Enforcement 与 Background Catalog

编辑器必须结构化：字段路径、typed value、条件、互斥、动作、scope、版本、来源和风险。无任意脚本执行，也没有通用 Artifact JSON 写入入口。

页面能力：

- Capability：模型字段/条件、样本验证、路径展开、冲突 review；
- RuleSet：before/after diff、sample simulate、Shadow/Canary；
- Group Enforcement：不可下调锁、System preserve/strip_client/replace/strip_all、Content Audit；
- Probe/Background Catalog：模板、client/version scope、动态字段安全目录、唯一性、7日 Shadow与命中样本；
- Price：模型输入/输出/cache单价、currency、生效版本。

System strip_all、replace、Enforcement 放宽、Probe/Background throttle/reject、全文策略变更均显示高风险预览并进入双人审批。

## 23. Environment Archetype 与 Transport Bundle

Archetype 页展示 OS/build、arch、runtime/client version、capture cohort、应用身份、TLS/H1/H2 evidence、Bundle、Credential 引用、生命周期和 blocker。

Bundle 页展示 schema/ABI、canonical hash、signer、min/max Engine build、target、protocol、evidence manifest/report、runtime quarantined、Canary cohort与回滚链。

明确展示三种状态：artifact lifecycle、active pointer、runtime loadability。当前 Windows 2.1.241 H1 为 `lifecycle=verified` 且 evidence gate 已通过（ReadyForCanary），尚未进入 `canary`；macOS/Linux evidence 待补时只禁用对应 promote/activate 按钮，不阻塞其它管理功能。生产拓扑图说明 Linux 单进程加载签名 Bundle，不要求生产三 OS。

## 24. PLAN 与 PLAN Mapping

Credential PLAN 展示 raw summary、normalized plan、billing mode、source adapter/version、mapping version、confidence、observed/normalized/last attempt时间、fresh/stale/unknown/not_applicable和失败分类。

PLAN Mapping 是 typed immutable Artifact：创建候选、用已保存 raw 做 diff/重算、validate、activate、rollback。发布不访问 Anthropic，auth/transport/capacity状态保持原值。所有 PLAN 视图固定显示“仅展示；不参与调度、限流、权重、资格或路由”。

## 25. 请求与用量

同一导航下两个视图：

- **请求明细**：Request、ConnectionAttempt、Messages Attempt、响应交付和错误；
- **聚合分析**：按时间/User/Key/Group/Credential/Admin-only/model/client/status聚合 usage/cost/latency。

共享时间范围与主要筛选。Request 列表：ID、User、Key、Group、client class、model、stream、status、时间、attempt 数、input/output/cache token、estimated amount、completeness。Admin 可展开脱敏 Credential、Archetype/Profile/Egress/Bundle、cross-Credential switch与内部分类；Owner 隐藏这些字段。

请求详情使用一条时间线：Gate → Queue/Reservation/Lease → ConnectionAttempt → Messages Attempt → Response/Delivery。零上游字节的 ConnectionAttempt 与真实 Messages Attempt分开展示。

## 26. Usage、Cost 与导出

usage source 与 completeness 分列：

```text
source: official | local_estimate | console_count | cancel_estimate
completeness: complete | partial | unknown
```

partial/unknown 显示“部分/未知”，不用 0 填充。取消估算与后来到达的官方 complete 同时保留差异审计。所有订阅 Credential 金额显示为 `estimated_api_value`，附 Price Snapshot/version/currency，避免被理解成实际订阅账单。

导出：当前筛选为默认；聚合 CSV，请求明细 CSV/JSONL。预计 ≤10,000 行同步，否则异步 Job；产物加密、默认 24 小时、短时一次性 URL。Owner 强制本人 scope，Admin可选全局。普通导出不包含 Content Audit Body。

## 27. 审批、Content Audit 与管理审计

审批中心分“待我审批”“我发起”“已完成”。Case 显示 kind、target、before/after、payload digest、resource revision、理由、发起人、过期和执行状态；发起人与批准人必须不同且均为 active Admin，批准时需要 step-up。

Content Audit 模型：

```text
Key requested mode: metadata_only | full_encrypted
Group policy: allow | require | forbid
effective:
  allow   → Key request决定，默认 metadata_only
  require → full_encrypted
  forbid  → metadata_only
```

全文启用、Group require/forbid、脱敏放宽、续期、正文检索/读取/导出、Legal Hold、手工删除均需两名 Admin。Key grant默认 7 天、单次最长 30 天；正文默认留存 7 天、Group 可配 1–365 天。

独立 Audit Case 授权短时 search session；每次解密读取再次审计。管理审计为 append-only hash chain视图，支持 actor/action/resource/time/result搜索，不显示 secret或正文。

## 28. 告警、静默与通知

Alert Center 显示 severity、state、rule、对象、首次/最近、次数、证据、建议与关联 Job/Request。动作：acknowledge、resolve、创建/结束维护静默。静默只抑制通知投递，不隐藏事件或改变健康。

站内通知始终启用；外部渠道支持 SMTP、HMAC Webhook、Server酱3。配置显示 secret presence、scope、severity、启停、测试结果、最近投递与 dead letter；secret 只可覆盖。

通知由 transactional outbox驱动，默认退避 1/5/15/30分钟；同对象/规则/状态在窗口内聚合，恢复时发送 recovery。渠道失败不会回滚业务动作，最终进入待处理告警。

## 29. 运维、系统设置与后台任务

页面：

- 实例：版本、uptime、readiness、capacity、buffer/Reservation、SLO；
- 配置收敛：Active Pointer、各 executor generation、失败对象；
- Job：type/state/progress、逐项结果、重试/取消；
- 备份：WAL、baseline、manifest、仓库、最近成功、完整性；
- 恢复演练：历史、RPO/RTO、链根/Deletion Ledger、隔离环境销毁；
- 升级：release签名/hash、compatibility、migration、drain、self-test、rollback；
- KeyProvider：健康、版本、轮换状态；
- 审计链：head、seal、验证、gap；
- 通知/邮件/Webhook测试。

生产 restore只展示 runbook和预检结果，没有在线覆盖数据库动作。审计链异常时高风险管理动作 fail-closed，现有数据面继续服务并产生 critical 告警。

## 30. 共享交互、API 映射、可访问性与测试

### 30.1 列表、状态与错误

- cursor分页默认20、最大100；稳定排序追加 ID；无 offset；
- q 最大128字符，最多3个排序字段，IN最多100；
- 不计算精确 total时显示“已加载 N 项”；
- 初始空态、筛选空态、权限不可见三种体验分开；
- 401重新登录，403提示权限/step-up，404不泄露，409展示revision diff，422字段/状态错误，428补条件写，429倒计时，503显示关键依赖；
- 状态使用文本+图标+颜色，绝对时间可附相对时间。

### 30.2 主要 API 映射

| 页面 | API 族 |
|---|---|
| Auth/User | `/auth/*`、`/users*` |
| Key | `/platform-keys*` |
| Group | `/groups*`、config versions/actions |
| Credential | `/credentials*`、`/credential-enrollments*`、maintenance actions |
| Profile/Egress/Proxy | `/credential-profiles*`、`/egress-bindings*`、`/proxies*` |
| Model/Rules | `/models*`、capability/ruleset/enforcement/background/price versions |
| Archetype/Bundle | `/environment-archetypes*`、`/transport-bundles*` |
| Request/Usage/Export | `/requests*`、`/usage/*`、`/exports*` |
| Approval/Audit | `/approval-cases*`、`/content-audit/*`、`/audit-events` |
| Alert/Ops | `/alerts*`、`/alert-silences*`、`/notifications*`、`/operations/*` |

dashboard、全局 audit、alert silence、站内 inbox、PLAN Mapping、Profile 集合、系统状态、备份/演练历史和 Legal Hold typed routes 已冻结在 API 契约中；实现与 UI 路由必须逐项通过合同测试。

### 30.3 可访问性

目标 WCAG 2.2 AA：全键盘、skip link、可见焦点、dialog focus trap/恢复、显式 label、error summary、aria-live、状态非颜色唯一表达、图表文本摘要/数据表、表格 caption/排序状态、200% zoom、窄屏、reduced motion。Secret 倒计时与复制结果提供文本通知，但屏幕阅读器不自动朗读 secret。

### 30.4 测试与 Reader Check

测试覆盖 RBAC/越权/字段/filter/cursor/export、首次初始化、Session/CSRF、step-up purpose、ETag/幂等、双人审批、secret 泄漏、所有状态机、Group六页签、Credential五页签、PLAN零调度影响、usage completeness、10,000导出边界、空/错态、a11y与OpenAPI契约。

读者应能回答：首版角色；Owner 数据范围；Key 是否可转移；客户端类型配置位置；PLAN 影响；空 Proxy 行为；初始化流程；step-up与双审批差异；Group/Credential页签；请求与usage为何合并；secret再次复制范围；Owner导出；Content Audit查看；生产restore入口；Windows/macOS/Linux证据如何展示。
