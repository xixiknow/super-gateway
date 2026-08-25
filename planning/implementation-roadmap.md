# Claude Code Gateway 实施路线图

> 状态：Active Implementation Baseline  
> 当前进度（2026-08-25）：R0/R1 与 196 个管理端后端路由已在本地闭合；R3 的 Background/Enforcement 发布与数据面、R4 的动态 Group owner 装配以及 R5/R7 核心链路已形成可运行闭环；PostgreSQL 18.3 空库与 R2/R4/R5/R7/R8/R9 集成路径已实际通过；R2/R6/R9 仍有 KMS、Linux 原生、真实 Provider、N-1/N-2 与恢复演练等外部执行证据；R10 本地回归不代表 RC 或 GA  
> 首版原则：18 个模块全部实现；可选能力通过配置关闭，不通过删减模块缩小范围

## 1. 路线图目标

本路线图把已完成的产品、架构、领域、数据库、API和专项详细设计转换为可交付的实施顺序。每个Phase同时交付代码、migration、test、telemetry、runbook和evidence；语义变化先回写合同。

未来实施Phase编号使用`R0..R10`，避免与当前“规划第1–9步”混淆。

## 2. 全局退出条件

首版GA必须同时满足：

- 18模块trace ledger全部绿色；
- API/OpenAPI、Domain、DB、UI无未归属合同；
- Body/SSE golden 100%；
- Scheduler/Credential/Transport资源与身份不变量通过；
- Platform Key、Token、Cookie、Proxy secret等泄漏扫描为零；
- Linux生产样式性能/SLO与24h soak；
- 最近45天内成功隔离恢复演练；
- 所有被标为Active的Archetype各自拥有完整evidence；
- 无未处置critical安全、数据完整性或P0缺陷。

## 3. R0 合同修订与追踪冻结

范围：在写Rust前消除跨文档差异并形成机器可读trace ledger。

必须闭合：

- CredentialEnrollment领域聚合与物理表；
- Maintenance kind/state/trigger；
- Create重复与Recover原对象的API差异；
- Managed Browser Strategy typed状态/动作；
- PLAN Mapping typed API；
- Proxy archived生命周期；
- Usage source与completeness；
- purpose-scoped step-up与Approval payload/revision/consumed字段；
- Content Audit统一术语与Legal Hold API；
- dashboard/global audit/alert silence/inbox/Profile集合/system/backup/restore历史API；
- bootstrap变量、migration路径和Audit ready语义。

并行轨：Domain/DB、API/OpenAPI、Admin IA、trace/evidence schema。

Exit：OpenAPI可生成；DB constraints完整；每个Requirement有owner/test/Phase；全文搜索无旧冲突术语；本轮规划文档交叉校验通过。

机器合同产物：

- [R0 机器合同说明](../contracts/README.md)；
- [数据面 OpenAPI](../contracts/openapi/data-plane.openapi.json) 与 [管理面 OpenAPI](../contracts/openapi/admin.openapi.json)；
- `contracts/schemas/` 下的领域、Trace Event、Transport Bundle Manifest 与追踪账本 Schema；
- [Requirement Trace Ledger](../contracts/traceability/requirements.json)，覆盖 18 个功能模块与 DEC-001 至 DEC-132；
- `python tools/generate_contracts.py` 确定性生成，`python tools/validate_contracts.py` 执行双向一致性检查。

## 4. R1 工程骨架与验证底座

范围：Cargo workspace、composition root、配置、health/ready、structured logging、testkit、CI evidence manifest、release provenance。

生产 crate 结构以技术架构为准：`gateway-domain`、`gateway-policy`、`gateway-scheduler`、`gateway-transport`、`gateway-storage`、`gateway-services`、`gateway-api`、`gateway-testkit` 与唯一二进制 `super-gatewayd`。Credential、Security 与 Ops 首版作为 `gateway-services` 的内部模块，只有出现独立编译或依赖隔离需求时才通过架构评审拆分。

并行：CI/reproducible build、testkit fake Anthropic/Proxy/Clock/DB、configuration/health、evidence manifest。

Exit：空业务骨架在Linux x86_64/arm64构建；health/ready合同通过；固定时钟与合成fixture可运行；每个artifact有hash/SBOM/provenance。

## 5. R2 数据库与安全根基

第一批：User/Session/MFA/StepUp、Platform Key/envelope/digest、Idempotency、Config Artifact/Active Pointer、Audit/Outbox、Job。第二批：Group/Credential/Enrollment/AuthVersion/Profile/Device/Egress/Proxy/Model/Bundle/Request/Attempt/Usage/Content。

并行：Schema/migration、repository、KeyProvider/AEAD、Audit chain/Seal、backup manifest。

Exit：空库与前两个release升级；constraints/CAS/lock order；secret envelope与rotation；Audit/Outbox transaction；Enrollment表；备份manifest可恢复。

## 6. R3 Edge、Access、Capability 与 Policy

覆盖模块01–08：四条路由、Key认证、IP/permission、framing/body、client/session/probe分类、Capability、Group Enforcement、RuleSet、GenericAdjustedRequest。

并行：HTTP handler；pure Policy/Capability engine；golden/fuzz corpus；OpenAPI管理基础。

Exit：API contract/golden/fuzz通过；Count Tokens北向未知；System四模式；模型保持；unknown扩展保留/Pin；Platform Key/Gateway/原client身份零南向泄漏。

## 7. R4 GroupExecutor 与 Scheduler

覆盖模块03、09、10、13：owner generation、Key/Group/Credential RPM/并发、四级DRR、queue、Session/Agent、optional slot、affinity、eligibility、Lease、retry decision、cancel/resource ledger。

并行：reference model/property test；actor runtime；virtual time/fault injection。

Exit：20关键场景；3 Credential×并发5，10 Platform Key×每Key 4请求；main+9 subagent；零饥饿/泄漏；旧generation零影响；attempt/deadline合同通过。

## 8. R5 Credential、Profile 与 Egress

覆盖模块09、11、17、18：Enrollment、OAuth/Setup/import/Console、全局去重、refresh/silent reauth/manual recovery、PLAN/quota、Profile/Device/Session、Proxy/direct、迁组/rebind/cohort/device、lifecycle。

并行：pure lifecycle/adapter；OAuth/Browser；Profile derivation；Proxy/Egress；Admin API projection。

Exit：账号唯一/CAS loser；20并发401 singleflight；固定Egress；Browser隔离；PLAN零调度影响；recovery/迁移；all secrets扫描通过。

## 9. R6 Transport 生产化

将现有POC提升为`gateway-transport`：BoringSSL、Bundle TrustStore/Compiler/Catalog、完整PoolKey、H1/H2 engine、direct/CONNECT/SOCKS5、ConnectionAttempt、cancel/disposition、health。

依赖R1/R5接口。Windows Bundle lane与Linux Core生产门禁并行。

Exit：Linux x86_64/arm64 native、sanitizer、RustSec/license/SBOM、RSS/heap；Windows H1 exact保持；Pool隔离、Proxy、cancel matrix；未知capability fail-closed。H2/resumption无evidence时保持配置关闭且管理面可解释。

## 10. R7 Response、Usage 与 Observability

覆盖模块13–15：SSE relay、non-stream buffer/encrypted spill、commit、client delivery、usage source/completeness、cancel estimate、cost/quota、Request timeline、metrics/trace/alert events。

可先接fake Transport，与R5/R6部分并行。

Exit：Body/SSE 100% golden；8/64MiB、1MiB背压、2GiB Reservation；cancel/commit竞态；Header隐私；partial/unknown保真；SLO instrumentation完整。

## 11. R8 Admin Console 与完整管理 API

覆盖模块16并为全部模块提供控制入口：Auth/User/Key、Group六页签、Credential五页签、Profile/Egress/Proxy、Model/Rule/Bundle、Request/Usage/Export、Approval/Content、Alert/Notification/Ops。

R2后即可并行开发UI shell、RBAC和typed clients，最终接各模块projection。

Exit：OpenAPI typed routes完整；RBAC/IDOR、ETag/幂等、secret、双审批；关键E2E；WCAG2.2AA；所有可选能力可见且具有安全关闭态。

## 12. R9 Security 与 Operations 收口

覆盖模块17–18：Content Audit、Legal Hold/Deletion Ledger、Audit Chain/Seal、Key rotation、Job/Outbox/通知、backup/PITR/restore、systemd upgrade/drain/rollback、incident runbook。

Exit：threat review；secret canary；审计篡改；Content latch/gap；RPO/RTO；restore lineage/Ledger replay；upgrade rollback；值班演练。

## 13. R10 集成、Canary 与 GA

全客户端/模块/wire/fault/perf/soak。发布层次：Bundle Canary → System Canary → Group/Key/Credential cohort扩大 → GA。

Exit：18模块trace绿色；24h soak；性能/SLO；最近恢复演练；Active Archetype evidence；零critical。某可选能力可处于“实现完整、配置关闭、激活证据待补”，状态不可为“模块缺席”。

## 14. 并行实施轨

```text
Contract/Trace: R0 ───────────────────────────────→ R10
Storage/Security:    R1 → R2 ───────────────→ R9
Data Plane:               R3 → R4 → R7 ─────→ R10
Identity/Transport:             R5 → R6 ─────→ R10
Control Plane:             R2 → R8 ──────────→ R10
Verification:     every phase ships tests/evidence ─→ R10
```

跨轨接口用domain types与contract test冻结；数据面不直接依赖Admin UI，Transport不拥有Scheduler/Credential状态。

## 15. 外部 Evidence 阻断范围

| Evidence | 当前 | 阻断 |
|---|---|---|
| Windows 2.1.241 H1 | paired 20/20、matrix17/17；Manifest verified、Capability Audit=ReadyForCanary，POC Bundle artifact 仍为 candidate | 解锁正式 Engine 重新制品与复验，不直接等同生产签名 Bundle Canary，更不等于系统GA |
| Linux native BoringSSL/sanitizer/security/RSS | 待执行 | R6 production promotion、System Canary、GA |
| macOS paired capture | 待外部条件 | 只阻断macOS Archetype |
| Linux Claude Code capture | 待外部条件 | 只阻断Linux Archetype；与Linux Core门禁分开 |
| 真实H2/HPACK cohort | 待证据 | 只阻断H2 Bundle active |
| TLS resumption matrix | 默认关闭、待证据 | 只阻断resumption enable |
| 单进程真实Claude pooled/10并发 | 增强项 | 不阻断Windows Bundle Canary |
| 生产样式负载/24h soak | 待实施 | 性能Gate与GA |
| 新Claude Code/SDK版本 | 每次升级重采 | 对应兼容声明/cohort |

macOS/Linux采集缺口不影响R0–R5和绝大多数R6编码。用户具备环境后按独立evidence lane补采，无需重做主架构。

## 16. 主要风险与控制

| 风险 | 控制 |
|---|---|
| 合同漂移 | trace/OpenAPI/golden diff阻断 |
| resource竞态 | reference model、virtual clock、fault-at-await、soak |
| audit latch重复调用 | latch前upstream=0；started后gap零replay |
| Bundle/cohort漂移 | cohort+epoch+evidence hash，不按版本号静默替换 |
| Linux/BoringSSL供应链 | native runner、lock、SBOM、sanitizer、repro build |
| Browser串号 | 每Credential独占context/Egress，CAS/generation |
| migration锁 | partition、checkpoint、expand/contract、前两版基线 |
| response透明破坏 | byte golden100%，Header策略分测 |
| secret泄漏 | 类型约束、canary、全sink scanner |
| 单实例升级 | drain/systemd rollback/SLO维护窗口 |
| 上游演进 | 官方contract差集、client corpus、fresh capture |
| 外部证据波动 | fail-closed、保留last verified Bundle |

## 17. 18 模块 Traceability

| 模块 | 主要文档 | 测试包 | Phase |
|---|---|---|---|
| 01 接入识别 | API/RP/DM | route/auth/classification/framing | R3 |
| 02 凭证访问 | DM/DB/API/SEC | digest/cipher/RBAC/IP/reveal | R2–R3/R8 |
| 03 入口路由 | TA/SD | owner generation/drain/ready | R3–R4 |
| 04 解析标准化 | API/RP | presence/duplicate/unknown/serializer | R3 |
| 05 参数校验 | FM/DM/RP | capability/model/property | R3 |
| 06 通用调整 | FM/RP | System/rule/determinism | R3 |
| 07 模型中心 | DM/API/AC | catalog/conflict/rollback | R3/R8 |
| 08 规则配置 | DB/API/AC | artifact/pointer/shadow/canary | R2–R3/R8 |
| 09 凭据分组 | CL/DB/API | Enrollment/dedupe/lifecycle/migration | R2/R4–R5/R8 |
| 10 调度选择 | SD | DRR/limits/affinity/Lease | R4 |
| 11 身份拟态 | RP/CL/TE | Profile/Session/epoch/isolation | R5–R6 |
| 12 上游连接 | TE/POC | wire/Bundle/pool/proxy/OS evidence | R6 |
| 13 错误重试 | SD/RP/TE | attempt/deadline/401/429/cancel | R4/R6–R7 |
| 14 响应透传 | API/RP/TE | JSON/SSE/spill/backpressure | R7 |
| 15 Usage遥测 | DM/DB/AC | source×completeness/cost/quota | R7–R8 |
| 16 控制台/API | API/AC | OpenAPI/RBAC/UI/a11y | R8 |
| 17 系统任务升级 | TA/CL/OPS | Job/restart/migration/backup/systemd | R1–R2/R5/R9 |
| 18 安全审计 | SEC/DB/API | secret/SSRF/approval/content/ledger | R1–R2/R8–R9 |

R10要求以上18行全绿。

## 18. 每个 Phase 的 Definition of Done

- 合同与代码同步；
- migration/backward compatibility；
- unit/property/integration/evidence；
- metrics/log/trace且secret scan；
- Admin status/action或明确内部接口；
- failure/rollback/runbook；
- resource/cancel/restart语义；
- trace ledger更新；
- reviewer签署P0不变量；
- 产物hash/provenance归档。

## 19. 当前停止线

规划基线、机器合同、Cargo workspace、forward-only migrations、196 个管理端后端路由与主要生产编排已经建立。本机可执行的 R1–R10 后端实现与回归已经收口，PostgreSQL 18.3 隔离空库集成也已通过；当前停止线转为补齐 N-1/N-2 升级、Linux native、KMS、Provider、恢复演练和 soak 等 promotion evidence，并将其与本地实现状态严格分离。

在全部 GA Requirement、性能/24h soak、隔离恢复、原生目标机与 Active Archetype evidence 变为可验证事实前，任何 `r10-local` 结果只表示本地证据包通过对应检查，不得解释为 RC 或 GA。

RC/GA promotion 必须额外执行 `python -B tools/verify_release_evidence.py EVIDENCE_DIR --profile r10-local --require-ga-ledger`；该开关要求所有 `release_gate=ga` 的 Requirement 状态为 `verified` 且具有测试绑定，任何 `implemented`、`planned` 或 `blocked` 都会阻断 promotion。

## 20. 2026-08-25 实施快照

以下状态区分“本地代码/合同完成”与“外部生产证据完成”。`部分闭环`不是删减模块，未完成能力仍保留在首版范围并保持 fail-closed。

| Phase | 本地实现状态 | 本轮已验证闭环 | 继续阻断 Exit 的事项 |
|---|---|---|---|
| R0 | 机器合同持续闭合 | 196 个 Admin operation、55 个枚举族可确定性生成；47 个 JSON 文件通过 2981 项一致性检查；196/196 operationId 已接后端分派 | 新增能力时继续收紧 route-specific DTO，并保持 schema/table/route 生成账本同步 |
| R1 | 本地闭合 | 9-crate Workspace、composition root、health/readiness、固定测试时钟；Windows Release 构建及包含 8 个哈希产物的 SBOM/provenance evidence 已完成生成—验证闭环 | Linux x86_64/arm64 原生构建、SBOM/provenance 的发布环境证据 |
| R2 | 本机闭环/外部证据门禁 | forward-only migration、CAS/lock、Secret envelope、数据库业务密钥轮换及 resumable checkpoint、密钥 retire/destroy 引用与恢复证据门禁、Audit/Outbox、Job、备份控制面；PostgreSQL 18.3 隔离空库已实际验证 migration/bootstrap/role/rotation | N-1/N-2 真实升级、外部 KeyProvider/KMS、PostgreSQL restore lineage 演练 |
| R3 | 本地闭环 | 四路由、认证/权限/Framing、Client/Session、Capability、System 四模式、分层 RuleSet、GenericAdjustedRequest；Background Catalog 使用强结构 typed matcher、确定性样本、7 天 Shadow 与风险接受证据门槛并进入数据面；suspected 始终 observe；Enforcement Artifact 激活/回滚原子生成 Group Config snapshot，RuleSet 不能放宽 | 真实 PostgreSQL 并发激活/回滚、7 天 Shadow 时间推进及管理流量组合证据 |
| R4 | 本地闭环 | Group owner actor、四级公平排队、Key/Group/Credential 限额、Session/Agent、Lease、连接/消息双重重试、401/429/5xx、资源账本；单 Credential/Group Config 代际栅栏和调度配置热替换；新 Credential 获得 Group 默认调度配置；新 Group commit 后无需重启即可装配唯一 owner，disable/archive drain 并释放，reactivate 使用新 generation；Active Group install→disable→reactivate 已在真实 PostgreSQL 执行 | 多进程 owner 竞争、进程崩溃及管理流量组合证据 |
| R5 | 本地后端闭环 | Enrollment、OAuth PKCE/Setup Token、账号去重、刷新 singleflight、recovery；Enrollment Job 的 `job_id + lease_generation` 已贯穿账号确认、Profile、Auth、Activation 与终态事务；PKCE verifier/callback material/一次性认领/Job/Audit 已原子提交，CAS loser stage 与过期 Enrollment 自动清理；迁组、cohort、device rebuild、候选探测后 rebind；OAuth/Setup PLAN 自动与手工采集；Managed Browser Initialize/Reactivate、固定 Egress、账号复验、加密 stage、四重 CAS 和运行时重投影均已接线 | Managed Browser helper 的真实浏览器实现及端到端账号证据；macOS/Linux Profile 采集证据仍归 R6 lane |
| R6 | 本机闭环/证据门禁 | Bundle verifier/compiler/catalog、H1 exact、PoolKey、CONNECT/SOCKS5、absolute connect deadline、cancel disposition；Environment Archetype 与签名 Bundle 的创建、20 次机器绑定 Canary 证据、激活/回滚/退役已接线；Catalog 先 stage、数据库提交后原子 publish，旧 generation 连接池排空且拒绝迟到归还；正常调度只接受 Active Archetype/Bundle | Linux 原生 BoringSSL/sanitizer/RSS、安全供应链；macOS/Linux capture；H2/HPACK 与 resumption evidence |
| R7 | 本地闭环 | JSON/SSE byte-exact relay、gzip side-channel、内存/加密 spill、commit/cancel、official/cancel usage、精确价格冻结、成本与 quota；取消估算只消费完整 SSE 事件，EOF/取消竞态固定为取消终态，异常已知 delta 与未知内容增量均 fail-unknown；同一估算重放校验完整 evidence，成本可幂等补写，Usage 以复合外键绑定精确 Request/Attempt；已知 cancel estimate 可替代 official unknown，但不覆盖 official partial/complete | 生产样式负载、长流/24h soak 与外部 SLO 证据 |
| R8 | 后端合同路由闭环 | Auth/User/Key、Group/Credential、Policy/Model/Capability、PLAN、Proxy、Profile/Archetype/Bundle、Content Audit、Request/Usage/Export、Alert/Notification/Job/Upgrade 等 196/196 operation 已有后端分派；响应 envelope 已统一 | 本次明确不含前端；真实管理流量、RBAC 越权矩阵、浏览器端可访问性与大数据分页仍需外部集成证据 |
| R9 | 本机控制链闭环 | Audit chain/seal、Legal Hold/Purge/Deletion Ledger、Key rotation/lifecycle、Job heartbeat/generation/cancel allowlist、Alert/Silence/Inbox 与基于 outbox 的 raised/recovery fanout、Usage 与 Content Audit 导出、Model discovery、Upgrade preflight、Backup/Restore control plane；通知 delivery 与 Job 终态原子提交，Server酱³ 持久重试链已接线 | 外部 KeyProvider/KMS、SMTP/Webhook、真实 Backup adapter、systemd upgrade/rollback 与值班演练；Server酱³/Model/Managed Browser 的 Linux native 实发证据 |
| R10 | 本机集成回归 | `cargo fmt`、全 Workspace Clippy、206 个 Rust 测试、合同、workspace、migration policy、systemd、Release evidence verifier 与 secret canary 全绿；8 个隔离空库上的 10 个 PostgreSQL 门禁测试通过；详见 [R10 本地验证证据](../evidence/r10-local-verification.md) | N-1/N-2 真实升级、Linux native、24h soak、45 天内隔离恢复演练、全部 Active Archetype evidence、GA trace ledger |

本轮新增的关键一致性约束：

- Credential disable/revoke/archive 在业务事务前先进入 actor 单凭据栅栏；在途 Lease 保留，新 Lease 停止；archive 仅在 `inflight=0` 时销毁 Secret 并从 actor 移除。
- 手工 Token refresh 使用 `Credential + token_version` Durable Job 幂等键；重跑发现 token generation 已推进时只修复运行时投影，不重复刷新。
- 每个 Messages 请求的 Group Config snapshot 必须与 Scheduler 当前 config generation 一致；配置换代时旧队列请求短暂重试，已提交请求继续使用其冻结超时。
- Group Scheduler 配置每 30 秒从 Active Config 自愈投影；相同版本不重建 Token Bucket，避免定时补满 RPM burst。
- Credential Scheduling PATCH 使用三态字段：缺省保留，`concurrency:null`/`messages_rpm:null` 恢复当前 Group 默认值；配置以不可变版本和单调 active-pointer revision 发布，actor 热替换时保留在途 Lease、Affinity 与 Session Claim，并先按旧速率结算再钳制 Token Bucket，禁止配置更新制造新 burst。
- RuleSet 激活不会就地修改 Group/Platform Key 配置；它在同一事务生成新的不可变配置版本并更新对应 active pointer，随后原子热加载管理/数据面快照。
- Background Catalog 的 `match_all` 仅使用有界 Header 与 JSON Pointer 强信号；重复 Header 不形成确定命中。只有已发布的显式模板可执行 action，suspected 永远不改变业务准入。高风险版本以 7 天 Shadow 为硬门槛，样本少于 100 时必须消费绑定 Artifact hash 的风险接受审批。
- Group Enforcement 是 Group Config 的显式 Artifact 引用；激活/回滚同时切换 Artifact pointer 与完整 Group Config pointer，运行时 snapshot 使用 Artifact version+hash，在途请求不被热加载改写。Group Config 和 Policy Artifact 内容均由数据库 trigger 禁止原地修改。
- 新 Group 在创建事务内获得默认 preserve Enforcement Artifact、证据行及 active pointer；动态 owner 装配失败时 durable Group 保留，30 秒 reconciliation 继续重试，owner generation 不修改业务 ETag revision。
- Environment Archetype 只有在采集、隐私扫描和协议证据完整时才能进入 Canary；Transport Bundle 激活前必须重新校验签名、信任根、ABI、运行时与 replay evidence，并通过 step-up 与审批门禁。
- Transport Catalog 激活先在内存中完整 stage，数据库 pointer 成功提交后才原子 publish；随后按 activation generation 排空旧连接池并拒绝迟到归还。目录中的候选文件始终不可绕过数据库激活状态。
- Notification Destination 的 provider secret 只进入 `security.encrypted_secret`；列表、Audit、Outbox、Job 与 delivery 仅保留脱敏配置和有界错误码。Server酱³ SendKey 连 URL path 也使用 zeroizing secret 类型。
- 通知测试采用持久 `notification_delivery + durable_job`；Server酱³ 暂态失败按 1/5/15/30 分钟退避，初次发送加最多四次重试，渠道失败不回滚原业务事务。
- 精确价格条目在 Request 接受时冻结，后发布价格不回算历史 Request。
- Credential Egress rebind 先探测候选路径，成功后才在短栅栏内同时递增 Profile/Egress epoch；direct 清空代理期望 IP，proxy 固定复制目标静态出口，旧连接由 Profile epoch watermark 排空。
- Subscription PLAN 只按 AuthKind 使用固定的 OAuth Profile 或 Claude CLI Bootstrap 端点；失败保留最后成功值，默认 24 小时自动重采，PLAN 仍只展示且不参与调度权重。
- Model discovery 仅由已启用的 Console API Key 调用官方 `/v1/models`，完整分页成功后才更新目录；新模型只进入 `discovered`，连续三次完整快照缺失且满 24 小时才由系统禁用。
- Managed Browser helper 只通过受控 stdin/stdout 交换临时秘密，stderr 丢弃、输出有界、进程带总超时；浏览器授权与 Anthropic Profile 复验使用同一个冻结 Egress，账号 UUID 不一致时不提交任何候选。
