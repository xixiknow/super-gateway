# Claude Code Gateway 测试策略

> 状态：Verification Baseline  
> 目标：为首版全部 18 个功能模块建立可追踪、可复现、可审计的证据链  
> 关联文档：[功能模块规划](./functional-modules.md)、[技术架构](./technical-architecture.md)、[实施路线图](./implementation-roadmap.md)

## 1. 目的与权威顺序

测试验证已发布合同，不自行创造产品语义。权威顺序：功能规划 → 技术架构 → 领域/数据库/API → 专项详细设计 → 测试策略。发现差异时先修订合同和trace ledger，再修改测试预期。

## 2. 首版质量边界

18个模块全部进入首版。Proxy、Session Slot、全文审计、H2 Bundle、TLS resumption等默认关闭能力仍须拥有数据模型、API/UI状态、fail-closed行为和测试；“关闭”表示运行配置状态，不是模块缺席。

P0质量目标：响应字节保持、零重复上游执行、零资源泄漏、零Credential/Profile/Egress串用、零secret泄漏、备份恢复完整。

## 3. Requirement/Test/Evidence ID

```text
REQ-F01..REQ-F18   功能模块
INV-*              全局不变量
CT-*               API/contract
GOLD-*             Golden/compatibility
PROP-*             Property/metamorphic
MODEL-*            Model-based state machine
WIRE-*             TLS/H1/H2/Proxy evidence
SEC-*              Security/privacy
PERF-*             Performance/soak
DR-*               Backup/restore/upgrade
UI-*               Admin/a11y
```

每条Requirement关联：权威文档位置、test ID、fixture ID、roadmap Phase、release gate、执行commit/binary/migration/Bundle hash、结果与证据URI。

## 4. 风险与优先级

- P0：Body/SSE改变、重复Anthropic调用、permit/Lease/Reservation泄漏、身份/连接跨Credential、secret/正文泄漏、restore损坏；
- P1：API合同、RBAC、调度公平、Credential恢复/迁移、规则/能力漂移、审计链；
- P2：PLAN/展示、非关键Job、通知渠道、普通交互问题。

每个P0行为至少包含一个底层可穷举/属性证明和一个纵向集成见证用例。

## 5. 测试金字塔

用例数量建议：65% pure unit/table/property/model，25% component/repository/contract，8% integration/fault/wire，2% E2E/UI/release。

总覆盖率不替代关键边矩阵。Secret、双审批、resource release、commit/retry、Profile/Egress隔离要求合法/非法/竞态边100%显式覆盖。

## 6. CI 执行层

| 层 | 内容 |
|---|---|
| pre-commit | pure unit、table、golden、schema、lint |
| PR | full workspace、PostgreSQL repository、contract、短fuzz、secret scan |
| merge | integration、并发模型、migration、UI unit/a11y static |
| nightly | 长fuzz、fault、wire replay、soak子集、retention/Job |
| RC | Linux native、安全/SBOM、客户端矩阵、负载、backup/restore、upgrade rollback |
| external evidence | Windows/macOS/Linux paired capture/replay/transport matrix |

失败证据保留，flaky test必须登记owner/root cause，不通过无期限重跑掩盖。

## 7. 环境矩阵与确定性

- 固定/虚拟时钟，UTC与monotonic分开；
- 确定性Typed ID、随机seed、DRR tie-break；
- PostgreSQL 16+真实实例；
- Linux x86_64/arm64；
- direct、CONNECT、CONNECT Basic、SOCKS5 local/remote DNS；
- H1/H2按Bundle evidence状态选择；
- Windows/macOS/Linux capture runner只在相应lane；
- network/DB/Object Store/KeyProvider/Browser均可编程故障。

## 8. Fixture 治理

每个fixture带：ID、来源类别、OS/build/runtime/client/arch/cohort、scenario、schema/normalizer version、content hash、privacy scan、生成命令、兼容范围和过期策略。

真实原始capture隔离保存；代码仓库只纳入规范化、脱敏、内容寻址制品。任何golden更新必须独立审阅语义diff，CI不会自动批量接受。

## 9. gateway-testkit

测试底座提供：

- 合成Anthropic H1/H2/SSE server；
- 可编程CONNECT/SOCKS5/TLS interception Proxy；
- virtual clock与deterministic scheduler；
- fault PostgreSQL/Object Store/KeyProvider；
- OAuth/token/profile/PLAN与Managed Browser adapter；
- ResourceLedger/actor event探针；
- slow/cancel client writer；
- wire capture/diff、secret canary scanner；
- fixture/evidence manifest生成器。

Testkit接口作为测试ABI版本化，避免各crate各写一套故障模拟。

## 10. 领域状态机 Table Tests

User、Key、Group、Credential、Enrollment、Maintenance、Profile、Egress、Proxy、Model、Artifact、Approval、AuditObject、Alert、Job、QueueTicket、Lease、Request、Attempt和Delivery全部覆盖：

- 每条合法转换；
- 每条非法转换；
- terminal后命令；
- expected revision/token/epoch CAS loser；
- cancel/timeout/grant竞态；
- generation变化后的迟到callback；
- Audit/Outbox原子性。

## 11. API 与 OpenAPI Contract

- 数据面只注册Messages、Models、health、ready；Count Tokens保持未知；
- 认证优先的401/404/405；
- 全部平台错误status/type/message/Header/资源占用；
- Anthropic错误原Body/Header过滤；
- ETag/If-Match、Idempotency、cursor actor/filter绑定；
- Admin/Owner route与字段矩阵；
- no-store、CSRF、Origin、Cookie；
- typed管理action和Job；
- OpenAPI example replay与breaking change检测。

## 12. Golden 与客户端兼容 Corpus

覆盖当前及前两个Claude Code兼容小版本、当前Harness和主流Anthropic SDK。用例：

- JSON missing/null/value、unknown top-level/content block；
- System四模式；tools/tool use/result；thinking/cache/beta/context；
- Client/Session/Agent/Attribution结构；
- Models与所有平台错误；
- non-stream原Body和SSE事件/任意chunk边界；
- Harness/SDK负向分类；
- 新模型Capability差集。

## 13. Property 与 Metamorphic

- counter永不下溢、permit/Lease等式；
- QueueTicket/Request唯一terminal；
- retry不延长deadline；
- client commit后retry恒false；
- PLAN任意变换对候选/排序/结果零影响；
- 同语义RuleSet重排保持结果；
- serializer确定性、normalize幂等；
- 跨Credential只改变attempt-scoped Profile/token/Session/Egress；
- Generic digest保持；
- unknown extension导致pin的保守性；
- key/group/user公平在持续capacity release下无饥饿。

## 14. Model-based 测试

Reference model随机生成：Queue/Grant/Cancel/Timeout、Lease/Retry、Session Claim/Affinity、Credential Enrollment/Maintenance/Rebind/Migration、Artifact publish/rollback、Approval/Content deletion、Job lease接管。

每一步对比：可见状态、资源计数、事件顺序、DB投影、唯一终态和迟到事件影响。生成counterexample最小化并加入固定回归。

## 15. Fuzz

Targets：HTTP framing/重复Header/CRLF；JSON/depth/node/unknown block；Capability条件树；RuleSet；pagination cursor；Bundle JCS/signature/ABI；H1 response framing；H2 frame/HPACK；SSE chunk；Proxy handshake；OAuth callback/state；Content chunk AEAD。

短fuzz进PR，长fuzz进nightly/RC。crash、hang、OOM、invariant violation都保留最小样本；coverage以target/corpus/crash/hang/回归样本衡量。

## 16. 并发、竞态与线性化

重点：grant/cancel/timeout；Reservation ready/deliver/discard；refresh/reauth/rebind；Enrollment duplicate；ActivePointer切换；Job lease接管；Outbox replay；Audit chain append；client cancel/write error；transport cancel/grace；Group drain/reload。

测试在每个await边界注入暂停、取消、重启和迟到消息。验证：旧generation对新状态零影响，每个资源最多一次release，每个Request一个terminal，CAS loser候选secret销毁。

## 17. Repository 与 PostgreSQL

使用真实PostgreSQL验证：account UUID全局唯一、Profile/Device/Egress 1:1、Proxy默认1:5、Attempt 1..3、partial unique operation、revision/token/epoch CAS、统一锁序、月分区、跨月Attempt/Usage、Outbox同事务、retention/Legal Hold/Deletion Ledger。

并发测试使用独立连接和barrier，不以单事务模拟竞争。执行EXPLAIN/lock timeout和大表索引门禁。

## 18. Migration、升级与恢复

- 空库全量、前两个release升级；
- expand/backfill/switch/contract；
- checkpoint/resume、旧binary兼容；
- dump/restore与WAL PITR；
- Audit Chain/Daily Seal、Deletion Ledger replay；
- Active Pointer与Bundle hash；
- systemd drain/switch/ready/rollback；
- RPO≤5m、RTO≤60m；
- 旧备份复活对象再次删除；
- Browser/Anthropic/通知在演练中保持隔离。

## 19. Edge、Access 与 Classification

测试route/Method/auth顺序、Key等形401、Body/Header/JSON限制、Models独立桶、health/ready来源与IP桶、可信代理IP、两类client classification正反样本、anonymous Session复用、Probe模板安全目录/唯一性、Suspected只观察、Background Shadow。

原始UA/Session/Platform Key/Gateway URL泄漏扫描必须覆盖所有Final Request。

## 20. Capability、Policy 与 Pipeline

- Capability model差异、conflict、path expansion、hot rollback；
- Group Enforcement不可下调；
- System preserve/strip_client/replace/strip_all；
- deterministic serializer与raw-body reuse；
- unknown字段保留；
- Portable/Pinned分类；
- audit Original/Final latch故障点；
- Generic digest跨retry一致；
- Profile应用与Session UUID格式；
- count estimate使用同一Generic Snapshot。

## 21. Scheduler 与 Credential Lifecycle

调度：四级DRR、Key/Group/Credential三层限制、queue cap、shared deadline、Session/Agent、optional slot、2s preferred、affinity migration、429/cooldown/half-open、Lease与cancel。

Credential：OAuth PKCE/state/replay、Setup bootstrap、Existing import、Console Key、Egress预分配、全局去重、20并发401 singleflight、Browser silent reauth、Manual Recovery、PLAN、Group migration/rebind/cohort/device、disable/revoke/archive。

固定场景包括3 Credential×5并发、10 Key×4请求，以及一个Base Session的main+9 subagent。

## 22. Transport Wire 与三 OS Evidence

- Bundle canonicalization/Ed25519/hash/ABI/privacy/unknown；
- same-target ClientHello exact diff、ALPN、证书/SNI；
- H1 request line/header order/casing/framing/reuse/residual；
- H2 SETTINGS/frame/pseudo-header/HPACK/GOAWAY/cancel；
- full PoolKey逐字段mutation；
- direct/CONNECT/Basic/SOCKS5 local/remote DNS；
- connection timeout/cancel；
- cohort drift和A→B→A pool generation；
- 每个Active Archetype独立paired capture/replay/matrix。

Windows H1当前只解锁Bundle Canary。macOS/Linux evidence、真实H2、resumption分别只阻断对应能力；Linux native Engine门禁独立阻断系统生产promotion。

## 23. Response、Usage 与透明性

non-stream：8 MiB切spill、64 MiB hard limit、2 GiB Reservation、完整后cancel、client write idle/total。SSE：任意chunk、1MiB背压、idle暂停、commit后断流。

验证Anthropic Body/SSE已交付前缀100%字节一致，Header过滤单独断言。usage用`source × completeness`；cancel estimate不覆盖official；partial/unknown不归零；Price Snapshot冻结，estimated value语义正确。

## 24. Fault Injection 与资源回收

故障：401/429/500/502/503/504/529；DNS/TCP/TLS/ALPN；Proxy407/interception；slow first byte/slow SSE；client断开；DB短断/锁；disk满/inode；Audit Store/KeyProvider/Notification；process restart；Bundle quarantine。

每个await注入后核对ResourceLedger、socket/pool、ticket/Lease/Claim/Reservation/buffer/tmp、Attempt/usage和terminal。审计latch前故障Anthropic调用数恒为0；首字节后audit gap不触发重放。

## 25. 安全验证

Auth/Session/MFA/CSRF；RBAC/IDOR；purpose step-up；Approval payload/revision/一次性；SSRF/DNS rebinding/redirect；authority allowlist；Proxy target；CL/TE/CRLF；Bundle/Release签名域；dependency/SBOM/license；Audit链改单/删单/重排/删整日；upgrade/rollback签名。

Security test证据要显示攻击输入、预期拒绝、资源副作用、日志脱敏和告警，不只检查HTTP status。

## 26. Privacy、Secret 与 Browser

- 编译期Secret Debug/Serialize/Clone约束；
- 日志/trace/metric/Job/Audit/notification/export/crash扫描；
- 合成secret canary跨所有sink；
- Envelope AAD跨owner/kind/purpose替换；
- rotation中断/恢复/历史key；
- Platform Key reveal no-store/60s；其它secret零reveal；
- Content DEK、Legal Hold、delete/Ledger/recovery；
- 每Credential Browser/profile/Cookie/Storage/Egress/connection零复用；
- 临时目录、spill、orphan sweeper。

## 27. Admin UI E2E 与 Accessibility

E2E：Admin/Owner导航与字段、首次初始化/MFA、Session/CSRF、Key reveal、User/Key lifecycle、Group六页签、Credential五页签、Enrollment/recovery、Proxy、Model/Rule/Bundle、Request/Usage/export、Approval/Content、Alert/Ops。

错误/空态、409 revision diff、Job progress、secret倒计时覆盖。A11y目标WCAG2.2AA：键盘、焦点、aria-live、label/error summary、状态非颜色唯一、图表数据表、200% zoom、窄屏、reduced motion。

## 28. 性能与容量

固定基线：应用8vCPU/16GiB、PG4vCPU/8GiB、SSD、1Gbps、Body≤64KiB、metadata-only、健康连接复用。目标≥200RPS、≥1000 SSE、32 Reservation、added latency≤20/50ms p95/p99、SSE relay≤10/25ms。

分别测direct/proxy、H1/H2、local/full audit、不同Body、cold/warm pool、DB延迟。记录CPU/RSS/heap/alloc/task/socket/WAL/query/pool。性能回归基于相同commit/fixture/environment manifest。

## 29. 24小时 Soak

混合短请求、长SSE、取消、连接轮换、401/429、配置pointer切换、Credential维护、Job/Outbox、备份、retention。Tokio task、socket、pool shard、ticket、Lease、Claim、Reservation、buffer、timer、RSS、heap、tmp进入稳定平台。

退出条件：零resource invariant、零跨Credential复用、零secret canary、无持续增长、SLO达标、恢复/升级动作可执行。

## 30. Coverage、Release Gate 与证据

Coverage建议：domain/policy/scheduler/security line≥90% branch≥85%；其它Rust业务crate≥80/75%；UI状态≥80/70%且关键旅程E2E。18模块、全局不变量、公开路由/错误、角色×动作、状态转换边100% traceability。

| Gate | 条件 |
|---|---|
| PR | unit/table/property、contract/schema、golden、secret scan、短fuzz |
| Merge | PG repository/migration、integration、并发模型、UI unit/a11y |
| RC | Linux native、sanitizer/SBOM、client/wire/fault、backup/restore、upgrade |
| Bundle Canary | 单cohort paired evidence、diff、签名/hash/ABI、rollback |
| System Canary | 18模块主路径、Admin/Runbook、零泄漏、小流量、告警/回滚 |
| GA | SLO、24h soak、<45天restore drill、所有Active Archetype证据、零critical |

所有PASS绑定commit、binary、Schema、migration、Bundle和fixture hash。例外有owner、到期和受影响Gate；P0/critical、响应字节、secret、资源泄漏、恢复完整性没有普通waiver。
