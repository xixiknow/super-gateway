# Claude Code Gateway 安全详细设计

> 状态：Detailed Design Baseline  
> 上位文档：[功能模块规划](./functional-modules.md)、[API 契约](./api-contract.md)、[领域模型](./domain-model.md)、[数据库设计](./database-schema.md)  
> 关联文档：[Credential 生命周期](./credential-lifecycle.md)、[Transport Engine](./transport-engine.md)、[管理控制台](./admin-console.md)

## 1. 文档目的与权威顺序

本文冻结身份、secret、管理安全、内容审计、审计完整性、SSRF/代理/Browser/Bundle 边界、备份密钥、日志隐私和安全事件响应。

安全控制需要同时保持数据面协议合同：请求按已发布规则调整，Anthropic Body/SSE 原字节交付；任何审计、观察或安全旁路都不参与客户端字节构造。

## 2. 安全目标、限制与剩余风险

目标：最小权限、secret 最短明文生命周期、Credential/Profile/Egress 隔离、高风险双人控制、可验证审计与删除、供应链 fail-closed、受控资源上限。

首版限制：单 Linux 实例；Business KeyProvider 可与业务密文同库，提供静态保护但隔离强度弱于外部 KMS；无多实例 HA；Content Audit、Proxy、Session Slot 等能力可默认关闭但其安全状态和管理入口完整交付。

## 3. 资产清单

| 级别 | 资产 |
|---|---|
| S0 根秘密 | Business、ContentAudit、Backup、AuditIntegrity 根密钥；Bundle/Release 私钥 |
| S1 可复用秘密 | Platform Key、Anthropic token/API Key、Cookie/Storage、PKCE、Proxy/通知 secret、Device seed、Session HMAC、TOTP secret |
| S2 业务内容 | Original、Final Request、Anthropic Body/SSE、正文导出 |
| S3 安全事实 | User/MFA/Session、Approval、AuditEvent、Daily Seal、Deletion Ledger、恢复 lineage |
| S4 内部拓扑 | Credential/Profile/Device/Egress/Proxy/Bundle、account UUID、Attempt |
| S5 普通遥测 | 脱敏 Request/Usage、聚合、健康、性能 |

`Secret<T>` 排除普通 Debug/Display/Serialize/Clone；Body/SSE 使用原始字节专用类型。

## 4. 数据分类与处理矩阵

| 类别 | 常规日志 | 普通导出 | 管理 GET | 加密静态存储 |
|---|---|---|---|---|
| S0/S1 | 排除 | 排除 | 仅 Platform Key 专属 reveal；其它排除 | 必须 |
| S2 | 排除 | 只经 Content Audit Case | 只经 Case | 必须、独立域 |
| S3 | 脱敏摘要 | Admin受控 | RBAC | 必须 |
| S4 | ID/短摘要 | Admin脱敏 | Admin脱敏 | 必须敏感字段 |
| S5 | allowlist | RBAC范围 | RBAC范围 | 按保留策略 |

任何字段进入新 sink 前必须声明 classification、owner、retention、redaction、key role 和删除路径。

## 5. 主体、身份与角色

主体：匿名数据客户端、Platform Key、Management User、Management Session、Platform Admin、Key Owner、内部 Job、Transport/Browser 子任务、离线签名主体。

首版外部角色只有 `platform_admin|key_owner`。无 Viewer、AccessSubject、应用主体或 Tenant。内部 Job 使用 service identity 和最小权限数据库角色，不冒充管理员。

## 6. 拓扑与信任边界

```text
Untrusted Client → Edge/Auth/Framing → Policy → Credential/Profile → Transport/Egress → Anthropic
Management Browser → Session/CSRF → RBAC/Step-up/Approval → Domain Command/Audit Transaction
Application ↔ PostgreSQL / KeyProviders / Audit Store / Spill / Managed Browser / Proxy / Notification / Backup
Offline Capture/CI → signed Bundle/Release → Production TrustStore
```

客户端输入不得决定南向 authority、SNI、Proxy target、Webhook target 或 Bundle source。不同边界使用 typed adapter，不传递原始通用 URL。

## 7. 威胁模型

重点威胁：Key 枚举/盗用；密码暴破、MFA 重放、Session 固定/CSRF；Owner IDOR；SSRF/DNS rebinding；CL/TE/CRLF；secret/正文进入日志或 dump；恶意 Proxy TLS interception；Browser/Profile/Pool 串号；Bundle/依赖篡改；Content Audit 越权与残留；Audit 链删除/重排；旧备份复活已删除正文；资源耗尽；单 Admin 滥用。

每个威胁在测试策略中有对应 `SEC-*` ID，且 release gate记录实际证据 hash。

## 8. 安全默认值

- 管理面默认回环/管理网监听，CORS关闭；
- Cookie Strict、Session idle 30m/absolute 12h；
- step-up 5m且 purpose scoped；
- Content Audit 默认 metadata-only；
- Browser debug/wire capture/core dump关闭；
- Proxy必须 TLS pass-through；
- Bundle/Release验签、未知 ABI fail-closed；
- 请求压缩关闭；Body最大64 MiB；所有 channel/queue/parser有界；
- 生产 `RUST_BACKTRACE=0`；
- secret只在专属 action 接收/使用；
- 高风险管理依赖健康审计链。

## 9. 首次初始化与管理账号

空库必须同时提供：

```text
GATEWAY_BOOTSTRAP_ADMIN_USERNAME
GATEWAY_BOOTSTRAP_ADMIN_PASSWORD
```

缺失时 not-ready，不生成/输出随机密码。一次事务创建初始 Admin，状态 `mfa_pending`、强制改密。初始化成功后部署系统删除 password 环境注入/credential file并重启验证。

首次 onboarding Session 只允许改密、TOTP enroll/confirm、本人状态和 logout。改密事务撤销全部旧 Session，并为当前浏览器签发全新 Session。

## 10. Platform Key

- 生成至少 256-bit 随机 secret，格式含版本与公开 prefix；
- 认证 lookup 使用版本化 digest key 上的 HMAC-SHA-256，候选恒定时间比较；
- 同时保存 envelope ciphertext支持再次复制；
- 创建响应只返回 prefix；完整值只经 step-up reveal、用途、可写审计链和 no-store；UI 60 秒隐藏；
- secret 不做 Unicode/大小写规范化；
- query/cookie/body 中的 Key不参与认证；
- 缺失、畸形、不存在、过期、禁用、吊销统一 401；
- 换 secret 创建新 Key，不原位轮换。

## 11. 密码与 MFA

默认：Argon2id 64 MiB、t=3、p=1、16-byte salt、32-byte output，参数版本化并在成功登录后重哈希。密码 14–128 Unicode code point，拒绝 username/email和本地常见泄漏词表，不强制字符类型拼盘。

TOTP：RFC 6238、SHA-1、6位、30秒，接受当前窗口±1；保存 last accepted step 防重放。首版无 recovery code。

限流：来源 IP 10/min burst5；账号 5/15min；MFA/step-up 5/5min。连续10次账号失败进入 locked并告警；对外文案统一。

## 12. Management Session

Session token 为32随机字节，Cookie `Secure; HttpOnly; SameSite=Strict; Path=/admin`，数据库只存 keyed digest。密码认证、MFA完成和权限提升后轮换 token。

`last_seen_at` 最多每60秒落库一次。认证缓存键包含 User revision/status；disable/locked/archived或密码修改使旧 revision立即失效。Session token不进入URL、日志、trace或前端持久存储。

## 13. CSRF、Origin 与 CORS

所有非 GET/HEAD 管理请求同时要求：有效 Session Cookie、`X-CSRF-Token`、精确 Origin、`Sec-Fetch-Site=same-origin`；缺少 Fetch Metadata时仍严格校验Origin。

CSRF token绑定 Session ID、revision、origin；Session rotation后更新。默认 CORS关闭；分离域仅允许精确 Origin，credentials模式下拒绝 wildcard。JSON Content-Type只是补充条件。

登录、MFA、step-up、secret/material响应均 no-store；敏感页面使用严格 CSP、frame-ancestors none、nosniff和合理 Referrer-Policy。

## 14. RBAC、Owner Scope 与脱敏

Key Owner scope由服务端注入到 ID、列表、filter、search、cursor、aggregate和export。越权对象在当前角色范围内返回404。Owner只见本人 User下全部 Key及请求/usage，不见 Credential/Profile/Device/Egress/Proxy/Bundle、内部 Attempt或正文。

字段 allowlist按角色编译；UI隐藏不是权限控制。导出和游标都绑定 actor scope digest。

## 15. Step-up 风险目录

```rust
struct StepUpGrant {
    session_id: SessionId,
    purpose: StepUpPurpose,
    verified_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    auth_context_digest: Digest,
}
```

purpose：`key_secret_reveal|irreversible_lifecycle|content_audit_access|approval_decision|key_provider_change|backup_restore_security|bundle_activation`。默认5分钟。不同 purpose不共享 grant。

普通写要求 RBAC+CSRF+If-Match+Idempotency+Audit；不可逆 lifecycle再加 step-up；Device rebuild、Bundle生产激活、主密钥/关键Provider、全文和策略高风险动作再加双人审批。

## 16. 双人审批

审批绑定 action type、target、canonical payload digest、resource revision、requester、decider、两侧 step-up、过期与一次性执行事实。发起人与批准人不同，均为 active Admin。

```text
authorize → verify case approved/not expired/not consumed
→ verify requester != decider and both active
→ verify action/target/payload digest/revision
→ transaction(resource mutation + consume case + Audit + Outbox)
```

Key全文 grant默认7天、最长30天；Content Read Case最长4小时。续期创建新Case。

## 17. Secret 分类与 Reveal 边界

只有 Platform Key拥有 reveal能力。Anthropic token/API Key、Browser Cookie/Storage、PKCE、Proxy/SMTP/Webhook secret、Device/Profile seed、Session HMAC、TOTP secret只有 submit/use/replace/destroy。

管理 GET、列表、错误、审计、通知、Job和导出只显示 presence、version、prefix/hash或最后更新时间。任何通用 Artifact API均无secret字段。

## 18. Secret Envelope 与 KeyProvider

```rust
enum KeyRole { Business, ContentAudit, Backup, AuditIntegrity }
```

- Business：首版可采用数据库Provider，明确剩余风险；
- ContentAudit：默认独立数据库外 `0600` key file Provider，也可配置外部Provider；
- Backup、AuditIntegrity：必须位于数据库与备份仓库之外。

Envelope：随机32-byte DEK、随机12-byte nonce、AES-256-GCM。AAD包含 schema、secret ID/kind、provider role、owner ref、purpose、key version；wrapped DEK由对应Provider产生。用途/owner/kind不匹配时解密失败。

## 19. 密钥轮换、销毁与恢复

```text
new active key version
→ new writes use it
→ checkpointed rewrap job
→ old key decrypt_only
→ reference/backups verification + restore drill
→ retire
→ destroy + Deletion Ledger
```

只重包DEK，payload ciphertext保持。Digest key轮换期认证同时检查 current与decrypt-only版本，后台从Platform Key ciphertext重算lookup digest。

历史Backup key在所有引用备份过期且隔离恢复演练通过前保持可用。缺历史Key的恢复校验失败并保持not-ready。

## 20. 内存、临时文件与进程保护

- `Secret<T>/SensitiveBytes`无普通Clone/Debug/Display/Serialize，Drop zeroize；
- 解密靠近使用点，secret引用不跨长await；
- 小型根秘密/DEK在有上限池中使用`mlock2(MLOCK_ONFAULT)`，失败产生安全告警；
- `PR_SET_DUMPABLE=0`、`RLIMIT_CORE=0`、systemd `LimitCORE=0`；
- ptrace、Crash body、wire capture默认关闭；swap关闭或主机全盘加密；
- panic/allocator/OpenTelemetry baggage排除请求与secret；
- spill随机文件名、0600、每文件随机DEK、终态删除、重启sweeper；
- Transport spill与Content Audit对象分目录、分密钥、分生命周期。

## 21. Content Audit 生效策略

```text
Key requested: metadata_only | full_encrypted
Group policy: allow | require | forbid

allow   + valid Key full grant → full_encrypted
allow   + otherwise            → metadata_only
require                       → full_encrypted
forbid                        → metadata_only
```

`forbid` 强制仅元数据，不拒绝业务请求。Group require/forbid的激活本身已经经过双人审批。请求接受时冻结 effective mode，后续 grant 到期或策略更新对在途请求零影响。

## 22. Full Audit 捕获与 AEAD

Full mode门闩：

```text
调度前：store preflight → durable redacted Original Request
       → failure: 503/5s，Anthropic调用数=0

Lease后、首字节前：build Final → strip reusable secrets
                  → durable first Final
                  → failure: 503/5s，释放资源

upstream started后：retry Final/Response side writer failure
                 → critical audit_gap
                 → retry和Body/SSE合同保持
```

Generic只保存digest、Snapshot和change set metadata，不另存正文对象。

Content对象采用每对象256-bit DEK、1 MiB分帧AES-256-GCM；64-bit随机nonce prefix + u32 chunk index。AAD绑定object/request/attempt/kind/schema/chunk/policy version。每方向默认64 MiB；审计副本超限标truncated，客户端仍接收原字节。

对象提交：temp encrypt → ciphertext hash/size → DB staged → object finalize → DB CAS committed；orphan sweeper清理。

## 23. Audit Case、Legal Hold 与删除

无永久明文全文索引。Audit Case最长4小时；临时search最多1000候选；单条正文UI默认10分钟隐藏；每次search、命中、解密、查看、复制尝试、导出和失败都审计。导出为一次性加密包，24小时删除。

Legal Hold创建、复核、解除均需双人审批；active hold增加`legal_hold_count`，retention和手工删除跳过。

删除顺序：

```text
assert legal_hold_count == 0
→ append planned Deletion Ledger
→ destroy wrapped DEK
→ delete ciphertext object
→ update result/deleted_at
→ Audit + Outbox
```

恢复旧备份时必须重放Ledger后再ready，避免已删除内容复活。

## 24. Audit Chain、Daily Seal 与 Outbox

```text
event_hash = SHA-256(
  "gateway-audit-event-v1" || day || sequence ||
  canonical_redacted_event || previous_hash)

daily_seal = HMAC-SHA-256(
  AuditIntegrityKey,
  "gateway-audit-day-v1" || day || count ||
  first_hash || last_hash || previous_day_seal_digest)
```

每日首事件链接前一日 seal digest。审计表只INSERT；更正用correction event。管理资源变化、AuditEvent和Outbox同一事务；数据面Request/Usage不逐条进入管理链。

启动、每小时、恢复校验；seal复制至备份仓库。运行中发现链异常：critical、现有数据面继续、高风险管理冻结；新启动/恢复发现Audit或Deletion完整性失败：not-ready。某管理事务追加审计失败则整事务回滚。

Outbox payload保持redacted；外部通知失败独立重试，不回滚业务状态。

## 25. SSRF、DNS、Header 与响应隐私

所有南向目标使用typed endpoint policy：固定scheme/host/port，拒绝userinfo/fragment/wildcard；解析全部A/AAAA并拒绝unspecified/loopback/link-local/multicast/metadata和默认私网，连接固定IP后复核peer，TLS使用精确SNI/hostname。Redirect默认关闭；开启时每跳重新完整校验。

Anthropic authority/path由固定enum生成；客户端Host/Forwarded/Body不参与。Webhook、SMTP、Proxy probe各有独立target policy。SOCKS remote DNS只允许固定Anthropic hostname，仍执行内层证书/SNI。

请求Header建议上限：128项、总64 KiB、单值16 KiB、request line 8 KiB。CL/TE冲突、重复敏感Header、obs-fold、CR/LF、非法字符返回400并关闭/reset。鉴权后删除北向认证和来源Header；响应删除hop-by-hop、set-cookie、连接实现、Credential限流/配额Header。

Body/SSE原字节、顺序、Content-Encoding保持；旁路审计/usage只观察。

## 26. Browser、Proxy、Transport 与 Pool 隔离

Managed Browser每Credential独立sandbox/profile/context/storage partition/认证连接/临时目录；Chromium sandbox开启；扩展、下载、持久历史、截图、业务正文缓存关闭；DevTools只用本地受限pipe；网络仅官方授权域并沿固定Egress。Cookie/Storage版本只有token、account验证和CAS同时成功才激活。

Proxy密码只提交/覆盖；Basic Header只发Proxy；内层BoringSSL执行证书/SNI/ALPN。TLS interception、证书替换、ALPN漂移首次确认即隔离。

PoolKey包含Credential、profile epoch、Bundle、Egress/epoch、authority、SNI、protocol；TLS ticket、H2、HPACK和socket不跨键。

## 27. Bundle、依赖与发布供应链

Bundle是数据规格，不加载任意动态插件。JCS RFC8785 + SHA-256 + Ed25519 detached signature；签名覆盖domain/schema/ABI/hash/evidence/engine range。Bundle与Release签名key domain分离。

TrustStore只含批准公钥；旧key只验历史，新active artifact由current key签名。Loader验证signature/hash/provenance/privacy/ABI/engine/evidence，任一失败quarantined。

CI产出SBOM、依赖漏洞和license检查、secret scan、provenance、可重复build、wire diff；Cargo.lock固定。Release manifest绑定binary、schema范围、Bundle ABI、UI资产和migration checksum。

## 28. 日志、备份与留存

日志字段采用allowlist，排除完整Header/Cookie/query userinfo/Body/SSE/secret/Browser页面/Proxy认证。具体主体ID使用内部ID或日志专用HMAC短摘要；不作为Prometheus label。panic、Job、幂等、Audit detail、notification和export都跑结构化secret scanner。

Backup每artifact随机DEK，由数据库外Backup Provider包装；manifest绑定DB system/timeline/LSN、ledger watermark、artifact hash、key version、schema/release lineage并签名/HMAC。连续WAL≤5m、每日基线、至少一份异机副本；RPO≤5m、RTO≤60m；每周校验、每月隔离恢复，45天无成功演练为critical。

默认留存：Request/Attempt/Usage明细30天，小时聚合180天，日聚合2年，管理Audit明细30天，Content正文7天（1–365可配），导出24h，幂等24h，备份7日/4周/12月，Daily Seal/Deletion Ledger/lineage至少15个月。

## 29. DoS、安全告警与事件响应

已有上限：Key并发5；Messages/Models 60 RPM burst10；health/ready IP 120 RPM burst20；Body 64 MiB；SSE pending 1 MiB；non-stream 8 MiB→spill、64 MiB单响应、2 GiB/32 Reservation、wait queue64；共享等待30s；connect5s；stream idle30s；client write idle120s。

新增解析上限：JSON深度64、单对象成员10000、总节点200000。密码哈希、Browser、Audit writer、Job、notification和所有channel均有独立有界worker/queue。

安全响应：detected→triaged→contained→eradicated→recovered→closed。Key泄漏通过新Key迁移后吊销旧Key；Credential secret泄漏停止新Lease并reauth/revoke；Session泄漏撤销Session/User revision；Bundle key泄漏移除TrustStore key并quarantine；审计链异常冻结高风险动作。每次事件关联Incident ID、Audit、Outbox和恢复验证。

## 30. 不变量、测试门禁与 Reader Check

核心不变量：

1. 完整Platform Key只从reveal返回；其它secret无reveal。
2. secret、正文、Cookie、Proxy密码、Session HMAC排除普通日志/trace/metric/export。
3. Owner scope覆盖ID、filter、cursor、aggregate、export。
4. step-up绑定purpose；Approval绑定action/target/payload/revision且一次性。
5. `forbid → metadata_only`。
6. Full Original和首次Final在首字节前durable。
7. 首字节后audit gap对retry/Body/SSE零影响。
8. 每个Content对象独立DEK；spill不转审计对象。
9. Legal Hold阻止删除；删除先Ledger后销毁；恢复先重放Ledger。
10. 管理变化、Audit、Outbox同事务。
11. 运行链异常保留数据面并冻结高风险；启动/恢复异常not-ready。
12. authority/SNI不由客户端决定；Proxy仅TLS pass-through。
13. Credential间Browser/Pool/Ticket/H2/HPACK隔离。
14. Body/SSE原字节；Header执行显式过滤。
15. Bundle/Release签名域分离；未知ABI fail-closed。
16. 密钥退休前引用归零且备份恢复通过。
17. 所有queue/buffer/parser有界；partial/unknown usage保持原语义。

测试：Auth等形401、Session/MFA/CSRF、Owner IDOR、purpose grant、Approval篡改、Envelope AAD/rotation、Content staged/finalize/gap、字节透明、Legal Hold/Ledger、Audit链篡改/整日删除、SSRF/DNS rebinding、CL/TE/CRLF、Proxy/Browser/Pool隔离、Bundle签名/ABI、备份缺历史key、深JSON/慢流/存储耗尽、24h soak。

Reader Check应能回答：哪一种secret可再次复制；为什么其它secret只有覆盖；Session/step-up窗口；哪些动作双人；allow/require/forbid；Full audit门闩；首字节后gap；Legal Hold与Ledger；链异常三种运行阶段；四个KeyProvider域；Proxy pass-through；Bundle签名域；日志允许字段；历史Backup key销毁条件。
