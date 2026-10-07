# 环境原型 / 传输包 设计检查报告

- 日期:2026-10-01
- 范围:`/bundles` 管理页背后的完整链路——spike-cli 采集与签名、catalog 数据模型、admin 生命周期操作、信任库、`gateway-transport` 运行时消费。
- 方法:代码走读(前端 `ArchetypeBundles.tsx`、后端 `admin_backend.rs` / `production_dispatcher.rs` / `gateway-transport`(bundle/tls/engine/h1/pool)、迁移脚本、transport-poc 工程、内置 bundle 资产),结论均附 文件:行号 证据。
- 结论速览:架构骨架与理想设计匹配;发现 **1 个 P0 缺陷(运行期隔离安全网实际失效)**;指纹一致性为「发布时刻的快照一致」,不是「运行中的持续一致」,存在三类已知敞口。

---

## 1. 设计梳理(基线)

### 1.1 一句话定位

网关不"伪造"客户端,而是把某个真实 Claude Code 客户端环境的完整 wire 行为(TLS ClientHello、HTTP/1.1 头序、帧方式)采集、签名、激活到运行时,使网关出口与该真实环境在协议层不可区分。

- **环境原型(Archetype)**:回答"哪类机器 + 哪个版本的客户端可以承载凭据"(OS 家族/架构/OS build + `claude_code_cli` + runtime 版本 + 采集批次)。
- **传输包(Transport Bundle)**:该环境**经过签名的协议实现**,Ed25519 签名信封 JSON;控制台只登记与验签,不生成传输实现。

### 1.2 数据链路

```
spike-cli 采集/发布管线
  真实客户端对拍抓包 → ReleasePackage(证据/稳定性/重放报告)
      │ promote:Ed25519 签名(JCS 规范化,preimage = "transport_bundle_v1" || hash || payload)
      ▼
  *.signed-bundle.json ──管理台上传──► catalog.transport_bundle(draft)
      │
catalog.environment_archetype(根)
  └─ environment_archetype_version(版本链,content_hash 锚定)
       ├─ evidence_set / capture_run / evidence_item(五类证据 + 隐私扫描)
       ├─ replay_verification(发布期正式重放结论)
       ├─ archetype_capacity_policy(max_credentials/调度权重)
       └─ archetype_bundle_binding(candidate→active→retired;每 bundle 唯一属主;每 (版本,协议) 唯一 active)
            │ 启动/激活时验签+编译
            ▼
gateway-transport:SignedBundleEnvelope::verify → CompiledTransportEngine
     → EngineCatalog(ArcSwap 原子发布,generation 单调)
            │
gateway.credential_profile(凭据锚定 archetype_version)
     → 出站请求按 bundle 渲染 TLS+HTTP → api.anthropic.com
```

### 1.3 状态机

| 对象 | 状态与迁移 |
| --- | --- |
| 原型版本 | `draft →(verify:五类证据齐+capture_run succeeded+privacy passed)→ verified →(activate:须已有活跃 h1 bundle)→ active →(新版本激活顶替)→ retired`;retire 要求无活跃凭据 profile 引用 |
| 传输包 | `draft →(verify:重验+证据/重放或签名发布 attestation)→ verified →(activate)→ active →(被顶替)→ retired →(rollback)→ active`;正交维度:`evidence_gate(pending/passed)`、`runtime_state(loadable/quarantined)` |
| Binding | `candidate → active → retired`,每 (archetype_version, protocol) 唯一 active |
| 信任 key | `current`(可验旧件+可批新激活)/ `historical`(仅复验旧件)/ `revoked`(全拒) |

### 1.4 信任链验证时机(fail-closed)

1. 进程启动:读信任库,扫描 bundles 目录逐个验签编译(`app.rs` `load_transport_catalog`)。
2. 本地引导:Windows x86_64 下 `local_bundle.rs` 验签内置件 → 编译自检 → 落盘信任库 → seed 整个 catalog(本机无人工操作即有完整数据的来源)。
3. 管理操作:上传/验证/激活走 `verify_and_compile(for_new_activation=true)`——**historical/revoked key 不能批准新激活**;激活事务内重扫全目录再原子发布;上传落盘 `.stage`→rename 防半写;`checked_bundle_path` 锁定路径。
4. 隐私闸:canonical payload 含 `bearer `/`sk-ant-`/`setup-token-` 等字面量直接拒绝(`bundle.rs:612-617`)。

### 1.5 运行时消费

- **调度硬闸**:`active_bundle_available_for_os` 五表 join(`production_dispatcher.rs:4658-4684`),无匹配链 → `bundle_missing_for_os` critical 告警 + 拒绝分发,绝不降级。
- **精确匹配无回退**:`catalog.find_exact` 按 profile 锚定的 bundle_id/version/hash 取引擎,禁止跨 OS/cohort 回退;连接池 key 含 bundle 版本;attempt 身份与引擎 key 强一致校验。
- **原子换代**:`engine_activation_generation = MAX+1`,ArcSwap 发布,在途请求持旧快照跑完。

### 1.6 页面区块与机制对应

| UI 区块 | 机制 |
| --- | --- |
| OS 覆盖总览(三卡) | 每 OS 是否同时存在 active 原型版本 + active bundle,缺口链到 /alerts |
| 4 步骤条 | 定义原型 → 绑证据 → 上传签名包 → 激活(状态机的叙事化) |
| 原型表 / 传输包表 | `/admin/v1/environment-archetypes`、`/transport-bundles`;生命周期动作 `id:verify|activate|...` 冒号路由 + `If-Match` 乐观锁 |
| 上传 dropzone | 前端仅预检 `.json`、≤8MiB、含 `payload+signature`;验签在服务端 |

---

## 2. 发现的缺陷

### F1(P0,已修复 2026-10-01)运行期 bundle 隔离路径违反 R6 CHECK 约束 —— 安全网实际失效(fail-open)

- **位置**:`crates/super-gatewayd/src/production_dispatcher.rs:486-494`(已亲自核实)。
- **现象**:传输错误归类为 `HealthEffect::QuarantineBundle` 时,调度器执行
  `UPDATE catalog.transport_bundle SET lifecycle_code='quarantined', runtime_state_code='quarantined' ...`。
  而 R6 迁移(`20260824000700_r6_transport_contract.sql:42-44`)已把 `transport_bundle_lifecycle_code_check` 收窄为
  `('draft','verified','canary','active','retired')`,且无后续迁移放宽(全部迁移中仅 R6 出现过 quarantined 相关 DDL)。
- **后果链**(确定性):
  1. Postgres 拒绝 UPDATE(CHECK 冲突)→ `map_err(|_| DispatchError::Unavailable)` 吞错;
  2. 事务丢弃 → 后续两步永不执行:不写 `bundle_runtime_incident` 事故记录(`:499-513`)、不隔离该环境原型下活跃凭据(`:514-524`);
  3. bundle 在目录中仍 `active + loadable` → 后续请求继续路由到故障 bundle,每次重复同样失败。
- **语义**:"运行期发现 bundle 坏 → 自动隔离 → 记录事故 → 保护凭据"这条安全网自 R6 起为死路径,且失效方向是 fail-open。
- **为何潜伏**:仅特定传输错误触发,常规路径不经过;无测试覆盖该 SQL 与 R6 约束的组合。
- **修复方向**:UPDATE 只改 `runtime_state_code='quarantined'`(调度闸要求 `loadable` 才放行,state 变更即切流);是否同步置 `lifecycle='retired'` 参照 R6 数据迁移先例(`:38-39` 旧数据 lifecycle→retired)决定;同步排查是否存在读取 `lifecycle_code='quarantined'` 的查询残留。
- **修复记录(2026-10-01)**:隔离 UPDATE 抽为 `PgStorage::quarantine_transport_bundle_runtime`(`gateway-storage/src/postgres.rs`),仅更新 `runtime_state_code`,lifecycle 保持正交不动;调度器改为调用该方法(`production_dispatcher.rs` `project_transport_health`)。排查确认全仓无其他 `lifecycle_code='quarantined'` 写入或读取方,所有运行闸(调度五表 join、激活校验、就绪检查)均只认 `runtime_state_code='loadable'`。回归测试 `runtime_quarantine_moves_only_runtime_state_and_stays_idempotent`(`production_dispatcher.rs` tests 模块,`TEST_R4_RUNTIME_DATABASE_ADMIN_URL` 门控)在真实 PostgreSQL 上验证:R6 CHECK 存在、旧双拨盘 UPDATE 被约束拒绝、新方法仅翻转 runtime_state 且幂等。

---

## 3. 指纹一致性评估

**理想定义**:网关出站与真实客户端在 wire 层完全不可区分,且每个指纹字节有证据背书、持续可验证、可审计。

### 3.1 第一层:受控且发布期验证过(✅ 核心指纹)

ALPN(协商结果强校验,不符即隔离,`tls.rs:116-129`)、TLS1.2 及以前 cipher 顺序(`tls.rs:288-311`)、supported_groups 顺序(`tls.rs:312-332`)、GREASE/扩展随机化开关(`tls.rs:339-340`)、OCSP/SCT(`tls.rs:333-338`)、resumption 强制关闭(`tls.rs:71`)、21 头逐字序与大小写(`production_dispatcher.rs:3779-3864`)、origin-form 与 content-length 帧(`h1.rs:42-94`)、9 字段 exact pool key(`bundle.rs:15-25` + `pool.rs:11-39`)。

发布期验证链:官方/受控双 lane 对拍 → wire-diff 逐字段硬比对(任何固定字段差异即 FAIL)→ 20 轮稳定性矩阵 → formal replay 以真实 BoringTLS 实测 ClientHello 比对 cipher 序、扩展类型序、ALPN、握手字节长、record 分帧(`spike-cli/src/release_bundle.rs:275-358`)。

### 3.2 第二层:「恰好一致」而非「受控一致」(⚠️ 风险区)

| 字段 | 现状 | 证据 |
| --- | --- | --- |
| TLS 1.3 cipher 顺序 | 引擎将其过滤,顺序由 BoringSSL 内置决定,当前与捕获恰好一致才通过 | `tls.rs:290-291`;`planning/transport-poc.md:283` |
| signature_algorithms | bundle 无此字段,纯 BoringSSL 默认列表 | tls-tap 可采集(`tls-tap.rs:638-644`)但 bundle 不表达 |
| 扩展顺序 | bundle 的 `extension_order` 仅用于审计;运行时只消费 OCSP(5)/SCT(18) 两个开关 | `bundle.rs:91` 注释;`tls.rs:333-338` |
| record 分帧/padding | 无控制点,仅事后核对 `record_lengths` | `release_bundle.rs:328` |

共同风险:BoringSSL 升级或客户端换版本时可能**悄悄漂移**;发布期重放会拦截新签发,但存量运行件无人盯。

### 3.3 第三层:固有不可控(非缺陷)

client_random、legacy_session_id、key_share 公钥字节、ECDHE 临时量——每条连接必然不同,风控不作为指纹;采集归一化按形状处理(`wire-normalizer/src/lib.rs:653-665`)。

### 3.4 第四层:验证链盲区与行为敞口(❌ 最值得关注)

1. **运行时头路径与验证路径不一致**:调度器在 21 头模板渲染后**追加**模板外头——`x-client-request-id` 恒追加、`x-stainless-helper-method` 流式时追加,位置在 Content-Length 之后(`production_dispatcher.rs:3839-3864`)→ 实际线上 22~23 头,与 formal replay 验证的 21 头序不同;该路径不被 formal replay / wire-diff 覆盖。
2. **运行时值覆盖**:`anthropic-beta` 被 `DEFAULT_CLAUDE_CODE_BETA` 覆盖模板值(`production_dispatcher.rs:75,3796-3803`);`X-Stainless-Retry-Count` 恒为 "0",重试不递增(真实客户端会递增,属上游可观测差异)。
3. **运行期零持续校验**:`TlsObservation`(实际协商 ALPN/cipher/版本/复用)每次握手都产出但**无人消费**——不落盘、不与 bundle 声明比对;上游 header 捕获仅作遥测。一致性 = 发布时刻一次性事实,非受监控状态。
4. **resumption 整链未实现**:当前与捕获一致(禁用),启用前置条件(按完整 Pool Key 隔离 Ticket Store + resumed reference 矩阵)在 transport-poc README「下一批实现」。
5. **无 pacing/请求节奏拟态**:wire-diff 仅 timing 分桶容差。
6. **H2 敞口**:当前 Windows 2.1.241 cohort 真实走 HTTP/1.1(README 证实),强制 h1 现无协议偏差;客户端未来升级 h2 时无 HPACK 参考,H2 bundle 是硬前置(`bundle.rs:113`、`transport-poc.md:287-288`)。
7. **合成认证配对**:采集流程用合成 auth,非真实 OAuth beta 集(`transport-poc.md:298`)。

### 3.5 评估结论

- 架构骨架(证据驱动签名指纹、三道闸、fail-closed 调度、原子发布)与理想设计**匹配**。
- 对 2.1.241 Windows cohort:**静态指纹在发布时刻被证明一致**;但 TLS 四类字段是一致性"外包"给 BoringSSL 的"恰好一致",运行时构建路径存在每日真实流量中的可观测差异(第四层 1-2),且运行中无任何机制持续确认一致性。
- 叠加 F1(隔离安全网失效),当前体系的真实保证是「**发布时快照一致**」,不是「**运行中持续一致**」。

---

## 4. 检查清单

| # | 检查项 | 状态 | 证据 |
| --- | --- | --- | --- |
| 1 | 指纹来源为真实客户端采集,非手写 | ✅ | transport-poc 采集管线;bundle `capture_cohort` 含 claude.exe sha256 |
| 2 | bundle 签名信封(Ed25519 + JCS)+ 信任库分级 key | ✅ | `bundle.rs:394-417,547-567`;`bundle-trust-store.json` |
| 3 | 隐私闸(sensitive 字面量拒签) | ✅ | `bundle.rs:612-617` |
| 4 | 启动/上传/激活三处验签;historical key 不批新激活 | ✅ | `app.rs:442-495`;`admin_backend.rs:217-246` |
| 5 | 证据门(五类 evidence + privacy scan + replay) | ✅ | `admin_backend.rs:9202-9236` |
| 6 | 调度按 OS 硬闸,无匹配链拒绝、不降级 | ✅ | `production_dispatcher.rs:4658-4703` |
| 7 | 引擎精确匹配、禁止跨环境回退 | ✅ | `engine.rs:232-246` |
| 8 | 激活原子发布 + generation 单调 + 在途隔离 | ✅ | `engine.rs:284-334`;`admin_backend.rs:8882-8935` |
| 9 | H1 头序/大小写逐字渲染、framing、exact pool key | ✅ | `production_dispatcher.rs:3779-3864`;`h1.rs:42-94`;`pool.rs:11-39` |
| 10 | TLS1.3 cipher 顺序受控 | ⚠️ 由库默认决定,恰好一致 | `tls.rs:290-291` |
| 11 | signature_algorithms 受控 | ⚠️ bundle 无此字段 | tls-tap 可采,bundle 不表达 |
| 12 | 扩展顺序受控 | ⚠️ 仅 OCSP/SCT 开关生效 | `tls.rs:333-338` |
| 13 | record 分帧受控 | ⚠️ 仅事后核对 | `release_bundle.rs:328` |
| 14 | 运行时头集合/顺序与已验证模板一致 | ❌ 追加 2 头改变头数与序 | `production_dispatcher.rs:3839-3864` |
| 15 | 运行时头值与真实客户端行为一致 | ❌ beta 覆盖、Retry-Count 恒 0 | `production_dispatcher.rs:75,3796-3803` |
| 16 | 运行期持续指纹哨兵(实测 vs 声明) | ❌ TlsObservation 无人消费 | `tls.rs:157-167` |
| 17 | 运行期隔离安全网可用 | ✅ 已修复(F1,2026-10-01):仅翻转 runtime_state,回归测试覆盖 | `PgStorage::quarantine_transport_bundle_runtime` |
| 18 | session resumption 支持 | ❌ 整链未实现(当前与捕获一致) | `tls.rs:71`;transport-poc README |
| 19 | H2/HPACK 证据 | ❌ 无真实参考(h1 cohort 下无偏差) | `bundle.rs:113`;`transport-poc.md:287-288` |
| 20 | 请求节奏/pacing 拟态 | ❌ 仅 timing 分桶容差 | `wire-diff.rs:447-460` |

图例:✅ 受控且验证 / ⚠️ 声明-校验而非声明-执行 / ❌ 缺失或失效。

---

## 5. 修复建议(按性价比排序,均不动架构)

1. **P0 · 修 F1**:隔离 SQL 仅更新 `runtime_state_code`(详见 §2 修复方向);补一条"传输错误 → 事故落库 + 凭据隔离"的集成测试,防止再次回归。
2. **P1 · 收敛运行时头路径**:把追加的 `x-client-request-id` / `x-stainless-helper-method` 纳入 bundle 头模板(按位置插入),或让 formal replay 覆盖"运行时渲染路径";`anthropic-beta` 运行时值来源写进 bundle 或改为版本化常量表。
3. **P1 · 运行时指纹哨兵**:持久化 `TlsObservation` 并与 bundle 声明比对,漂移 → 告警/自动隔离(与 F1 修复联动后此路径才可用)。
4. **P2 · `X-Stainless-Retry-Count` 随 attempt.ordinal 递增**。
5. **P2 · TLS1.3 cipher / signature_algorithms 升级为 bundle 声明字段**:在 boring-sys 允许范围内接管,摆脱"恰好一致"。
6. **P3 · resumption / H2 / pacing**:按 transport-poc README 既定路线推进(需新采集证据)。

---

## 附:关键证据索引

- 隔离缺陷:`crates/super-gatewayd/src/production_dispatcher.rs:486-494`;约束:`crates/gateway-storage/migrations/20260824000700_r6_transport_contract.sql:32-44`
- 验签与三道闸:`crates/gateway-transport/src/bundle.rs:438-461,507-512,547-567,612-617`
- TLS 执行点:`crates/gateway-transport/src/tls.rs:71,116-129,257-342,333-342`
- H1 执行点:`crates/gateway-transport/src/h1.rs:42-94`;连接池:`crates/gateway-transport/src/pool.rs:11-39`
- 引擎目录:`crates/gateway-transport/src/engine.rs:156-173,232-246,284-334`
- 管理生命周期:`crates/super-gatewayd/src/admin_backend.rs:8347-9297,14207-14316`
- 运行时头渲染:`crates/super-gatewayd/src/production_dispatcher.rs:75,3779-3864,4080-4106`
- 发布期验证:`transport-poc/spike-cli/src/release_bundle.rs:275-404`;归一化:`transport-poc/wire-normalizer/src/lib.rs:653-665`
- catalog schema:`crates/gateway-storage/migrations/20260824000200_catalog_gateway.sql`、`20260824000700_r6_transport_contract.sql`
- 内置资产:`.super-gateway-local/bundles/windows-claude-code-2.1.241-h1.json`、`crates/super-gatewayd/assets/windows-claude-code-2.1.241-h1.signed.json`
