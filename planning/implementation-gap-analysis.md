# 实现差距审计与补齐计划

> 审计日期：2026-08-28
> 方法：三路并行审计——(1) 通读 `implementation-roadmap.md`、`technical-architecture.md`、`domain-model.md`、`functional-modules.md`、全部 `evidence/` 验收文档与三份 ADR；(2) 以七份后端设计文档（scheduler / credential-lifecycle / transport-engine / request-pipeline / security-design / operations-runbook / database-schema）逐项对照 `crates/` 实现；(3) 以 `admin-console.md` 与 196 条 API 契约路由对照 `web/admin-console` 前端。所有结论均有代码文件与行号依据。

## 一、官方进度基线

- 路线图共 **R0–R10** 十一个阶段；四份 evidence 文件（r3-r4 / r6 / r7 / r10）声明的均为「**本地闭环**」，**明确未达 RC/GA**。
- **R8（管理台）验收明确「本次不含前端」**：后端 196/196 路由闭环，但前端深度、关键 E2E、WCAG 2.2 AA 属于官方承认的未完成区。
- R10 GA 收口缺：24h soak、45 天恢复演练、全部 Active Archetype 外部证据、GA trace ledger。

## 二、不算欠账的三类（排除项）

### 2.1 设计上明确延后（`functional-modules.md` §11）

多 Provider（Bedrock/Vertex）、OpenAI 兼容北向协议、商业计费、Redis/多实例/owner 自动故障转移、模型自动切换与别名重写、响应 Body/SSE 改写、WebSocket、忘记密码/MFA 丢失自助恢复、面向客户端的 availability 端点等 11 项。

### 2.2 首版范围内但默认/强制关闭

- H2 Bundle 激活：无 wire evidence 时硬拒绝（`production.rs:85`），且 H2 帧/HPACK 执行引擎本体未实现
- TLS 会话恢复：loader 与 TLS connector 双重关闭（`bundle.rs:523`、`tls.rs:71`）
- Session 槽、全文审计（默认 metadata-only）、Bundle 自动联网获取、主动模型验证等
- **Windows 开发机限制**：enrollment 交换 / 凭据维护 / PLAN 采集 / 受控浏览器均被 `cfg` 关闭（`app.rs:293-330`），凭据全链路端到端验证需 Linux 环境

### 2.3 外部证据阻断（非写码可解）

Linux native BoringSSL/sanitizer 验证、真实 N-1/N-2 升级（ADR-0003：首个 schema release 前保持 planned）、外部 KMS/KeyProvider、真实 SMTP/Webhook/systemd 演练、24h soak、45 天恢复演练、GA 账本。

## 三、真实缺口清单

### 3.1 后端（Rust）

| 编号 | 缺口 | 证据 | 状态 |
|------|------|------|------|
| B1 | 上游 Session 派生混入 `agent_id`，与 request-pipeline.md §11、database-schema.md L656/L1738 三处合同冲突 | `production_dispatcher.rs` `derive_session_id` 3487-3492 及调用点 1173-1177 | **已定方案并修复中**：去掉 agent 入参；Agent 的公平队列（fair_queue 三层 DRR）与 affinity（AffinityKey 含 agent_id）用途不受影响；上游 UUID 不落库、未 GA，无迁移风险 |
| B2 | 约 35 个 admin list 端点假分页：固定 `LIMIT 100` + `has_more:false`，契约 `page[size]/page[after]` 未消费（真分页仅内容审计搜索、升级检查 2 处） | `admin_backend.rs` `list_response` 15301 | 待做（P2） |
| B3 | `GET /admin/v1/credentials` 无 lifecycle 过滤参数（前端暂以客户端过滤兜底） | `admin_backend.rs:5086-5108` | 待做（P2，随 B2） |
| B4 | `GET /admin/v1/exports` 全量列表端点缺失（仅 create/get/download），导致前端导出页无表可列 | OpenAPI `/admin/v1/exports` 路径；`App.tsx` `/exports: null` | **进行中**（P1）：经 `planning/api-contract.md` 路由表新增 GET 行 → `tools/generate_contracts.py` 再生成契约 → 后端补 `getExports` 分发与 handler |
| B5 | `telemetry.token_estimate` 有表无写入路径（内部 Count Tokens 服务链未实现） | migration `20260824000300`；crates 内零 INSERT | 待做（P4） |
| B6 | 运维 CLI 子命令（bundle verify / release verify / transport probe） | 二进制无 clap 子命令 | **经确认不做** |
| B7 | 内存保护未落地：security-design §20 的 mlock / PR_SET_DUMPABLE 全库无匹配（仅 zeroize） | 全仓 grep | 待做（P4） |
| B8 | gateway-transport / gateway-scheduler / gateway-api 无 crate 级集成测试 | 各 crate 无 tests/ 目录 | 待做（P4） |
| B9 | 分组凭据数已修复为排除 `revoked/archived`（对齐全库统一口径），但 cargo check 曾被中断未确认编译 | `admin_backend.rs` list_groups / get_group | **随本轮统一编译验证** |

### 3.2 管理台前端（对照 `admin-console.md`）

| 编号 | 缺口 | 优先级 |
|------|------|--------|
| F1 | Group 详情六页签 + 配置版本发布链（validate → publish-shadow → promote-canary → simulate → activate → rollback）+ 实时容量 + 组内凭据——设计定位的产品核心，现仅列表壳 | P1 |
| F2 | Credential 详情五页签（详情/调度配置/维护记录/reauth 策略/浏览器操作）+ begin-recovery / migrate-group / rebind-egress / rebuild-device / refresh-token / 注册 `:cancel` | P1 |
| F3 | Content Audit 整族 UI（search sessions / 正文解密读 / 导出 / Legal Hold / 清理 Job）——`/security` 页名实不符 | P3 |
| F4 | 导出任务追踪：有创建无状态轮询与下载（依赖 B4） | P1 |
| F5 | 请求详情时间线（`requests/{id}` + attempts）与 `usage/timeseries` | P1 |
| F6 | 运维子页：备份 Job/运行记录、演练、恢复预检、升级检查历史、KeyProvider 轮换 | P3 |
| F7 | 治理版本族：enforcement / background-catalog / price / plan-mapping 四族 UI；ruleset 的 validate/simulate/activate | P3 |
| F8 | 告警配套：silence 列表与结束、通知渠道（SMTP/Webhook）CRUD 与测试 | P3 |
| F9 | 详情页族：users/{id}+sessions、approval case 详情、proxy 详情+bindings、egress-bindings、credential-profiles、models/{id}、archetype 详情 | P3 |
| F10 | Key Owner 体验：Owner 专属首页（现指标全为 "—"）、Owner 向文案、dashboard summary 接入、会话到期提醒 | P3 |
| F11 | 分页规约不一致：设计要求服务端 cursor、不显示精确 total；现为客户端切片过渡方案 | P2（随 B2 归位） |

### 3.3 契约层结论

- OpenAPI 196 个 operationId 后端 dispatch **全覆盖**，缺口几乎全在前端消费层
- 契约文件为生成物：`planning/api-contract.md` 路由表 → `tools/generate_contracts.py` → `contracts/*`；改契约必须改源头再生成，禁止手改 JSON

## 四、已做出的决策

1. **B6 不做**（2026-08-28 确认）
2. **B1 改代码对齐文档**（2026-08-28 确认）：同一 Base Session 的 main 与 subagent 共享上游会话，恢复 prompt cache 共享；固化旧行为的单元测试一并修正

## 五、补齐顺序

- **P0（bug 与遗留）**：B1 Session 派生修复；B9 编译验证 —— 修复已完成，待统一编译验证
- **P1（管理台核心深度）**：F1 Group 详情 → F2 Credential 详情 → F5 请求详情/时序 → F4+B4 导出闭环
- **P2（契约还债）**：B2 真 cursor 分页统一改造（~35 端点）+ B3 lifecycle 过滤 + F11 前端对接归位
- **P3（面上补齐）**：F3 内容审计、F6 运维子页、F7 治理版本族、F8 告警配套、F9 详情页族、F10 Owner 体验
- **P4（系统性）**：B5 token_estimate 写入、B7 内存保护、B8 集成测试

## 六、近期已完成（不在缺口内，供对照）

- 管理台星河液态暗色主题改版（亚克力材质、星空背景、登录页重设计、双语文案）
- 下拉框点击空白性能问题定位与修复（backdrop-filter 合成开销）
- 通知中心：高不透明浮层、详情独立对话框、外部点击关闭、全部已读图标
- 凭据注册续办流程（OAuth 授权页打开/回调自动拆分与 state 预填/材料提交/状态轮询）
- 凭据表单认证方式卡片单选；全站表格客户端分页（过渡）、创建按钮图标化、刷新加载反馈；凭据列表归档过滤（过渡）
- 分组凭据数排除已归档/已吊销（待编译验证）
