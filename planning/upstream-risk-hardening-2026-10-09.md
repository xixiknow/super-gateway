# 上游风控对抗设计笔记（吸收 sub2api-terra 对比结论，2026-10-09）

来源：对 sub2api-terra（Go/utls/Redis 流派的订阅池网关）的对比审计。结论：**不采纳其技术路线**
（utls 可配模板、Redis 分布式槽位、随机值+TTL 伪装），只吸收其检测点清单、fleet 多样性思路与事故教训。
本文固化三部分：Codex/OpenAI 检测点清单、设计红线、已关闭的审计项。

## 一、Codex/OpenAI 上游身份检测点清单

上游（chatgpt.com backend / Codex）按以下字段统计"设备数/会话数/线程数"来风控共享账号。
实现位于 `gateway-services/src/openai/session.rs` 与 `production_dispatcher/openai.rs`（dispatch_openai 建头段）。

| 字段 | 位置 | 派生规则 | 粒度 |
|---|---|---|---|
| `session_id` | 头 + `prompt_cache_key` | HMAC(`openai-session-v1`, namespace→seed; key, account, base_session)，URL-safe base64 | 凭证+key+base_session |
| `thread-id` | 头 | UUIDv4 位（HMAC `openai-thread-v1`，同上输入） | 同 session（一个上游线程/会话） |
| `x-codex-window-id` | 头 + client_metadata | `{thread_id}:0` | 跟随 thread |
| `x-codex-installation-id` | 头 + client_metadata | UUIDv4 位（HMAC `openai-installation-v1`; account） | **凭证恒定**（设备等价物） |
| `x-codex-turn-id` | client_metadata | 每请求 UUIDv7 | 每请求 |
| `x-codex-turn-metadata` | 头 | JSON `{turn_id, window_id, prompt_cache_key}`，同一请求内三载体一致 | — |
| `user-agent` | 头 | 固定 `codex_cli_rs/0.120.0 (Windows)`（仓库内真实样本，client_identity.rs:73） | 全局 |
| `originator` | 头 | `codex_cli_rs`（原状） | — |

约束与事实：
- 真实 Codex 客户端的 session_id 是进程级随机 UUID、会话内不变。基线证据：`open-project/CLIProxyAPI`
  （vendored）`codex_executor_request.go` 展示完整头集合与 body `client_metadata.*` 形态。
- WebSocket 路径身份头只在握手发一次（`openai_http.rs:92-149`）；per-turn 字段（turn_id）进每 turn 的
  `response.create` body。连接身份围栏（account+token_version+installation 摘要，`openai.rs:351-360` 一带）
  变化即断开重连——**session_namespace 轮换必须触发重连**（已纳入 version 摘要）。
- Anthropic 侧对照：`derive_session_id`（session_hmac，Agent 不参与输入，main/subagent 共享 prompt cache）、
  `derive_device_id`（profile_seed + device_epoch）。所有派生确定性，同输入字节级可复现。

## 二、设计红线（事故教训）

1. **会话级身份禁止收敛为凭证常量**。sub2api-terra v0.1.175 曾把 Codex 五类 ID 默认收敛为账号常量，
   上游按设备/会话计费导致额度缩水，被迫改回 opt-in。我们的对应纪律：
   - installation（设备等价物）→ per-credential 恒定，唯一允许的常量；
   - thread/session/window → per-credential+base_session（HMAC 派生，天然不同凭证不同值）；
   - turn → 每请求。
2. **failover 会话身份隔离**：同一会话身份绝不能经两个上游账号发出。回归测试钉死：
   `thread_follows_session_but_not_credentials`（session.rs 测试，跨 key/跨账号必变）。
3. **不透传客户端身份头**：入站头整体丢弃重建（openai_http.rs `*upstream.headers_mut() = headers`），
   禁止把租户真实 installation/session 泄漏给上游。

## 三、TLS / Bundle 审计结论（已关闭项）

1. **extension_order 14 vs 10 差异——无偏差**。内置 Bundle asset
   （`crates/super-gatewayd/assets/windows-claude-code-2.1.241-h1.signed.json`）的 extension_order 为 14 项
   （含 5=OCSP、18=SCT），但 `transport-poc/var/real-capture/` 的官方采集与我们自己的 TLS 回放
   （`windows-2.1.241.tls-replay.normalized.json`）均为 10 项、251 字节、无 GREASE/ECH；tls-wire-diff 报告
   decision=PASS（BEHAVIORAL_MATCH）。资产内的 14 项与 client_hello_len=512 属证据面元数据不一致
   （extension_order 在 TlsProfile 中标注为审计用途；tls.rs build_connector 仅对 5/18/grease/permute 真实生效），
   **不构成 wire 指纹偏差**。B5 修复不触发。
2. **ECH GREASE（扩展 65037）**：boring 5.2.0 提供 `set_enable_ech_grease` 但工程未接线；当前 cohort 真实
   采集无 ECH 扩展，暂不实现。若未来目标环境（Cloudflare 前置）开始要求，需在 TLS 层新增能力并在
   Bundle schema 增加对应 capability 字段。
3. **dateline 隐写（sub2api-terra 的 anthropicfp/dateline）**：无需修正。"Today's date is..." 句由真实客户端
   写入 messages 的 system-reminder，网关对 messages 字节级透传，撇号变体（U+2019/U+0027）天然保真；
   网关改写只落在顶层 system（Environment 三字段、billing 块、beta 对称）。红线：将来给 archetype version
   填 system_template 时不得把含日期/月份的动态段冻结进模板（`replace_system_static` 机制已防住）。

## 四、本轮落地清单

- B1 Codex 身份收敛：session.rs 四个派生函数 + dispatch_openai 头/body 改写 + WS 围栏纳入 installation。
- B2 SSE 排队保活：`bridge_queued_stream`（提前 200 SSE + `: keep-alive` 注释行 + 桥接任务）+
  `EarlyStreamCompletion` + `complete_early_delivery`；仅 Messages 流式 + Queued 路径，失败以
  `event: error` 终止（早提交后状态码不可变）。
- B3 凭证级 pacing：`min_request_interval`（CredentialConfig/scheduler eligibility/grant 前置门）+
  migration `20261009000100_credential_pacing.sql` + admin 补丁命令 `min_request_interval_ms`
  （NULL=禁用）+ contract schema。默认关（None）。
- B4 Bundle 多版本 cohort（canary 按凭证分组）：**后置未实现**——卡点
  `archetype_one_active_bundle_uq` 部分唯一索引 + 调度 SQL canary/active 等价；需先有第二个真实采集
  Bundle 才有意义，单独立项。
