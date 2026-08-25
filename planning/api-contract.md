# Claude Code 企业网关 API 合同

> 状态：详细设计基线  
> 上位文档：[功能模块规划](functional-modules.md)、[技术架构](technical-architecture.md)、[领域模型](domain-model.md)、[数据库设计](database-schema.md)  
> 适用范围：首个单实例 Linux Rust 版本  
> 北向协议：Anthropic Messages / Models 兼容协议 + `/admin/v1` 管理 API

## 1. 文档目的与决策权威

本文冻结平台所有 HTTP 可观察合同，包括：

- 数据面路由、认证、Header、Body、SSE、错误与透明响应；
- 管理面资源路径、字段、权限、分页、条件写、幂等和异步 Job；
- Platform Admin 与 Key Owner 的可见范围和字段脱敏；
- Content Audit、审批、导出、告警、备份与升级的管理入口；
- OpenAPI 拆分、兼容策略和 contract test 门禁。

决策优先级为：功能规划 > 技术架构 > 领域模型 > 数据库设计 > 本文。本文可细化路径和字段；若变化会扩大公开端点、改变透明响应、放宽 Group Enforcement、暴露 Credential 内部状态或改变已确认错误，则先修订上位规划。

本文使用 claude-api 原始 HTTP 合同作为 Anthropic 外形参考：Messages 使用 `POST /v1/messages`、JSON 请求和可选 SSE；`content-type: application/json`、`anthropic-version` 与认证 Header 参与协议处理。模型、参数与 beta 能力的合法性仍由平台版本化 Model/Capability Snapshot 决定，不硬编码某个当前模型。

## 2. 首版范围与非目标

### 2.1 数据面注册路由

| Method | Path | 认证 | 资源域 |
|---|---|---|---|
| `POST` | `/v1/messages` | Platform Key | Messages RPM、Key 并发、Group、Credential；非流式还有 Reservation |
| `GET` | `/v1/models` | Platform Key + models 权限 | 独立 Models RPM |
| `GET` | `/healthz` | 无 | 独立来源 IP 限速 |
| `GET` | `/readyz` | 无 | 独立来源 IP 限速 |

首版没有以下公开能力：

- `/v1/messages/count_tokens`；
- `/v1/gateway/availability`；
- OpenAI 兼容路径；
- 多 Provider 路由参数；
- 模型 alias、自动降级或自动切换；
- WebSocket 或 SSE/WS 转换；
- 数据面请求幂等去重、SSE replay、响应领取。

`/v1/messages/count_tokens` 在任何 Method 下都视为未知 `/v1/*`。内部 Token Estimate 不形成公开端点、权限项或 `Allow` 内容。

### 2.2 管理面

管理 API Base Path 固定为 `/admin/v1`。管理控制台静态资源、管理 API 和数据面共享进程，但使用独立 Router、Session、CSRF、限流和审计策略。首版只有 Platform Admin 和 Key Owner 两种外部角色；没有 viewer、AccessSubject、应用主体或 Tenant 资源。

### 2.3 南向边界

南向只连接 Anthropic 官方 Messages/Auth/Profile 等已经批准的精确域名。客户端 Header、URL、model 或 metadata 无权改变南向 authority。上游认证、UA、Attribution、Metadata、Session、Archetype、Bundle 和 Egress 都由选中的 Credential Profile 重建。

## 3. API 分面、版本与兼容策略

### 3.1 数据面版本

- Path 兼容 Anthropic `/v1`；`anthropic-version` 由 Capability Snapshot 验证。
- Beta 使用客户端 `anthropic-beta`、Group/Key 权限和 Credential Profile 能力的交集。
- 平台禁止把客户端未请求的业务 beta 静默加入；仅身份相关的兼容 Header 由 Profile 规则生成。
- 数据面字段新增遵循 compatible/strict 模式；已知字段语义变化必须发布新 Capability Snapshot。

### 3.2 管理面版本

- 首版路径版本为 `/admin/v1`。
- 向后兼容的可选响应字段可追加；客户端应忽略未知响应字段。
- 字段删除、类型改变、枚举语义改变或路径重构进入新的 `/admin/v2`。
- 管理 Request 可通过 `Accept: application/json`；响应统一 UTF-8 JSON，Content Audit 明文/导出下载除外。

### 3.3 OpenAPI 文件

实现阶段生成：

```text
openapi/
├── data-plane.yaml
├── admin-auth.yaml
├── admin-core.yaml
├── admin-operations.yaml
└── components.yaml
```

`data-plane.yaml` 只出现四个注册路由。CI 必须断言 Count Tokens、Availability、Provider 参数和任何管理路径均未进入数据面 OpenAPI。

## 4. HTTP、TLS、Media Type 与大小

### 4.1 通用 HTTP

- 外部 TLS 终止策略由部署配置决定，生产只接受 TLS 1.2+；管理面推荐只通过同源 HTTPS 或受限管理网段访问。
- 数据面 Messages 请求只接受 `application/json`，允许标准 `charset=utf-8` 参数。
- JSON 编码为 UTF-8；非法编码进入通用 400。
- Request body 读取采用 Content-Length 快速检查与流式累计双限制。
- 生效上限为 `min(platform_hard_limit, key_body_limit)`；413 中隐藏上限数值。
- gzip 等请求体压缩首版不启用，避免解压炸弹和 wire/审计歧义；响应 Content-Encoding 由上游透明保留。

### 4.2 Body 所有权

原始 Body 只读一次并进入受限 `SensitiveBytes`。解析层、审计旁路和 deterministic serializer 通过只读 handle 访问。普通请求 Body 不落数据库、日志、Trace 或响应临时目录；full encrypted Content Audit 只接收去秘密和审计脱敏后的副本。

## 5. 通用标识、时间和数值编码

| 类型 | API 编码 |
|---|---|
| Typed ID | 带前缀字符串，如 `usr_...`、`grp_...`、`cred_...`、`req_...` |
| 时间 | RFC 3339 UTC，如 `2026-08-24T08:00:00Z` |
| Duration | 整数毫秒，字段后缀 `_ms` |
| Bytes | 非负整数，字段后缀 `_bytes` |
| Token | 非负整数；未知时为 `null`，不以 0 替代 |
| Revision | 正整数，并同时进入 `ETag: "rev-N"` |
| Epoch/Version | 正整数或稳定版本字符串 |
| 金额 | 十进制字符串 + `currency`，禁止 JSON 浮点 |
| Ratio | 十进制字符串 `0..1` |
| IP/CIDR | 标准文本；仅在有权管理范围内返回 |

外部 ID 不包含数据库 sequence、Credential account UUID、Proxy password、Profile seed、Session HMAC 或内部分区信息。

## 6. Request ID、Correlation 与 Trace

### 6.1 数据面

- Edge 为每次连接请求先生成平台 RequestId，格式 `req_...`。
- 平台自产 JSON 错误同时返回 `request-id` Header 和 Body `request_id`，两者相同。
- 上游最终响应保持 Anthropic 自有 `request-id` Header 与原 Body；平台 RequestId 只进入内部 RequestRecord，不覆盖上游 Header。
- 客户端 `x-client-request-id`、`traceparent`、`tracestate` 只作为受控关联信息，禁止成为 Credential Session 派生输入。

### 6.2 管理面

所有管理响应含 `request-id` Header；JSON 包络 `meta.request_id` 或错误顶层 `request_id` 与之相同。批量和异步 Job 另返回 `correlation_id`，用于关联每项 AuditEvent。

## 7. 数据面 Platform Key 认证

### 7.1 接受的 Header

为兼容 Claude Code、Harness 和主流 Anthropic SDK，北向接受两种等价编码：

```http
x-api-key: PLATFORM_KEY_SECRET
```

```http
Authorization: Bearer PLATFORM_KEY_SECRET
```

规则：

1. Query、Cookie、Body 中的值均不参与 Platform Key 认证。
2. 两种 Header 同时出现时，规范化后必须相同；冲突、重复多值、空值或畸形均进入统一 401。
3. `Authorization` 只接受单一 Bearer scheme，不接受 Basic、Digest 或额外参数。
4. 成功鉴权后，两类 Header 与原 secret 立即从请求对象移除。
5. 北向 secret 不进入南向；上游认证完全由 Credential Profile 重建。
6. 客户端 Header 编码只影响入口兼容，Key identity、RPM 与并发计数保持一致。

### 7.2 统一认证失败

缺失、畸形、不存在、过期、禁用和吊销使用完全相同的客户端结果：

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
request-id: req_...
```

```json
{
  "type": "error",
  "error": {
    "type": "authentication_error",
    "message": "Invalid API key."
  },
  "request_id": "req_..."
}
```

响应不含 `retry-after`、Key prefix、状态、到期信息或授权端点。内部安全事件保留真实原因码和脱敏来源。

## 8. 数据面路由与 Gate 顺序

固定顺序：

```text
RequestId
→ route classification
→ Platform Key authentication
→ method contract
→ endpoint permission
→ trusted proxy / source IP allowlist
→ Content-Length + streaming body limit
→ JSON/basic parse
→ Client/Session/Traffic classification
→ Key Messages RPM / special traffic gate
→ Key concurrency
→ Snapshot/Capability/Rule/Enforcement
→ Group admission / Reservation / Lease
```

关键语义：

- 未知 `/v1/*` 先鉴权；异常 Key 401，有效 Key 404。
- 已知 `/v1/messages`、`/v1/models` 使用错误 Method 时先鉴权；异常 Key 401，有效 Key 405。
- `HEAD`、`OPTIONS` 首版也进入 405。
- Count Tokens 永远走未知路由 404，不进入 405，也不出现在 `Allow`。
- Endpoint/IP/Client Class 拒绝发生在 Key 并发和 Group 资源之前。
- Key Messages RPM 先于 Key 并发；被 RPM 拒绝的请求不占并发。

## 9. `POST /v1/messages` 请求合同

### 9.1 请求示例

```http
POST /v1/messages HTTP/1.1
Host: gateway.example.internal
Content-Type: application/json
x-api-key: PLATFORM_KEY_SECRET
anthropic-version: 2023-06-01
```

```json
{
  "model": "MODEL_ID",
  "max_tokens": 4096,
  "messages": [
    {"role": "user", "content": "Hello"}
  ],
  "stream": true
}
```

### 9.2 结构化字段

平台至少识别：

```text
model, max_tokens, messages, system, stream,
temperature, top_p, top_k, stop_sequences,
tools, tool_choice, thinking, metadata,
output_config, context_management
```

具体 required/allowed/forbidden、类型、范围、条件和模型差异来自请求冻结的 Capability Snapshot。`thinking.type` 等随模型演进的字段通过数据化 conditional 扩展，禁止在 API Router 中累积 model-specific 分支。

### 9.3 Presence 与未知字段

- 缺失、显式 `null`、具体值三种状态分别保留。
- compatible 模式保留未知顶层字段、content block、tool schema 和扩展字段。
- strict 模式对未知字段返回稳定 400。
- 合法且未命中显式 RuleSet 的业务字段保持原值。
- 客户端 `model` 字符串保持原样；平台禁止 alias、fallback 或自动切换。

### 9.4 Body 构造

- 无业务调整时优先复用原始 Body 字节。
- 有调整时使用冻结版本的 deterministic serializer。
- GenericAdjustedRequest 跨 attempt 保持不变。
- 每次 Credential retry 都从 GenericAdjustedRequest 重新应用新 Profile，禁止在旧 FinalUpstreamRequest 上替换认证后复用。
- 数据面不按 Idempotency-Key 去重；客户端重试形成新的 RequestId。

### 9.5 响应模式

`stream=true` 走 SSE；缺失或 false 走非流式完整缓冲。`Accept` Header 只参与基本兼容检查，最终模式由 Body 明确值决定。

## 10. Messages 非流式响应合同

### 10.1 提交点

平台完整接收 Anthropic status、Header 和原始 Body，经大小、存储完整性和 Header Policy 检查后，才向客户端 commit。Body 禁止反序列化后重排、重编码或包裹。

### 10.2 缓冲

| 项目 | 默认 |
|---|---:|
| 内存阈值 | 8 MiB |
| 单响应硬上限 | 64 MiB |
| 实例总 Reservation | 2 GiB |
| 保障槽 | 32 |
| Reservation 等待队列 | 64 |
| 客户端 write idle | 120 秒 |
| 客户端 delivery total | 300 秒 |

超过内存阈值后无损切换到每文件随机 DEK/AEAD 的临时文件。临时文件无管理查看、领取、审计复用或重启恢复路径，终态后立即销毁。

### 10.3 资源

- Credential Lease 在完整收到上游 Body 时释放。
- Key/Group permit 与 Reservation 持有到交付成功、取消、失败或缓冲销毁完成。
- 完整上游成功但客户端写失败时，Attempt 仍为 success、usage complete、成本正常计算。
- 客户端交付失败、idle/total timeout、commit 后取消均不会触发上游 retry 或 Credential 切换。

## 11. Messages SSE 流式响应合同

### 11.1 Content Type 与 commit

上游最终 `2xx` SSE Header 到达、Header Policy 完成且客户端 writer 建立后立即 commit，不等待第一个 event。`Content-Type: text/event-stream` 和原始 Content-Encoding 保持上游值。

### 11.2 字节透传

- 上游 SSE bytes 到达即进入有界窗口并 flush。
- 平台不拆分、合并、重排、重编码或注入 event。
- 上游 `ping` 作为原始字节转发，同时重置内部 upstream idle timer。
- usage/audit parser 只旁路观察完整事件边界，解析故障不阻塞主 writer。

### 11.3 背压和超时

| 项目 | 默认 |
|---|---:|
| 每请求 pending window | 1 MiB |
| upstream stream idle | 30 秒，可配 5–600 秒 |
| client write idle | 120 秒，仅 pending 非空时运行 |
| cancel grace | 2 秒 |

pending window 满时暂停上游读取；暂停期间 upstream idle timer 同步暂停，由 client write idle 负责。窗口下降后继续读取。流式没有绝对交付总时限。

### 11.4 commit 后终态

已 commit 后发生上游截断、平台异常、upstream idle、client backpressure timeout 或客户端取消时：

- 保留已经交付的 status、Header 和 SSE bytes；
- 取消/关闭对应上游 stream；H1 连接逐出，H2 只 reset 当前 stream；
- 关闭客户端响应；
- 无第二个 JSON 响应、无 Gateway error event、无伪 message_stop、无另一 attempt 拼接；
- usage 为 complete/partial/unknown 中的真实状态，缺失不会记为 0。

## 12. `GET /v1/models` 合同

### 12.1 请求

```http
GET /v1/models?limit=20&after_id=MODEL_ID HTTP/1.1
x-api-key: PLATFORM_KEY_SECRET
```

`limit` 默认 20、最大 100；`after_id` 使用模型 ID。未知 query 字段返回 400，不静默忽略。

### 12.2 响应

```json
{
  "data": [
    {
      "id": "MODEL_ID",
      "type": "model",
      "display_name": "DISPLAY_NAME",
      "created_at": "2026-08-24T00:00:00Z"
    }
  ],
  "has_more": false,
  "first_id": "MODEL_ID",
  "last_id": "MODEL_ID"
}
```

可见集合严格为：

```text
published Model
∩ Group model scope
∩ Platform Key model scope
```

Credential 冷却、满载、代理故障、实时 queue 或临时无 Lease 不影响模型列表。模型从 published 进入 deprecated/disabled 后从新列表移除；已开始请求继续遵守冻结 Snapshot。

### 12.3 限流

Models 使用每 Key 独立默认 60 RPM/burst 10，不占 Messages RPM、Key 并发、Group 队列、Session、Credential Lease 或 usage。

## 13. `/healthz` 与 `/readyz`

### 13.1 Health

```http
GET /healthz
```

事件循环可响应即返回：

```json
{"status":"ok"}
```

Health 不查询 PostgreSQL、Anthropic、Credential 池或 Proxy。

### 13.2 Ready

```json
{"status":"ready"}
```

或：

```json
{"status":"not_ready"}
```

ready 要求 PostgreSQL/migration、Active 配置、Business KeyProvider、TransportCore、必要 Active Bundle 和 application lifecycle 正常。冷启动或恢复时还要求 Audit Chain、AuditIntegrity KeyProvider 与 Deletion Ledger 完整。实例已 serving 后才发现审计完整性异常时保持数据面 ready，但冻结高风险管理动作并产生 critical 告警。ContentAudit KeyProvider 只影响 `full_encrypted` 请求；Backup KeyProvider/仓库故障不撤实例 ready。某个 Group 无 Credential、全部冷却、Proxy 故障、PLAN/通知/统计 Job 失败时实例仍保持 ready。

Health/Ready 使用来源 IP 独立默认 120 RPM/burst 20，不创建 Platform Key、RequestRecord、Session、Agent 或 usage。成功与未就绪响应固定携带 `Content-Type: application/json` 和 `x-gateway-response-source: gateway`；不得携带版本、依赖、拓扑或失败原因。

来源 IP 限速耗尽时固定返回 HTTP 429、`{"status":"rate_limited"}`、`Content-Type: application/json`、`x-gateway-response-source: gateway` 与 `retry-after`。`retry-after` 按下一枚令牌时间向上取整且至少 1 秒。该 429 仍与所有 Platform Key、Group、Session、Agent、Credential 及 usage 资源隔离。

## 14. Header 过滤与透明透传

### 14.1 入站 Header 类别

| 类别 | 例子 | 处理 |
|---|---|---|
| Platform Key | `x-api-key`、`authorization` | 鉴权后删除 |
| Anthropic 协议 | `anthropic-version`、`anthropic-beta` | 解析/Capability/Profile 输入 |
| Body/framing | `content-type`、`content-length`、`transfer-encoding` | Edge 使用，Transport 重建 |
| Client evidence | `user-agent`、Stainless、`x-app` | 仅内部 ClientContext |
| Session/trace | Claude Session Header、`traceparent` | 归一化/内部观察 |
| 来源/代理 | `host`、`forwarded`、`x-forwarded-*`、`x-real-ip`、`via` | 删除；可信代理解析只用于入口安全 |

Gateway Base URL、原 Host、Forwarded、来源 IP、真实客户端 UA 和 Platform Key 均不会传给 Anthropic。

### 14.2 上游响应 Header

分类：

1. hop-by-hop：删除；
2. Credential 内部：Anthropic 单凭据 RPM/配额/cooldown Header 只更新内部状态；
3. 安全可转发：Content-Type、Content-Encoding、上游 request-id、缓存和 retry 语义按策略保留。

首版不额外注入 `x-gateway-ratelimit-*` 成功 Header，避免扩大客户端依赖面。平台自产 429 只使用对应错误合同的 `retry-after`；Group/Credential 数量、单凭据配额与恢复原因保持内部可见。

### 14.3 Body

真实 Anthropic success/error Body 与 SSE 保持原始字节。上游最终错误保持原包络、原 message，且不加入平台 RequestId。只有平台在调用上游前或非流式 commit 前生成的本地错误使用第 16 章包络。

## 15. Deadline、Retry、Cancel 与 Commit

### 15.1 Deadline

- Group RPM、Group concurrency/fair queue 与 Reservation 三类提交前等待共享一个默认 30 秒绝对 deadline，阶段切换不重置。Key RPM 与 Key 并发均立即决策，不形成等待阶段。
- 新连接默认 timeout 5 秒，可按 Group 配置 1–30 秒。
- 非流式 attempt 1 首字节创建默认 300 秒 upstream total deadline，attempt 2/3、refresh、backoff 和 Credential 切换共享。
- 流式完整提交后启用默认 30 秒 upstream idle，收到 Header、SSE bytes 或 ping 重置。
- 下一 retry 所需剩余预算至少 5 秒。

### 15.2 Attempt

- 每 Request 最多 3 条 ConnectionAttemptRecord、3 条 Messages AttemptRecord，两个预算独立。
- DNS/TCP/Proxy/TLS/ALPN 在零上游请求字节时只消耗 ConnectionAttempt。
- Transport 实际写出首个上游请求 byte 才计 Messages Attempt。
- 三次纯建连失败产生 0 个 Attempt 与 0 条 usage。

### 15.3 Retry

Retry 同时要求：客户端未 commit、Body 可重放、错误类别允许、attempt/deadline 尚有预算、候选可用、portability 允许。

```text
401: Attempt1(A) → singleflight refresh → Attempt2(A)
     → 第二次401且Portable → Attempt3(B)
429: 消费可信 Retry-After；Portable 可重调度
500/502/503/504/529: 有界抖动退避
400/403/404/409/422: 最终响应
```

跨 Credential retry 先终止旧 Transport、释放旧 Lease，再获取新 Lease并从 GenericAdjustedRequest 构造完整 Final。无 speculative racing。

### 15.4 Cancel

客户端取消立即结束 Session/Agent 活跃引用并释放 Key/Group permit；QueueTicket 原子取消。上游可能仍活动时，Lease 等待 Transport 确认或默认 2 秒 grace，随后强制 reset/close。非流式 Reservation 在 buffer 与临时 DEK 销毁后释放。

### 15.5 Commit

- SSE：最终可转发 Header commit 后 retry 永久结束。
- 非流式：完整 Body、大小/存储/Header policy 完成后 commit；commit 后无上游 retry。
- commit 后任何故障都只关闭/reset 当前响应，不构造第二个错误。

## 16. 数据面平台错误矩阵

### 16.1 标准包络

```json
{
  "type": "error",
  "error": {
    "type": "api_error",
    "message": "Internal server error."
  },
  "request_id": "req_..."
}
```

Header profile：

- `H0`：JSON Content-Type + 同值 `request-id`；
- `HR`：H0 + 整数秒 `retry-after`；
- `HM`：H0 + `Allow`。

### 16.2 矩阵

| 场景 | HTTP / type / message | Header | 平台自动 retry |
|---|---|---|---|
| Key 异常 | 401 / `authentication_error` / `Invalid API key.` | H0 | 否 |
| 有效 Key + 未知 `/v1/*` | 404 / `not_found_error` / `The requested resource could not be found.` | H0 | 否 |
| 已知路径错误 Method | 405 / `invalid_request_error` / `Method not allowed.` | HM | 否 |
| Endpoint/IP/Client Class/Group 管理状态 | 403 / `permission_error` / `This request is not permitted.` | H0 | 否 |
| Explicit Probe reject | 同 403 | H0 | 否 |
| Body 超限 | 413 / `request_too_large` / `Request is too large.` | H0 | 否 |
| JSON/Content-Type/基础结构 | 400 / `invalid_request_error` / `Invalid request body.` | H0 | 否 |
| 模型不可用 | 400 / `invalid_request_error` / `The requested model is not available for this API key.` | H0 | 否 |
| 字段/Capability | 400 / `invalid_request_error` / 安全首项诊断 | H0 | 否 |
| Key RPM/并发 | 429 / `rate_limit_error` / `Rate limit exceeded.` | HR，至少 1 秒；并发默认 2 秒 | 否 |
| Probe throttle | 429 / `rate_limit_error` / `Rate limit exceeded.` | HR，两桶较大恢复值 | 否 |
| Group RPM timeout | 429 / `rate_limit_error` / `Rate limit exceeded.` | HR，默认 5 秒 | 否 |
| 全候选长 cooldown | 同 429 | HR，Group 最早恢复值 | 否 |
| Group queue full | 503 / `api_error` / `Service temporarily unavailable.` | HR，默认 2 秒 | 否 |
| Group/Reservation wait timeout | 同 503 | HR，默认 5 秒 | 否 |
| Buffer admission full | 同 503 | HR，2 秒 | 否 |
| Owner/确定性无 Credential | 同 503 | H0 | 否 |
| Required Audit 首字节前失败 | 同 503 | HR，5 秒 | 否 |
| 非超时连接恢复耗尽 | 同 503 | H0 | 否 |
| Capability runtime conflict | 500 / `api_error` / `Internal server error.` | HR，1 秒 | 否 |
| 未提交的未知平台异常 | 同 500 | H0 | 否 |
| 已提交/结果未知平台异常 | 同 500 | H0 | 否 |
| 非流式接收中平台异常 | 同 500 | H0 | 否 |
| 非流式 buffer 超限 | 同 500 | H0 | 否 |
| connect/upstream total timeout | 504 / `timeout_error` / `Request timed out.` | H0 | 否 |
| SSE idle 未 commit | 同 504 | H0 | 否 |
| SSE idle 已 commit | 无新 HTTP 错误，关闭连接 | 已 commit Header | 否 |
| Anthropic 最终响应 | 原 status、原 Body | 安全过滤后的原 Header | 已按 retry 决策完成 |

字段诊断只返回稳定排序第一项；内部完整诊断、Snapshot、Credential、Proxy、Bundle、队列和资源状态仅进入管理遥测。

## 17. 管理登录、Session、MFA、Step-up 与 CSRF

### 17.1 Session

- 同源 UI 使用 `Secure; HttpOnly; SameSite=Strict` Cookie。
- Session idle 默认 30 分钟，absolute 默认 12 小时。
- 登录、密码、MFA、step-up 和 secret/material 输入响应均 `Cache-Control: no-store`。
- 默认 CORS 关闭；未来分离域部署必须配置精确 Origin allowlist 与 credentials。

### 17.2 CSRF

所有非 GET/HEAD 管理请求要求双提交或 Session 绑定的 `X-CSRF-Token`。Token 与管理 Session、Origin、revision 绑定，登录后轮换。JSON Content-Type 不是 CSRF 的唯一防线。

### 17.3 MFA 与 step-up

- 首次管理员/邀请用户完成改密和 TOTP 后进入 active。
- `POST /admin/v1/auth/step-up` 必须提交 `purpose`；响应返回 `step_up_grant_id`、purpose 和默认 5 分钟的 `expires_at`。`GET /auth/me` 只列当前有效 purpose/grant 摘要，不返回一个通用 `step_up=true`。
- purpose 至少覆盖 secret reveal、不可逆 lifecycle、审批决定、Content Audit 读取、KeyProvider/备份策略、Bundle activation 和 Device rebuild；不同 purpose 不互认，一次性 purpose 在业务事务中消费。
- MFA code、password 和 enrollment secret 永远不会进入日志或幂等记录。

## 18. 管理角色与可见范围

外部角色：

| 角色 | 说明 |
|---|---|
| `platform_admin` | 全平台控制面；高风险操作仍受双人审批 |
| `key_owner` | 数据库 `user` 的外部名称；只管理自己 User 下的 Platform Key 生命周期和数据 |

Key Owner 可：管理自己 Session/MFA/密码；查看自己 Key；修改自己 Key 名称/有效期；禁用、恢复、吊销自己 Key；step-up 后 reveal；查看/导出自己的 Request/Usage。

Key Owner看不到 Credential ID、account UUID、Profile、Device、Proxy、Egress、Bundle、内部 Attempt/ConnectionAttempt、完整内部原因或其他用户数据。Platform Admin 也看不到 token、Cookie、Web Storage、Device seed、Session HMAC、Proxy password 等 secret 正文。

## 19. 管理成功与错误包络

### 19.1 单资源

```json
{
  "data": {
    "id": "grp_...",
    "revision": 7
  },
  "meta": {
    "request_id": "req_..."
  }
}
```

### 19.2 列表

```json
{
  "data": [],
  "page": {
    "size": 20,
    "has_more": false,
    "next_cursor": null
  },
  "meta": {
    "request_id": "req_..."
  }
}
```

### 19.3 错误

```json
{
  "error": {
    "code": "revision_conflict",
    "message": "The resource has changed.",
    "field": null,
    "details": []
  },
  "request_id": "req_..."
}
```

### 19.4 管理状态码

| HTTP | 用途 |
|---:|---|
| 200 | 查询、即时 action、幂等 replay |
| 201 | 创建资源 |
| 202 | 异步 Job 已创建 |
| 204 | 登出等无 Body 操作 |
| 400 | JSON、参数、过滤、排序语法 |
| 401 | 管理 Session 无效 |
| 403 | 权限、step-up、审批主体不合格 |
| 404 | 当前角色范围内资源不存在 |
| 409 | revision、唯一性、幂等或当前状态冲突 |
| 422 | 管理 Command 语义、非法状态转换 |
| 428 | 缺少要求的 `If-Match` |
| 429 | 管理面独立限流 |
| 503 | 审计链或关键管理依赖暂不可用 |

数据面字段/Capability 错误固定使用 400；422 只属于管理 Command。

## 20. Revision、ETag 与 Idempotency

### 20.1 ETag

可变资源：

```http
ETag: "rev-7"
```

PATCH 与既有资源的状态转换 action 必须携带：

```http
If-Match: "rev-7"
```

缺失返回 428 `precondition_required`；过期返回 409 `revision_conflict`。Body 同时返回 revision。Credential 内部 token 更新另校验 token_version；Profile/Device/Egress command 另校验 epoch；Artifact 内容 ETag 使用 content hash，Active Pointer 使用 pointer revision。

### 20.2 Idempotency-Key

以下 POST 必填：资源创建、状态 action、审批、导出、维护操作、探针、备份、演练、升级和异步 Job。

例外：登录、TOTP、step-up、纯 validate/simulate、Content Audit 临时 search、数据面 Messages。

语义：

- scope 为 `(actor, method, normalized_path, idempotency_key)`；
- 默认保存 24 小时；
- 同 key/同 payload 返回原 status/resource/job，并加 `Idempotency-Replayed: true`；
- 同 key/不同 payload 返回 409 `idempotency_key_reused`；
- 记录只保存 request digest 与资源引用，不保存 plaintext secret；
- Key 创建响应只返回掩码，完整 secret 统一经 reveal，避免幂等 replay 复制秘密。

## 21. 分页、过滤、搜索与排序

### 21.1 游标分页

管理集合统一使用：

```http
GET /admin/v1/RESOURCE?page[size]=20&page[after]=OPAQUE_CURSOR
```

- `page[size]` 默认 20，最大 100；
- `page[after]` 为签名的不透明游标，不接受客户端自行构造的 offset；
- 游标至少绑定 API 版本、资源类型、排序字段与方向、上一项排序值、过滤条件摘要、actor scope 和签发时间；
- 游标与当前过滤、排序或权限范围不匹配时返回 400 `invalid_cursor`；
- 排序末尾自动追加 `id` 作为稳定 tie-breaker；
- `has_more` 与 `next_cursor` 必须返回，默认不计算精确 `total_count`。

### 21.2 过滤、搜索、排序和投影

```http
GET /admin/v1/requests?filter[status]=completed&filter[created_at][gte]=...&sort=-created_at,id&q=REQ&page[size]=50
```

规则：

- 每类资源拥有字段 allowlist；未知字段返回 400；
- 时间范围使用半开区间 `[gte, lt)`；
- `q` 最大 128 个 Unicode code point，结果仍受角色范围约束；
- 一次最多三个显式排序字段；
- `filter[id][in]` 等集合过滤最多 100 项；
- `fields[RESOURCE]=a,b,c` 仅能减少普通字段，服务端强制保留 `id`、`revision` 等协议字段；
- secrets、原始 token、代理口令和临时认证材料不属于任何投影集合。

## 22. User、Session 与自助身份 API

### 22.1 路径

| Method | Path | 角色 | 说明 |
|---|---|---|---|
| POST | `/admin/v1/auth/login` | 匿名 | 用户名和密码登录 |
| POST | `/admin/v1/auth/password/change` | 本人 | 修改密码并撤销其他 Session |
| POST | `/admin/v1/auth/mfa/enrollments` | 本人 | 创建 TOTP enrollment |
| POST | `/admin/v1/auth/mfa/enrollments/{id}:confirm` | 本人 | 确认 TOTP |
| POST | `/admin/v1/auth/mfa/verify` | 本人 | 完成登录二次验证 |
| POST | `/admin/v1/auth/step-up` | 本人 | 获取短时高风险授权 |
| GET | `/admin/v1/auth/me` | 本人 | 当前 User、Session、step-up 状态 |
| DELETE | `/admin/v1/auth/session` | 本人 | 注销当前 Session |
| GET | `/admin/v1/auth/sessions` | 本人 | 查看本人 Session |
| DELETE | `/admin/v1/auth/sessions/{id}` | 本人 | 撤销本人某个 Session |
| GET、POST | `/admin/v1/users` | Admin | 查询或创建 User |
| GET、PATCH | `/admin/v1/users/{id}` | Admin | 查看或修改显示名、邮箱 |
| POST | `/admin/v1/users/{id}:disable` | Admin | 禁用 User，并同步禁用其 Key |
| POST | `/admin/v1/users/{id}:reactivate` | Admin | 恢复 User；Key 保持原状态 |
| POST | `/admin/v1/users/{id}:unlock` | Admin | 解锁登录 |
| POST | `/admin/v1/users/{id}:archive` | Admin | 全部 Key 已 revoked 后归档 |
| GET | `/admin/v1/users/{id}/sessions` | Admin | Session 摘要 |
| POST | `/admin/v1/users/{id}/sessions:revoke-all` | Admin | 撤销全部 Session |

### 22.2 字段合同

`POST /users`：

```json
{
  "username": "alice",
  "display_name": "Alice",
  "email": "alice@example.com",
  "role": "key_owner",
  "temporary_password": "SECRET"
}
```

User 响应字段固定为：`id`、`username`、`display_name`、`email`、`role`、`status`、`revision`、`created_at`、`updated_at`。首版 `username` 与 `role` 创建后只读；管理员不经 API 重置用户密码或 MFA。初始管理员在进程首次运行时依据环境变量一次性初始化。

## 23. Platform Key API

### 23.1 路径

| Method | Path | 说明 |
|---|---|---|
| GET、POST | `/admin/v1/platform-keys` | 查询或创建 Key |
| GET、PATCH | `/admin/v1/platform-keys/{id}` | 详情或可变配置 |
| POST | `/admin/v1/platform-keys/{id}:reveal` | step-up 后再次查看完整 secret |
| POST | `/admin/v1/platform-keys/{id}:disable` | 临时禁用 |
| POST | `/admin/v1/platform-keys/{id}:reactivate` | 恢复 |
| POST | `/admin/v1/platform-keys/{id}:revoke` | 永久吊销 |
| GET | `/admin/v1/platform-keys/{id}/config-versions` | 配置历史 |
| GET | `/admin/v1/platform-keys/{id}/audit-events` | Key 范围审计 |
| GET | `/admin/v1/platform-keys/{id}/client-config` | 生成不含 secret 的客户端配置模板 |

### 23.2 创建与返回字段

```json
{
  "name": "team-a-cli",
  "owner_user_id": "usr_...",
  "group_id": "grp_...",
  "expires_at": null,
  "endpoint_permissions": ["messages", "models"],
  "model_scope": {"mode": "group", "model_ids": []},
  "body_limit_bytes": 67108864,
  "messages_rate": {"rpm": 60, "burst": 10},
  "models_rate": {"rpm": 60, "burst": 10},
  "concurrency": {"limit": 5, "retry_after_ms": 2000},
  "ip_allowlist": [],
  "requested_content_audit": "metadata_only",
  "ruleset_id": null
}
```

响应包含 `id`、`name`、`display_prefix`、owner、Group、状态、上述配置、`effective_content_audit`、`active_config_version`、`revision` 与时间戳。`owner_user_id`、`group_id` 与 secret 不属于 PATCH 字段；Key 不支持转移用户或轮换 secret。创建后的完整 secret 通过 reveal 查看，响应携带 `Cache-Control: no-store`，默认 UI 60 秒后隐藏。

Key Owner 只可查询和操作本人 Key；PATCH allowlist 仅包含名称与过期时间，并可执行本人 Key 的 disable/reactivate/revoke/reveal。并发、RPM、模型、IP、RuleSet、Content Audit 等限制由管理员配置。Key 的客户端类型限制由 Group 决定，不在 Key 上配置。首版 Key Owner 不创建 Key。

## 24. Credential Group API

### 24.1 路径与配置发布

| Method | Path | 说明 |
|---|---|---|
| GET、POST | `/admin/v1/groups` | 查询或创建 Group |
| GET、PATCH | `/admin/v1/groups/{id}` | 聚合信息；PATCH 只改名称等元数据 |
| GET、POST | `/admin/v1/groups/{id}/config-versions` | 查询或创建不可变候选配置 |
| GET | `/admin/v1/groups/{id}/config-versions/{version}` | 读取完整配置、hash、来源 |
| POST | `/admin/v1/groups/{id}/config-versions/{version}:validate` | 静态验证 |
| POST | `/admin/v1/groups/{id}/config-versions/{version}:simulate` | 样本请求与历史窗口模拟 |
| POST | `/admin/v1/groups/{id}/config-versions/{version}:publish-shadow` | 发布 Shadow |
| POST | `/admin/v1/groups/{id}/config-versions/{version}:promote-canary` | 推进 Canary |
| POST | `/admin/v1/groups/{id}/config-versions/{version}:activate` | 激活 |
| POST | `/admin/v1/groups/{id}:rollback-config` | 回滚 Active Pointer |
| POST | `/admin/v1/groups/{id}:disable` | 禁用并结束尚未获得 Lease 的请求 |
| POST | `/admin/v1/groups/{id}:reactivate` | 恢复服务 |
| POST | `/admin/v1/groups/{id}:archive` | 归档 |
| GET | `/admin/v1/groups/{id}/credentials` | 组内 Credential 列表 |
| GET | `/admin/v1/groups/{id}/capacity` | 管理面实时容量，不形成公开 Availability |

首版 owner Executor 由单实例内部稳定分区决定，不开放 owner 转移接口；多实例共享与 owner 自动故障转移留在演进范围。

### 24.2 Group Config

```json
{
  "accepted_client_classes": ["claude_code_cli", "non_claude_code_cli"],
  "model_scope": {"mode": "all_published", "model_ids": []},
  "authentication_pool": {
    "mode": "subscription_primary",
    "console_fallback_enabled": false
  },
  "fully_managed_required": false,
  "egress_mode": "auto",
  "limits": {
    "concurrency": null,
    "messages_rpm": null,
    "messages_burst": null
  },
  "credential_defaults": {"concurrency": 5, "messages_rpm": 60},
  "queue": {
    "capacity_mode": "effective_concurrency_multiplier",
    "capacity_value": 2,
    "pre_upstream_timeout_ms": 30000,
    "full_retry_after_ms": 2000,
    "wait_timeout_retry_after_ms": 5000
  },
  "session": {
    "capacity_enabled": false,
    "max_active_sessions": null,
    "idle_ttl_ms": 1800000,
    "slot_wait_ms": 5000,
    "affinity_ttl_ms": 86400000
  },
  "retry": {
    "max_messages_attempts": 3,
    "max_connection_attempts": 3,
    "preferred_wait_ms": 2000,
    "min_retry_budget_ms": 5000,
    "cancel_grace_ms": 2000
  },
  "timeouts": {
    "upstream_connect_ms": 5000,
    "upstream_non_stream_total_ms": 300000,
    "upstream_stream_idle_ms": 30000,
    "client_write_idle_ms": 120000,
    "client_write_total_non_stream_ms": 300000
  },
  "stream_pending_bytes_max": 1048576,
  "content_audit": {
    "policy": "allow",
    "retention_days": 7,
    "direction_limit_bytes": 67108864
  },
  "token_estimate": {
    "mode": "local_estimate",
    "console_count_key_ref": null,
    "internal_rpm": 60,
    "local_fallback": false
  },
  "snapshot_refs": {
    "ruleset_id": null,
    "enforcement_id": "art_...",
    "capability_id": "art_...",
    "background_catalog_id": "art_...",
    "price_id": "art_..."
  }
}
```

`limits.* = null` 表示 Group 层默认不限制。订阅 Credential 是主要认证池；Console API Key 仅在明确配置后用于 Count Tokens 内部估算或业务 fallback，二者配置分别独立。

## 25. Credential、Profile、Egress 与 Proxy API

### 25.1 Credential Enrollment 与生命周期

| Method | Path | 说明 |
|---|---|---|
| GET | `/admin/v1/credentials` | 查询 Credential |
| GET | `/admin/v1/credentials/{id}` | Admin 详情 |
| POST | `/admin/v1/credential-enrollments` | 发起添加流程 |
| GET | `/admin/v1/credential-enrollments/{id}` | 当前状态与 next action |
| POST | `/admin/v1/credential-enrollments/{id}:submit-material` | 提交 Setup Token 等临时 secret |
| POST | `/admin/v1/credential-enrollments/{id}:complete-callback` | 完成 OAuth 回调 |
| POST | `/admin/v1/credential-enrollments/{id}:cancel` | 取消 enrollment |
| PATCH | `/admin/v1/credentials/{id}/scheduling-config` | priority、weight、容量和能力收窄 |
| POST | `/admin/v1/credentials/{id}:disable` | 禁用 |
| POST | `/admin/v1/credentials/{id}:reactivate` | 恢复 |
| POST | `/admin/v1/credentials/{id}:revoke` | 吊销 |
| POST | `/admin/v1/credentials/{id}:archive` | 归档 |
| POST | `/admin/v1/credentials/{id}:refresh-token` | 手工触发 Token refresh Job |
| POST | `/admin/v1/credentials/{id}:refresh-plan` | 手工刷新展示用 PLAN |
| POST | `/admin/v1/credentials/{id}:clear-cooldown` | 明确清除 cooldown |
| POST | `/admin/v1/credentials/{id}:begin-recovery` | 从 `manual_recovery_required` 开始恢复 |
| POST | `/admin/v1/credentials/{id}:migrate-group` | 排空后迁移至目标 Group |
| POST | `/admin/v1/credentials/{id}:rebind-egress` | 重绑出口并原子增加 profile epoch 与 egress epoch |
| POST | `/admin/v1/credentials/{id}:migrate-profile-cohort` | 迁移 Archetype 版本 |
| POST | `/admin/v1/credentials/{id}:rebuild-device-identity` | 双人审批后重建设备身份 |
| GET | `/admin/v1/credentials/{id}/maintenance-operations` | refresh、reauth、PLAN 历史 |
| GET | `/admin/v1/credentials/{id}/reauth-strategy` | 策略类型、健康、Browser material version 与 next action |
| POST | `/admin/v1/credentials/{id}/reauth-strategy:initialize` | 建立或重建 Managed Browser Strategy，202 |
| POST | `/admin/v1/credentials/{id}/reauth-strategy:disable` | 停用自动维护并重算 management class |
| POST | `/admin/v1/credentials/{id}/reauth-strategy:reactivate` | 完整验证后恢复自动维护 |
| GET | `/admin/v1/credentials/{id}/browser-operations` | 只读状态、过期时间、Egress 摘要；无 Cookie/页面正文 |
| POST | `/admin/v1/credentials/{id}/browser-operations/{operation_id}:cancel` | 取消尚未终态的交互/静默授权 |

`auth_method` 固定为 `oauth_pkce|setup_token|existing_oauth_material|console_api_key`。Enrollment 先通过冻结 Egress 验证账号并取得稳定 `account_uuid`，再在 Credential 激活前跨全部 Group 和生命周期查重。Create 命中时返回 409 `credential_account_exists` 和脱敏既有引用；Recover 只有绑定原 `manual_recovery_required` Credential 且账号相同时才更新原对象。

Credential 响应包含：账号掩码、Group、用途、认证种类、canonical status、lifecycle/auth/capacity/transport 正交状态、`blockers[]`、management class、token 到期与版本、cooldown、调度配置、展示用 subscription plan、Profile 摘要、Egress 摘要、5h/7d/model quota 与估算成本。任何 secret 均不进入响应。

### 25.2 Profile 与 Egress

| Method | Path | 说明 |
|---|---|---|
| GET | `/admin/v1/credential-profiles` | Profile 集合、Archetype/Bundle/epoch/健康筛选 |
| GET | `/admin/v1/credential-profiles/{id}` | Profile、profile epoch、Archetype、Device Identity 摘要、证据状态 |
| GET | `/admin/v1/egress-bindings` | Egress Binding 集合、mode/Proxy/健康/漂移筛选 |
| GET | `/admin/v1/egress-bindings/{id}` | mode、Proxy、egress epoch、出口摘要、健康与漂移 |

Device ID、Profile seed、Session HMAC 与 token 原文始终脱敏；管理员看到 hash/prefix、版本、状态与最近验证时间。Profile 与 Egress 的改变只经上表明确 Command 进行，并写不可变审计事件。

### 25.3 Proxy

| Method | Path | 说明 |
|---|---|---|
| GET、POST | `/admin/v1/proxies` | 查询或创建 CONNECT/SOCKS5 Proxy |
| GET、PATCH | `/admin/v1/proxies/{id}` | 普通元数据和容量配置 |
| POST | `/admin/v1/proxies/{id}:replace-secret` | step-up 后替换认证 secret |
| POST | `/admin/v1/proxies/{id}:probe` | 异步验证连通性、TLS pass-through 与出口 |
| POST | `/admin/v1/proxies/{id}:disable` | 禁用 |
| POST | `/admin/v1/proxies/{id}:reactivate` | 恢复 |
| POST | `/admin/v1/proxies/{id}:archive` | 归档 |
| GET | `/admin/v1/proxies/{id}/bindings` | 当前绑定 Credential |

默认一个 Proxy 最多绑定 5 个活动 Credential。首版不增加代理总并发限制。Group `egress_mode=auto` 时，从允许且健康的 Proxy 中选择活动绑定数最少者，并以 Proxy ID 做稳定 tie-break；无可用容量时创建 `direct` Egress Binding。已绑定 Credential 的请求不使用临时公共代理回退；浏览器静默授权沿用该 Credential Binding，Direct Binding 则直连。

## 26. Model、Capability、Rule、Archetype 与 Bundle API

### 26.1 模型与能力

| Method | Path | 说明 |
|---|---|---|
| GET | `/admin/v1/models` | 模型目录与发布状态 |
| GET | `/admin/v1/models/{id}` | 详情、能力版本和定价引用 |
| POST | `/admin/v1/models:refresh` | 自动发现 Job |
| POST | `/admin/v1/models/{id}:approve` | 审核新模型后发布 |
| POST | `/admin/v1/models/{id}:deprecate` | 标记弃用，不再接受新请求 |
| POST | `/admin/v1/models/{id}:disable` | 停用 |
| GET、POST | `/admin/v1/capability-versions` | 查询或创建 typed candidate |
| POST | `/admin/v1/capability-versions/{id}:validate` | 样本与路径展开验证 |
| POST | `/admin/v1/capability-versions/{id}:activate` | 激活版本 |

Capability 采用数据驱动的字段路径、类型、条件、互斥和 transform 描述。新模型出现 `thinking.type` 等差异时创建新版本，无需在请求管线写模型分支。已消失的模型自动进入 disabled 并通知管理员；deprecated/disabled 模型均不接受新调用。

### 26.2 RuleSet、Enforcement、Catalog 与 Price

| Method | Path | 说明 |
|---|---|---|
| GET、POST | `/admin/v1/rulesets` | 规则候选 |
| POST | `/admin/v1/rulesets/{id}:validate` | 静态验证 |
| POST | `/admin/v1/rulesets/{id}:simulate` | 输入样本模拟 |
| POST | `/admin/v1/rulesets/{id}:activate` | 激活 |
| GET、POST | `/admin/v1/enforcement-versions` | 安全强制版本 |
| POST | `/admin/v1/enforcement-versions/{id}:validate` | typed 编译与不可放宽校验 |
| POST | `/admin/v1/enforcement-versions/{id}:publish-shadow` | 发布 Shadow 候选并冻结证据窗口 |
| POST | `/admin/v1/enforcement-versions/{id}:activate` | 双人审批后激活并原子生成 Group Config snapshot |
| POST | `/admin/v1/enforcement-versions/{id}:rollback` | 双人审批后回滚历史不可变版本 |
| GET、POST | `/admin/v1/background-catalog-versions` | 测活与背景流量特征版本 |
| POST | `/admin/v1/background-catalog-versions/{id}:validate` | 编译强结构模板并由平台运行确定性样本 |
| POST | `/admin/v1/background-catalog-versions/{id}:publish-shadow` | 开始不少于 7 天的 Shadow 窗口 |
| POST | `/admin/v1/background-catalog-versions/{id}:activate` | 按证据门槛及双人审批激活 |
| POST | `/admin/v1/background-catalog-versions/{id}:rollback` | 回滚历史不可变 Catalog |
| GET、POST | `/admin/v1/price-versions` | 模型价格版本 |
| GET、POST | `/admin/v1/plan-mapping-versions` | PLAN Mapping typed candidate |
| GET | `/admin/v1/plan-mapping-versions/{id}` | 版本、来源、mapping、diff 与影响摘要 |
| POST | `/admin/v1/plan-mapping-versions/{id}:validate` | 对已保存 raw corpus 验证 |
| POST | `/admin/v1/plan-mapping-versions/{id}:activate` | 激活并创建重算 Job，返回标准 `202 JobEnvelope` |
| POST | `/admin/v1/plan-mapping-versions/{id}:rollback` | 切回历史版本并创建重算 Job，返回标准 `202 JobEnvelope` |
| POST | `/admin/v1/plan-mapping-versions/{id}:recompute` | 显式重算已保存 raw，202 |
| GET | `/admin/v1/artifacts/{id}` | 统一只读 Artifact 元数据、hash 和 provenance |

写入只能走各 typed API，通用 `/artifacts` 不接受任意 JSON 写入，以免绕开专属校验和审批。

Background Catalog 的确定性模板由 `client_classes + match_all` 组成；`match_all` 只接受 bounded Header 精确/包含匹配与 JSON Pointer 的标量相等/存在匹配。平台执行样本后记录命中数，管理员不能直接提交计数。`throttle|reject` 激活必须完成 7 天 Shadow；确定性样本不足 100 时消费 `background_catalog_risk_acceptance` 双人审批，否则消费 `background_catalog_activate` 双人审批。启发式 suspected 流量永远只观察。

Enforcement 激活和回滚消费 `enforcement_activate` 双人审批。激活动作在同一事务切换 Artifact pointer、创建引用该 Artifact 的新 Group Config、切换 Group Config pointer并写 Audit/Outbox；运行时按 Artifact hash 冻结 Enforcement snapshot，在途请求继续使用旧 snapshot。

### 26.3 Archetype 与 Transport Bundle

| Method | Path | 说明 |
|---|---|---|
| GET、POST | `/admin/v1/environment-archetypes` | 类别模板 |
| GET | `/admin/v1/environment-archetypes/{id}` | 字段和证据摘要 |
| POST | `/admin/v1/environment-archetypes/{id}:verify` | 运行自动证据门禁 |
| POST | `/admin/v1/environment-archetypes/{id}:promote-canary` | 进入 Canary |
| POST | `/admin/v1/environment-archetypes/{id}:activate` | 激活供新 Credential 分配 |
| POST | `/admin/v1/environment-archetypes/{id}:retire` | 退休 |
| GET、POST | `/admin/v1/transport-bundles` | Bundle 元数据与上传 |
| POST | `/admin/v1/transport-bundles/{id}:verify` | 签名、hash、ABI、证据验证 |
| POST | `/admin/v1/transport-bundles/{id}:promote-canary` | 绑定至少 20 次 fresh、零硬失配的机器证据后进入 Canary |
| POST | `/admin/v1/transport-bundles/{id}:activate` | 双人审批后激活 |
| POST | `/admin/v1/transport-bundles/{id}:rollback` | 切回已验证版本 |

Bundle 创建/上传 DTO 必须携带唯一 `source_archetype_version_id`、capture cohort、`protocol=h1|h2`、schema/ABI、engine range、evidence hash、RFC 8785 JCS canonical hash 和 `transport_bundle_v1` 域的 Ed25519 detached signature。一个 Bundle 版本只对应一个 ArchetypeVersion/cohort/protocol；Release 签名 key domain 与 Bundle key domain 分离。Verify 响应分别报告 artifact lifecycle、evidence gate 和 runtime loadability，`ReadyForCanary` 只表示 `lifecycle=verified + evidence_gate=passed`，不是额外生命周期状态。

生产部署是单台 Linux 主机上的 Rust Edge/Executor、一个进程内 `TransportCore` 与多个不可变 `CompiledTransportEngine` 逻辑实例；它们不是多进程服务。三 OS runner 只在研发/CI 采集真实 Claude Code 和运行时证据，生成签名 Bundle 后进入发布链。首版允许 Windows 证据先作为已验证基线，macOS/Linux 状态公开标记为待外部证据，相关 Archetype 不越过其证据门禁。

## 27. Request、Usage、聚合与 Export API

### 27.1 查询

| Method | Path | 说明 |
|---|---|---|
| GET | `/admin/v1/requests` | 请求与使用记录统一列表 |
| GET | `/admin/v1/requests/{id}` | 阶段、attempt、usage、成本与错误 |
| GET | `/admin/v1/requests/{id}/attempts` | ConnectionAttempt 与 Messages Attempt |
| GET | `/admin/v1/usage/summary` | 时间、User、Key、Group、Credential、模型聚合 |
| GET | `/admin/v1/usage/timeseries` | 使用量与估算成本时序 |
| POST | `/admin/v1/exports` | 创建导出 |
| GET | `/admin/v1/exports/{id}` | Job 状态 |
| GET | `/admin/v1/exports/{id}/download` | 短期一次性下载 |

请求记录和使用记录共用 Request 详情，避免两套事实表。列表默认字段包括 Request ID、User、Key、Group、客户端类别、模型、stream、状态、时间、attempt 数、输入/输出 token、cache token、估算金额与 currency。Admin 还可见脱敏 Credential、Archetype、profile/egress epoch、Transport Engine、跨 Credential 切换、内部错误分类；Key Owner 只见本人请求，且隐藏 Credential 内部信息。

usage 使用两个正交字段：`source=official|local_estimate|console_count|cancel_estimate`，`completeness=complete|partial|unknown`。订阅组支持本地估算，或由内部 Console API Key 调用 Count Tokens；该调用不属于外部路由，也不消耗 Platform Key 的 Messages/Models 配额。

### 27.2 导出

- 首版数据集固定为 `usage_requests_v1`，格式为 `jsonl|csv`，时间采用半开区间且单次范围不超过 31 天；
- Key Owner 的有效 scope 由服务端强制收敛为本人；Platform Admin 可选择 `own|all`，但导出状态和下载始终只对任务发起人可见；
- 所有导出统一返回 202 Durable Job；最多 10,000 行、32 MiB，超限明确失败且不静默截断；
- 产物默认保留 24 小时，使用每产物随机 DEK 与 AES-256-GCM 加密保存；成功下载一次后立即销毁数据库中的 wrapped DEK/nonce/object URI，后续下载统一返回 404；
- 导出字段固定为 Request/时间、Owner/Key/Group/模型、endpoint/outcome/status、usage source/completeness、nullable token 与金额/currency；Credential、Attempt、upstream request ID、Profile、Proxy、secret 和请求/响应正文始终排除；
- `partial|unknown` 中缺失的 token 保持 `null`，不得补零；CSV 对公式前缀和引号/换行执行安全编码；
- Content Audit Body 不通过普通 Request 导出，需走第 28 章的独立审批检索。

## 28. Approval、Content Audit、Alert、Notification 与运维 API

### 28.1 高风险审批

| Method | Path | 说明 |
|---|---|---|
| GET、POST | `/admin/v1/approval-cases` | 查询或发起审批 |
| GET | `/admin/v1/approval-cases/{id}` | 详情 |
| POST | `/admin/v1/approval-cases/{id}:approve` | 第二名 Admin 批准 |
| POST | `/admin/v1/approval-cases/{id}:reject` | 拒绝 |
| POST | `/admin/v1/approval-cases/{id}:cancel` | 发起人撤销 |

审批绑定 action type、target、payload digest、发起人、过期时间与理由。发起人与批准人必须不同；执行时重新校验 resource revision、payload digest、step-up 和审批有效期。高风险操作包括 Device Identity 重建、Bundle 生产激活、审计链破损后的恢复确认、主密钥轮换等。

### 28.2 Content Audit

| Method | Path | 说明 |
|---|---|---|
| POST | `/admin/v1/content-audit/search-sessions` | step-up + 理由，创建短时检索 Session |
| GET | `/admin/v1/content-audit/search-sessions/{id}/records` | 在授权范围内查询 |
| GET | `/admin/v1/content-audit/records/{id}` | 解密单条记录，强审计 |
| POST | `/admin/v1/content-audit/records/{id}:export` | 双重确认后的独立导出 |
| POST | `/admin/v1/content-audit/purge-jobs` | 到期或管理员明确清理 Job |
| GET、POST | `/admin/v1/content-audit/legal-holds` | 查询或创建 Legal Hold；创建需双人审批 |
| GET | `/admin/v1/content-audit/legal-holds/{id}` | 范围、复核、到期与 active object count |
| POST | `/admin/v1/content-audit/legal-holds/{id}:review` | 定期复核并记录理由 |
| POST | `/admin/v1/content-audit/legal-holds/{id}:release` | 双人审批后解除 |

Key 请求模式固定为 `metadata_only|full_encrypted`，Group 策略固定为 `allow|require|forbid`：`allow` 按有效 Key grant 计算，`require` 强制全文，`forbid` 强制仅元数据且不拒绝业务请求。生效为 `full_encrypted` 时，Original 与首次 Final 持久化成功是上游首字节前门闩；任一上游字节已写出后，后续 Final/Response 审计失败只记 critical `audit_gap`。Body 默认保留 7 天、每方向 64 MiB；访问理由、字段范围、Legal Hold 和下载动作全部写审计链。

### 28.3 告警、通知与运维

| Method | Path | 说明 |
|---|---|---|
| GET | `/admin/v1/alerts` | 告警列表 |
| POST | `/admin/v1/alerts/{id}:acknowledge` | 确认 |
| POST | `/admin/v1/alerts/{id}:resolve` | 解决 |
| GET、POST | `/admin/v1/alert-silences` | 查询或创建维护静默 |
| GET | `/admin/v1/alert-silences/{id}` | 静默范围、过期与创建者 |
| POST | `/admin/v1/alert-silences/{id}:end` | 提前结束静默 |
| GET、POST | `/admin/v1/notification-channels` | 邮件、Webhook、Server酱3 等渠道 |
| POST | `/admin/v1/notification-channels/{id}:test` | 测试发送 |
| GET | `/admin/v1/notifications` | 当前用户站内通知 inbox |
| POST | `/admin/v1/notifications/{id}:read` | 标记已读 |
| POST | `/admin/v1/notifications:read-all` | 当前用户全部已读 |
| GET | `/admin/v1/dashboard/summary` | 角色裁剪后的首页聚合 |
| GET | `/admin/v1/system/status` | release、Schema、readiness、capacity、SLO 与完整性摘要 |
| GET | `/admin/v1/audit-events` | 全局管理审计；Key Owner 自动限定本人范围 |
| GET | `/admin/v1/operations/jobs` | 异步 Job |
| GET | `/admin/v1/operations/jobs/{id}` | Job 进度与逐项结果 |
| POST | `/admin/v1/operations/jobs/{id}:cancel` | 取消尚可中止的 Job |
| POST | `/admin/v1/operations/backup-jobs` | 在线备份 |
| GET | `/admin/v1/operations/backup-runs` | 备份历史、manifest、WAL 与验证状态 |
| GET | `/admin/v1/operations/backup-runs/{id}` | 单次备份详情 |
| POST | `/admin/v1/operations/restore-validations` | 离线恢复包预检 |
| GET | `/admin/v1/operations/restore-validations` | 预检历史 |
| GET | `/admin/v1/operations/restore-validations/{id}` | 单次预检详情 |
| POST | `/admin/v1/operations/key-rotation-jobs` | 主密钥轮换 |
| POST | `/admin/v1/operations/key-lifecycle-jobs` | restore-gated 的主密钥退役或销毁 |
| POST | `/admin/v1/operations/upgrade-checks` | 升级前检查 |
| GET | `/admin/v1/operations/upgrade-checks` | 检查历史与当前兼容性 |
| POST | `/admin/v1/operations/drills` | 演练任务 |
| GET | `/admin/v1/operations/drills` | 演练历史 |
| GET | `/admin/v1/operations/drills/{id}` | 结果、RPO/RTO 与证据引用 |

生产恢复只遵循离线 runbook，不设计在线 restore action。通知发送失败不得回滚原业务状态；进入独立重试和告警链。

备份与恢复操作的冻结合同：

- 三个 POST 仅允许 `PlatformAdmin`，强制 `Idempotency-Key`，并消费 purpose=`backup_restore_security` 的一次性 step-up grant；
- 在线备份请求为 `{step_up_grant_id, reason}`，返回 `backup_create` Job；base backup、连续 WAL、对象快照及 manifest 的编排由环境 Backup Adapter 完成；
- 恢复预检与隔离演练请求为 `{backup_run_id, recovery_point?, step_up_grant_id, reason}`；只接受已有 `succeeded` 且具 32-byte manifest digest 的 Backup Run；
- Adapter 仅从 stdin 接收非秘密 manifest/reference；Backup key file 与 repository 通过进程环境引用传递，stdout 只允许 2 MiB 内的 typed JSON，stderr 不进入 Audit、Job 或 API；
- `manifest_validation` 不恢复到生产；`full_restore_drill` 必须在隔离环境完成 DB/Object/Deletion Ledger 重放、无出网/无通知 serving simulation，并在销毁隔离材料后才能成功；
- 成功演练强制 `RPO <= 300s`、`RTO <= 3600s`；不满足时以失败证据保留，不冒充可恢复；生产切换仍只使用离线 runbook；
- Backup Adapter 未配置或不可达不撤销数据面 ready；对应 Job 明确失败并产生运维告警。API 永不返回 repository credential、Backup key 或命令 stderr。

## 29. 批量、异步 Job、OpenAPI 与兼容门禁

### 29.1 批量边界

首版没有通用异构 batch endpoint。仅提供领域明确的批量操作：

- Key lifecycle 批量 disable/reactivate/revoke；
- Alert 批量 acknowledge；
- Credential 批量 refresh-token/refresh-plan；
- 导出、备份、密钥轮换和升级检查使用 Job。

每批最多 100 项。生命周期批量 Command 需携带每项 expected revision，采用全有或全无事务；维护类 Job 返回 202，逐项记录成功或失败。secret reveal、archive、egress rebind、Device Identity rebuild、recovery、审批、Content Audit 与 Bundle activation 只允许单项执行。

### 29.2 Job 合同

```json
{
  "data": {
    "id": "job_...",
    "type": "credential_refresh",
    "status": "queued",
    "progress": {"completed": 0, "total": 10},
    "created_at": "RFC3339",
    "expires_at": null
  },
  "meta": {"request_id": "req_..."}
}
```

状态为 `queued|running|succeeded|partially_succeeded|failed|cancelled`。Job 只保存 secret 引用，不把临时认证材料写入 payload/result；回调、重试和取消均以 generation 抵御迟到结果。

### 29.3 OpenAPI 与兼容门禁

- `planning/api-contract.md` 是语义权威，OpenAPI 3.1 文件在实现阶段由此生成并纳入版本控制；
- CI 执行 schema 校验、示例回放、Breaking Change 检测和 Anthropic 兼容 corpus；
- 同一 major 内只新增可选字段、枚举需采用 unknown-safe reader；删除或改变语义进入新 major；
- 管理客户端发送未知字段时返回 400，避免静默忽略配置错误；数据面 Messages 的未知扩展按 compatible 模式保留；
- 日志、trace、审计和错误快照执行结构化秘密扫描。

## 30. 权限矩阵、全局约束与 Reader Check

### 30.1 权限矩阵

| 资源/动作 | Platform Admin | Key Owner |
|---|---|---|
| 本人密码、MFA、Session | 是 | 是 |
| User 管理 | 是 | 否 |
| 创建任意 owner 的 Key | 是 | 否 |
| 本人 Key 查询、名称与过期时间修改 | 是 | 是 |
| 本人 Key reveal/revoke | 是 | 是，需 step-up |
| Group/Credential/Profile/Proxy | 是 | 否 |
| Artifact、模型和 Bundle | 是 | 否 |
| 本人请求、usage、导出 | 是 | 是 |
| 全局请求、usage、导出 | 是 | 否 |
| Content Audit Body | step-up + 理由 + 独立授权 | 否 |
| 高风险生产动作 | 双人审批 | 否 |

所有角色看到的 secret 范围都受专属 reveal/submit 合同约束；普通 GET、列表、导出、审计和错误响应均为脱敏结果。

### 30.2 全局合同约束

1. Platform Key 固定绑定一个 Group，且不支持 owner 或 Group 转移。
2. Group 只属于一个 owner Executor；Transport Engine 不拥有 Credential 状态。
3. 一个 Anthropic Credential 对应一个 Credential Profile；Device Identity 每 Credential 唯一。
4. Archetype 可以共享，Device ID、Session HMAC 与 Egress Binding 不共享。
5. 同 Credential 的声明环境、Transport Bundle 证据和请求拟态必须一致。
6. GenericAdjustedRequest 在跨 Credential retry 中保持稳定；FinalUpstreamRequest 按新 Profile、token 和 egress epoch 重建。
7. 数据面只调整请求；Anthropic 响应 Body/SSE 保持原始字节。
8. 单 Credential 限流 Header 只供内部消费；客户端只看 Key/Group 级平台限流。
9. PLAN 仅展示，不参与调度、限流、路由、权重或资格判断。
10. Count Tokens 只供平台内部估算，不形成北向 API。
11. 客户端类型在 Group 层分为 `claude_code_cli` 与 `non_claude_code_cli`，不由客户端自报字段单独决定。
12. 响应一经 commit，任何后续异常只结束当前交付，不创建新 attempt。

### 30.3 Reader Check

- Claude Code CLI 应调用哪个 URL、使用哪种认证 Header？见第 7、9 章。
- 为什么 `/v1/messages/count_tokens` 返回未知路由？见第 8、27 章。
- Key 并发满与 Group 队列满分别返回什么？见第 16 章。
- 模型列表是否随 Credential 瞬时可用性变化？见第 12 章。
- SSE commit 后出错时是否注入平台事件？见第 11、15 章。
- 上游 429 Header 如何处理？见第 14、16 章。
- Key Owner 能否查看 Credential 或 Content Audit Body？见第 18、30 章。
- Key secret 是否支持再次复制？见第 23 章。
- Key 能否换 owner 或换 Group？见第 23、30 章。
- 客户端类型由哪里配置？见第 24 章。
- Credential 新增时如何防止同账号重复？见第 25 章。
- OAuth refresh token 失效后如何进入恢复？见第 25 章；细节由 Credential Lifecycle 文档定义。
- Proxy 池为空时请求是否停摆？见第 25 章。
- 一个 Proxy 默认可绑定多少 Credential？见第 25 章。
- PLAN 是否影响调度权重？见第 30.2 节。
- 订阅 Credential 如何估算 token？见第 27 章。
- 管理写入如何防止覆盖并发修改？见第 20 章。
- 大导出如何交付？见第 27、29 章。
- 生产环境是否需要部署 Windows/macOS/Linux 三套服务？见第 26 章。
- 哪些操作需要双人审批？见第 28、30 章。

若实现、OpenAPI、管理 UI 或测试与本合同冲突，以本合同和其引用的上位决策为准；后续修改必须通过同一版本化评审流程同步更新。
