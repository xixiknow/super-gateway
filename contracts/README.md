# 机器合同

本目录冻结 Claude Code 企业网关的机器可读合同。语义权威仍是 `planning/` 下的规划文档；生成器把已确认的接口、枚举、Trace、Bundle、运行时配置、发布证据和追踪关系转换为版本化 JSON 产物，校验器负责发现双向漂移。

## 目录

- `openapi/data-plane.openapi.json`：北向数据面 OpenAPI 3.1，仅包含 `POST /v1/messages`、`GET /v1/models`、`GET /healthz` 和 `GET /readyz`。
- `openapi/admin.openapi.json`：管理面 OpenAPI 3.1，路由从 `planning/api-contract.md` 的管理 API 表格自动抽取。
- `schemas/credential.schema.json`：Credential、五类正交状态、Enrollment 与自动重认证合同。
- `schemas/maintenance.schema.json`：维护操作 kind/trigger/conflict/state 与 CAS 快照合同。
- `schemas/session.schema.json`：Base Session、Agent、公平 affinity 与上游 Session 派生边界。
- `schemas/egress-profile.schema.json`：Profile、Device Identity、固定 Egress、Proxy 生命周期与健康合同。
- `schemas/usage-plan.schema.json`：Usage source/completeness、成本和只展示 PLAN 合同。
- `schemas/audit-approval.schema.json`：purpose-scoped step-up、双人审批、Content Audit 与 Legal Hold 基础合同。
- `schemas/trace-event.schema.json`：Request、ConnectionAttempt、MessagesAttempt、Usage、资源台账和交付事件。
- `schemas/transport-bundle-manifest.schema.json`：Bundle ABI、Archetype/cohort、TLS/H1/H2、完整 Pool Key、证据、JCS 哈希和签名合同。
- `schemas/runtime-config.schema.json`：R1 环境变量、secret reference、配对项、默认值和 readiness 影响合同。
- `schemas/release-evidence.schema.json`：二进制 hash、SBOM、provenance、evidence manifest 与测试 fixture 来源合同。
- `schemas/requirement-trace-ledger.schema.json`：Requirement → owner → phase → test → fixture 的账本 Schema。
- `traceability/requirements.json`：18 个功能模块、132 条已确认决策及 R1 阶段门禁的源行、哈希、owner、Phase 与测试入口。
- `registries/enums.json`：所有跨文档共享枚举的唯一生成注册表。
- `fixtures/`：Trace Event、Transport Bundle、runtime config、fixture provenance 与 release evidence 的有效基准样例。

## 固定边界

数据面只公开 Anthropic/Claude Code Gateway 外形；Count Tokens 保持平台内部能力，WebSocket、Files、Batches 和多 Provider 不进入首版公开合同。Messages 请求允许兼容未知扩展，经过显式规则校验与调整后提交 Anthropic；响应 JSON Body 与 SSE 字节保持透明。

管理面使用 Session Cookie、所有写请求的 CSRF、可变资源的 `If-Match` 和适用 Command 的 `Idempotency-Key`。Key Owner 的可见范围由 OpenAPI `x-roles` 和服务端授权共同实现；OpenAPI 不暴露 Credential secret、Browser secret、Proxy password、Device seed 或 Session HMAC。

## 生成与验证

在仓库根目录执行：

```powershell
python tools/generate_contracts.py
python tools/validate_contracts.py
```

生成器输出采用确定性排序与固定基线时间戳。修改规划基线后必须重新生成；校验器会检查 JSON 与本地 `$ref`、OpenAPI 路由和方法边界、54 组枚举、有效 fixture、18 模块、DEC-001 至 DEC-132 与 R1 门禁的连续性，以及每一条追踪项的源行哈希、owner、Phase 和测试引用。

`contracts/openapi/*.json`、`contracts/schemas/*.json`、`contracts/registries/*.json`、`contracts/fixtures/*.json` 和 `contracts/traceability/requirements.json` 都是生成产物；合同逻辑在 `tools/generate_contracts.py` 中维护。
