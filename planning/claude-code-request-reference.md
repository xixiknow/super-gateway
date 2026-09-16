# Claude Code `/v1/messages` 请求完整参考（基于 2.1.220 逆向）

> 来源：`open-project/ClaudeCodeCli`（真实 CLI 2.1.220 逆向源码 `cli.pretty.js` + `work/2.1.220` 提取产物）与 `open-project/sub2api`（第三方拟态代理实现）交叉核对。
> 用途：作为本平台拟态代理的"真实请求形态"基线。随 CLI 版本会变，落地时须按采集版本复核。
> 标注：`[CLI]` = 真实 CLI 源码证据；`[sub2api]` = 第三方代理实现证据。

> **版本说明（重要）**：本文全部证据基于 **2.1.220**。仓库现有 Windows 签名资产（`crates/super-gatewayd/assets/windows-claude-code-2.1.241-h1.signed.json`）是 **2.1.241** 抓包，其头值与本文 §1.2 不同：`X-Stainless-Package-Version` **0.112.1**（本文 0.94.0）、`X-Stainless-Runtime-Version` **v26.3.0**（本文 v22.x）、`anthropic-beta` 含 `thinking-token-count-2026-05-13` 与 `mid-conversation-system-2026-04-07`。该资产也有已知缺陷（UA entrypoint 为 `sdk-cli`、beta 缺 `oauth-2025-04-20`/`extended-cache-ttl-2025-04-11`），见任务 T4.1。凡本文与采集资产冲突处，**以同版本真实抓包为准**；T4.1 三 OS 重采集后据抓包更新 §1、§2、§9。

## 0. 请求落点

- `POST https://api.anthropic.com/v1/messages?beta=true`（`?beta=true` 恒带）。`[CLI]` cli.pretty.js L18949 `[sub2api]` gateway_service.go:34

---

## 1. HTTP 请求头全集

### 1.1 Claude Code 固定注入头

| Header | 典型值 | 条件/来源 |
|---|---|---|
| `User-Agent` | `claude-cli/2.1.220 (external, cli)` | 完整格式见下；`[CLI]` L116644 |
| `x-app` | `cli`（后台会话 `cli-bg`） | `[CLI]` L160492 |
| `anthropic-version` | `2023-06-01` | 固定 |
| `anthropic-dangerous-direct-browser-access` | `true` | `dangerouslyAllowBrowser` |
| `Accept` | `application/json` | 含流式 |
| `Content-Type` | `application/json` | |
| `X-Claude-Code-Session-Id` | 会话 UUID | `[CLI]` `Ht()` |
| `x-client-request-id` | 每请求随机 UUID | firstParty 时由 fetch 层加；`[CLI]` L161084 |

> 拟态说明：`X-Claude-Code-Session-Id` 由平台按 `(凭据×OS)` 派生并与 `metadata.user_id.session_id` 同值（§10.1）；`x-client-request-id` 由平台每请求新生成。上表描述的是真实 CLI 自身行为。

**User-Agent 完整格式** `[CLI]` L116644：
```
claude-cli/2.1.220 (external, <entrypoint>[, agent-sdk/<ver>][, client-app/<app>][, workload/<tag>])
```
- `<entrypoint>` = 环境变量 `CLAUDE_CODE_ENTRYPOINT`，缺省 `cli`。

### 1.2 X-Stainless 头（Anthropic SDK 注入，直接暴露 OS/运行时）

| Header | 值示例 | 来源 |
|---|---|---|
| `X-Stainless-Lang` | `js` | 固定 |
| `X-Stainless-Package-Version` | `0.94.0` | SDK 版本 `[CLI]` L15646 |
| `X-Stainless-OS` | `Windows` / `MacOS` / `Linux` | `process.platform` 映射 |
| `X-Stainless-Arch` | `x64` / `arm64` | `process.arch` 映射 |
| `X-Stainless-Runtime` | `node`（Bun 二进制伪装为 node） | |
| `X-Stainless-Runtime-Version` | 如 `v22.x.x` / `v24.3.0` | `process.version` |
| `X-Stainless-Retry-Count` | `0`、`1`… | 重试次数 |
| `X-Stainless-Timeout` | 秒，如 `600` | `timeout/1000`，默认 600000ms |
| `x-stainless-helper-method` | `stream` | 流式调用；`[sub2api]` mimic 补 |

> **拟态要点**：`X-Stainless-OS/Arch/Runtime-Version` 必须与所选 Archetype 的 OS 一致，且与 body 里 `# Environment` 的 OS 一致。

### 1.3 认证头

| 模式 | Header | 备注 |
|---|---|---|
| OAuth 订阅 | `Authorization: Bearer <access_token>` | + 强制 beta `oauth-2025-04-20` |
| Setup Token | `Authorization: Bearer <access_token>` | 同 OAuth 处理 |
| API Key | `x-api-key: <key>`（或账号配 `authorization: Bearer`） | 不做 CC body 拟态 |

### 1.4 可选/偶发头 `[CLI]`

`x-claude-remote-container-id`、`x-claude-remote-session-id`、`x-client-app`(`CLAUDE_AGENT_SDK_CLIENT_APP`)、`x-claude-code-agent-id`、`x-claude-code-parent-agent-id`、`x-anthropic-additional-protection: true`、`x-is-refusal-fallback: true`、`x-cc-fallback-latched-by`、`x-cc-atis`、自定义 `ANTHROPIC_CUSTOM_HEADERS`（按行 `Key: Value`）。

---

## 2. `anthropic-beta` 头

Body 里的 `betas: [...]` 由 SDK 转成逗号拼接的 `anthropic-beta` 头。`[CLI]` L18954

### 2.1 真实 CLI 完整 beta 注册表 `[CLI]` L116846–116877 / L161597–161627

| header 值 | 触发条件 |
|---|---|
| `claude-code-20250219` | 非 haiku 模型几乎恒有；agentic 强制 |
| `oauth-2025-04-20` | OAuth 登录 |
| `interleaved-thinking-2025-05-14` | thinking 可用且模型支持 |
| `context-1m-2025-08-07` | 1M 上下文模型 |
| `context-management-2025-06-27` | firstParty 且开启上下文管理 |
| `structured-outputs-2025-12-15` | 结构化输出 |
| `advanced-tool-use-2025-11-20` / `tool-search-tool-2025-10-19` | 工具搜索（按 provider） |
| `effort-2025-11-24` | `output_config.effort` |
| `task-budgets-2026-03-13` | task budget |
| `prompt-caching-scope-2026-01-05` | firstParty |
| `prompt-caching-evict-2026-05-12` | 缓存驱逐 |
| `extended-cache-ttl-2025-04-11` | 1h cache TTL |
| `fast-mode-2026-02-01` | fast mode |
| `redact-thinking-2026-02-12` / `thinking-token-count-2026-05-13` | thinking + firstParty |
| `afk-mode-2026-01-31` | auto/AFK |
| `mcp-servers-2025-12-04` | MCP |
| `files-api-2025-04-14` | Files API |
| `mid-conversation-system-2026-04-07` | 会话中 system |
| `per-turn-control-2026-07-01` | 每轮 effort |
| `server-side-fallback-2026-06-01` / `-category-2026-07-01` / `fallback-credit-2026-06-01` | 服务端 fallback |
| `auto-mode-classifier-2026-07-16` | auto mode |
| `environments-2025-11-01`、`ccr-byoc-2025-07-29`、`advisor-tool-2026-03-01`、`cache-diagnosis-2026-04-07`、`context-hint-2026-04-09` | 各能力 |

可经 `ANTHROPIC_BETAS=a,b,c` 追加。
**注意**：`fine-grained-tool-streaming-2025-05-14` 在 2.1.220 **已不作为 beta 头**，改为工具字段 `eager_input_streaming: true`。`[CLI]` L543993

### 2.2 sub2api 拟态用的固定 7 项（有序）`[sub2api]` constants.go:80

```
claude-code-20250219, oauth-2025-04-20, interleaved-thinking-2025-05-14,
prompt-caching-scope-2026-01-05, effort-2025-11-24,
context-management-2025-06-27, extended-cache-ttl-2025-04-11
```

---

## 3. Body 顶层字段全集 `[CLI]` L545687

| 字段 | 常见 | 类型/默认 | 说明 |
|---|---|---|---|
| `model` | 是 | string | 规范化 ID（短名→日期长名） |
| `max_tokens` | 是 | number | `[sub2api]` 缺省补 128000；CLI 按模型 + `CLAUDE_CODE_MAX_OUTPUT_TOKENS` |
| `messages` | 是 | array | normalize + cache_control |
| `system` | 是 | array of text block | 见 §4 |
| `tools` | 是（主 agent） | array | 见 §5 |
| `tool_choice` | 常 | `{type:"auto"}` | thinking 时强制 tool 降级为 auto |
| `betas` | beta 路径 | string[] | → header |
| `metadata` | 是 | `{user_id:"<json>"}` | 见 §6 |
| `thinking` | 常 | `{type:"adaptive"|"enabled"|"disabled",...}` | |
| `temperature` | 条件 | number，常 `1` | 仅非 thinking 且模型允许采样 |
| `stream` | 流式 | `true` | |
| `output_config` | 条件 | `{effort?,format?,task_budget?}` | |
| `context_management` | 条件 | `{edits:[{type:"clear_thinking_20251015",keep:"all"}]}` | thinking 时；须与 beta 对称 |
| `stop_sequences` | 罕 | string[] | |
| `top_p` | 罕 | number | 主路径不强制 |
| `speed` | fast mode | `"fast"` | + beta `fast-mode-…` |
| `cache_control` | 条件 | 顶层/块级 | 1h TTL / evict |

> **能力对称约束** `[sub2api]`：最终 beta 不含 `context-management-2025-06-27` 时必须**删除** body 里的 `context_management`（在任何签名/hash 前）。

---

## 4. `system` 数组逐 block

顺序：`billing block` → 静态段 → `__SYSTEM_PROMPT_DYNAMIC_BOUNDARY__`（发送前滤除）→ 动态段。

### 4.1 Block 0：billing/归属块（是 system 文本，不是 HTTP 头）

**真实 CLI 2.1.220** `[CLI]` L119222：
```
x-anthropic-billing-header: cc_version=2.1.220.<fp3>; cc_entrypoint=cli;[ cch=00000;][ cc_workload=<tag>;][ cc_is_subagent=true;][ cc_prev_req=<id>;]
```
- `cc_version` = `2.1.220.` + 3 字符内容指纹后缀。
- `cch` = **字面量 `00000`**（firstParty/vertex 时出现），**不计算**。整段可由 `CLAUDE_CODE_ATTRIBUTION_HEADER=falsy` 关闭。
- 无 `cache_control`。

**sub2api 实现** `[sub2api]` gateway_billing_block.go：`x-anthropic-billing-header: cc_version={ver}.{fp3}; cc_entrypoint=cli;`（**不发 cch**）。

**cc_version 后缀 `fp3` 算法** `[sub2api]`：
```
salt = "59cf53e54c78"
chars = 首条 user 消息首个 text 的第 4、7、20 个字符（不足补 '0'）
fp3  = SHA256(salt + chars + version) 的 hex 前 3 位
```
→ 只依赖首条 user 消息的 3 个字符，与 system/tools/环境块无关。

**"首条 user 消息"的精确定义**：`messages[0]`（role 必为 user）的 `content` 里**第一个 `type:"text"` 块**的 `text` 全文——真实 CLI 会把 `<system-reminder>…</system-reminder>` 前置到该文本里，**它算在内**，字符下标 4/7/20 从含 reminder 的全文数起（与 sub2api 一致）。字符按 Unicode 标量计，不是字节。

**样例值提醒**：§9 样例里的 `cc_version=2.1.220.a3f` 中 `a3f` 是**示意值**，不是按上式算出来的；写 golden 测试时须自算，不能抄。

### 4.2 Block 1：身份串 `[CLI]` L239787
```
You are Claude Code, Anthropic's official CLI for Claude.
```
SDK 变体：`You are a Claude agent, built on Anthropic's Claude Agent SDK.` 等。

### 4.3 静态段（标准交互，`[CLI]` work/2.1.220/prompts/SYSTEM-PROMPT-FULL.md）
顺序与标题：`intro`（无标题）→ `# System` → `# Doing tasks` → `# Executing actions with care` → `# Using your tools` → `# Tone and style`。随 CLI 版本固定，逐字文本见提取产物。

### 4.4 边界
`__SYSTEM_PROMPT_DYNAMIC_BOUNDARY__` —— 仅特定门控时插入，**发送前被滤掉，不进 API**。

### 4.5 动态段（提醒顺序 `[CLI]`）
`Communicating`/输出效率 → `pronouns` → 谨慎行动 → 任务连续性 → 家族身份 → JSON 参数 → 先调查 → `session_guidance` → `memory`（CLAUDE.md）→ **`env_info_simple`（# Environment）** → `language` → `output_style` → 后台会话 → `scratchpad` → `context_management` 文案 → 模式相关 → token 附件。

**`# Environment` 完整字段** `[CLI]`：
```
# Environment
You have been invoked in the following environment:
 - Primary working directory: <cwd>
 - Is a git repository: Yes|No
 - Platform: <win32|darwin|linux>
 - Shell: <PowerShell|bash|zsh|…>
 - OS Version: <…>
 - You are powered by the model named <Display>. The exact model ID is <id>.
 - Assistant knowledge cutoff is <date>.
 - The most recent Claude models are the Claude 5 family and Haiku 4.5. …
 - Claude Code is available as a CLI…
 - Fast mode …
```

### 4.6 cache_control
每个 system block 可带：`{type:"ephemeral", ttl?:"1h", scope?:"global"}`。`[CLI]` L544756

---

## 5. `tools` 数组 `[CLI]` L544004

进 body。单个 schema：
```js
{ name, description, input_schema /* JSON Schema */, strict?, eager_input_streaming?, defer_loading?, cache_control? }
```
内置工具：`Agent`/`Task`、`Glob`、`Grep`、`Read`、`Edit`、`Write`、`Bash`、`PowerShell`、`Skill`、`TodoWrite`/`TaskCreate`、`WebFetch`、`WebSearch`、`AskUserQuestion`、`ExitPlanMode`、`NotebookEdit` 等（按能力/平台启用）。完整描述见 `work/2.1.220/prompts/TOOL-DESCRIPTIONS.md`。

| Tool | 核心 input |
|---|---|
| Bash | `command`, `timeout?`, `description?` |
| Read | `file_path`, `offset?`, `limit?` |
| Edit | `file_path`, `old_string`, `new_string`, `replace_all?` |
| Write | `file_path`, `content` |
| Glob | `pattern`, `path?` |
| Grep | `pattern`, `path?`, `glob?`, … |
| Agent/Task | `prompt`, `subagent_type?` |

---

## 6. `metadata` `[CLI]` L544820

**新格式（UA ≥ 2.1.78）**：`user_id` 是 JSON 字符串：
```js
metadata: { user_id: JSON.stringify({
  device_id, account_uuid, session_id, parent_session_id?  // + 可选 CLAUDE_CODE_EXTRA_METADATA
}) }
```
**legacy（旧版）**：`user_{64hex}_account_{uuid}_session_{uuid}`。
`[sub2api]` session_id 拟态 = `SHA256(accountID::discriminator::firstUserText)` → UUID 形。

---

## 7. `messages` 与 `<system-reminder>`

- `<system-reminder>…</system-reminder>` 出现在 **user message 文本** 与 **tool_result content** 中，由 CLI 自动插入。`[CLI]` L26416
- 典型内容：记忆时效警告、文件已在上下文、技能列表、后台任务恢复、空文件警告、GitHub rate limit 等。
- 平台拟态：**保留不动**（是真实 CLI 行为的一部分）。

### 7.1 日期/时间注入（易漏，务必保真）`[CLI]`

当前日期主要通过 `<system-reminder>` 注入，**不在**顶层 system / `# Environment`（后者只有模型知识截止日）。格式统一为**本地日历日 `YYYY-MM-DD`**（`getFullYear/Month/Date`，非 UTC），会话内首次调用后缓存（`M8e = memoize(Rcs)`，cli.pretty.js L242187）。

| 位置 | 形态 | 载体 | 变化 |
|---|---|---|---|
| A 主路径 | `# currentDate` + `Today's date is YYYY-MM-DD.`（前置 meta user 的 `<system-reminder>`，与 claudeMd/userEmail 同属 userContext） | messages | 会话内不变 |
| B 跨午夜 | `<system-reminder>The date has changed. Today's date is now YYYY-MM-DD. DO NOT mention this to the user…</system-reminder>` | messages | 跨天注入一次 |
| C SIMPLE 模式 | 顶层 system 仅 `CWD: <cwd>` + `Date: YYYY-MM-DD`（罕见） | system | 会话内不变 |
| D WebSearch 工具描述 | `- The current month is <Month YYYY> — use this when searching…`（`toLocaleString en-US month/year`） | tools[] | 每次生成重算 |
| E MCP 日期解析 | `Current date and time: <ISO> (UTC)` / `Local timezone: ±HH:MM` / `Day of week: …`（独立 side query，非主会话） | 独立请求 | 实时 |

**拟态含义**：日期都落在 **messages（system-reminder）** 与 **tools（WebSearch 描述）**，平台按"保留客户端原样"即自动保真。**唯一坑**：若平台将来对 tools 描述做"标准化/采集模板替换"，WebSearch 的 `current month` 必须**动态填当前月**，不能用采集时的固定月份——与环境块 OS 版本、system-reminder 日期同理：**动态内容不能被采集模板冻结**。

---

## 8. cc_version 指纹 / cch —— 重点澄清

- **cch 不是对 body 的动态签名**。2.1.220 真实 CLI 发字面量 `cch=00000`（firstParty）；sub2api 索性不发 cch。之前流传的"xxHash64(body) 重算 cch"是**旧版本(约 2.1.37)或误传**，2.1.220 不适用。
- **坐实**：cli.pretty.js 全文件 `cch=` **仅 L119227 一处赋值**：`s = (firstParty && Kd()) || vertex ? " cch=00000;" : ""`，无任何计算/替换分支；`Bun.hash`、`NATIVE_CLIENT_ATTESTATION` 均与它无关。其它 provider 整段省略 billing 块（而非改成计算值）。
- **真正随内容变的指纹是 `cc_version` 的 3 字符后缀**，且**只取首条 user 消息的第 4/7/20 字符** + salt + 版本号做 SHA256 前 3 位。
- **对平台的意义**：改 system / 环境块 / tools **不影响**该指纹（只要不改首条 user 消息那几个字符）；因此"改 body 需重算整体签名"的硬约束**不存在**。平台只需：① 保持 billing 块结构正确、`cc_version` 语义版本与 UA 一致；② 若确要改首条 user 消息文本，则按上式重算后缀。

---

## 9. 一条完整请求样例（firstParty + OAuth + 流式，尽量不省略）

```http
POST https://api.anthropic.com/v1/messages?beta=true HTTP/1.1
Host: api.anthropic.com
Accept: application/json
Content-Type: application/json
anthropic-version: 2023-06-01
anthropic-dangerous-direct-browser-access: true
Authorization: Bearer <oauth_access_token>
anthropic-beta: claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05,effort-2025-11-24,context-management-2025-06-27,extended-cache-ttl-2025-04-11
User-Agent: claude-cli/2.1.220 (external, cli)
x-app: cli
X-Claude-Code-Session-Id: 1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed
x-client-request-id: 6f4a2c1e-7b0a-4c9e-9a1f-2d3e4f5a6b7c
X-Stainless-Lang: js
X-Stainless-Package-Version: 0.94.0
X-Stainless-OS: Windows
X-Stainless-Arch: x64
X-Stainless-Runtime: node
X-Stainless-Runtime-Version: v22.14.0
X-Stainless-Retry-Count: 0
X-Stainless-Timeout: 600
x-stainless-helper-method: stream
```

```json
{
  "model": "claude-opus-4-6",
  "max_tokens": 64000,
  "stream": true,
  "temperature": 1,
  "thinking": { "type": "adaptive" },
  "output_config": { "effort": "high" },
  "tool_choice": { "type": "auto" },
  "betas": [
    "claude-code-20250219",
    "oauth-2025-04-20",
    "interleaved-thinking-2025-05-14",
    "prompt-caching-scope-2026-01-05",
    "effort-2025-11-24",
    "context-management-2025-06-27",
    "extended-cache-ttl-2025-04-11"
  ],
  "context_management": {
    "edits": [ { "type": "clear_thinking_20251015", "keep": "all" } ]
  },
  "metadata": {
    "user_id": "{\"device_id\":\"c0ffee…\",\"account_uuid\":\"a1b2c3d4-…\",\"session_id\":\"1b9d6bcd-…\"}"
  },
  "system": [
    {
      "type": "text",
      "text": "x-anthropic-billing-header: cc_version=2.1.220.a3f; cc_entrypoint=cli; cch=00000;"
    },
    {
      "type": "text",
      "text": "You are Claude Code, Anthropic's official CLI for Claude.",
      "cache_control": { "type": "ephemeral" }
    },
    {
      "type": "text",
      "text": "<intro>\n\n# System\n - All text you output outside of tool use is displayed to the user. …\n\n# Doing tasks\n …\n\n# Executing actions with care\n …\n\n# Using your tools\n …\n\n# Tone and style\n …",
      "cache_control": { "type": "ephemeral", "ttl": "1h" }
    },
    {
      "type": "text",
      "text": "# Environment\nYou have been invoked in the following environment: \n - Primary working directory: C:\\\\Users\\\\you\\\\proj\n - Is a git repository: Yes\n - Platform: win32\n - Shell: PowerShell\n - OS Version: Windows 11 Pro 10.0.26100\n - You are powered by the model named Claude Opus 4.6. The exact model ID is claude-opus-4-6.\n - Assistant knowledge cutoff is …\n"
    }
  ],
  "tools": [
    {
      "name": "Read",
      "description": "Reads a file from the local filesystem…",
      "input_schema": {
        "type": "object",
        "properties": {
          "file_path": { "type": "string" },
          "offset": { "type": "number" },
          "limit": { "type": "number" }
        },
        "required": ["file_path"]
      },
      "eager_input_streaming": true
    },
    {
      "name": "Bash",
      "description": "Executes a shell command…",
      "input_schema": {
        "type": "object",
        "properties": {
          "command": { "type": "string" },
          "timeout": { "type": "number" },
          "description": { "type": "string" }
        },
        "required": ["command"]
      }
    }
  ],
  "messages": [
    {
      "role": "user",
      "content": [
        {
          "type": "text",
          "text": "<system-reminder>\nAs you answer the user's questions, you can use the following context…\n</system-reminder>\n\n帮我修一下登录接口的 bug"
        }
      ]
    }
  ]
}
```

---

## 10. 拟态实现对照要点（最短正确路径）

1. **头**：OAuth `Authorization: Bearer` + `oauth-2025-04-20`；强制一套与 Archetype 同 OS 的 `User-Agent`（entrypoint 必须是 `cli`）/`X-Stainless-*`；`x-app` 只放行客户端 `cli`/`cli-bg`，其余置 `cli`；`anthropic-dangerous-direct-browser-access: true`；`anthropic-version: 2023-06-01`；`stream=true` 时加 `x-stainless-helper-method: stream`；每请求新 `x-client-request-id`（UUID v4）；`X-Claude-Code-Session-Id` 用平台派生值并与 `metadata.user_id.session_id` 同值。不要把客户端杂散头透传上去。**OS 识别读 `X-Stainless-OS`**——UA 不含 OS。
2. **billing 块**：`system[0]` = `x-anthropic-billing-header: cc_version=<ver>.<fp3>; cc_entrypoint=cli;`（cch 用 `00000` 或不发，按采集版本常量表；无 cache_control）。`<ver>` 与 UA 一致；`<fp3>` 按 §4.1 算法（依赖首条 user 消息含 reminder 全文）；客户端已发且版本一致时**原样保留**。
3. **system**：billing → identity → 平台标准静态段（采集自同版本 CLI）→ `# Environment`（OS 行对齐 Archetype，cwd/git 保真）→ memory 等保客户端。分段定界不能靠 `__SYSTEM_PROMPT_DYNAMIC_BOUNDARY__`（不上线，§4.4），靠静态段末标题 / 动态段首项 / cache_control 断点。
4. **body 补齐与对称**：`temperature`(默认 1)、`max_tokens`、缺失 `tools: []`；beta↔body 对称按 [simplified-blueprint.md](simplified-blueprint.md) §6.5 对称表**双向**执行（context_management / cache_control.ttl 1h / output_config.effort·format·task_budget / speed / thinking↔interleaved）；body 顶层 `betas[]` 一律删除（真实 CLI 由 SDK 转头，不进 body，附录 C）。
5. **metadata.user_id**：JSON 字符串三字段（device_id/account_uuid/session_id），按 `(凭据×OS)` 设备身份派生并整体替换客户端值；legacy `user_…_account_…_session_…` 格式识别后升格为 JSON。
6. **不需要**对整个 body 做 cch 签名。
7. **`messages` 与 `<system-reminder>` 原样保留**；RuleSet 在引擎层禁止 `/messages` 路径。
8. 序列化：真实 CLI `system` 在 `messages` 前——平台重序列化必须保序（`serde_json` 开 `preserve_order`，否则字母序会把 `messages` 排前面）。

---

# 附录：完整枚举（2.1.220，三代理穷举）

> 对 §1–§9 的**穷举补全**，覆盖条件字段/分支/全类型。三个探索代理逐一走代码路径并自检；仍存在的盲区见**附录 H**（只有方法 B 真实抓包能最终钉死）。行号默认相对 `cli.pretty.js`（附录 E/F 部分相对 `cli.renamed.js`，已注明）。

## 附录 A. HTTP Header 完整枚举

### A.1 恒有（firstParty 主会话）
`Accept: application/json`(L20652)、`content-type: application/json`(L15813)、`User-Agent: claude-cli/2.1.220 (external, <entrypoint>[, agent-sdk/…][, client-app/…][, workload/…])`(L160494/L116637)、`x-app: cli|cli-bg`(L160493)、`X-Claude-Code-Session-Id`(L160495)、`anthropic-version: 2023-06-01`(L20660)、`anthropic-dangerous-direct-browser-access: true`(L160524)、`X-Stainless-Lang/Package-Version/OS/Arch/Runtime/Runtime-Version/Retry-Count/Timeout`(L15705–15710, L20654–20655)、认证头（A.3）。

### A.2 条件头

| Header | 出现条件 |
|---|---|
| `anthropic-beta` | betas 非空（完整表见 §2） |
| `x-claude-remote-container-id` / `-remote-session-id` | `CLAUDE_CODE_CONTAINER_ID` / `_REMOTE_SESSION_ID` |
| `x-client-app` | `CLAUDE_AGENT_SDK_CLIENT_APP` |
| `x-claude-code-agent-id` / `-parent-agent-id` | 子代理 |
| `x-anthropic-additional-protection` | `CLAUDE_CODE_ADDITIONAL_PROTECTION` |
| `ANTHROPIC_CUSTOM_HEADERS` | 任意 `Key: Value` 行 |
| `x-client-request-id` | firstParty 每请求 UUID |
| `x-is-refusal-fallback` / `x-cc-fallback-latched-by` | refusal fallback |
| `x-cc-atis` | GrowthBook `atis` |
| `traceparent` | `Eer()` / `CLAUDE_CODE_PROPAGATE_TRACEPARENT` |
| `x-stainless-helper-method: stream` / `x-stainless-helper` | stream 助手 / 工具 helper |
| `anthropic-usage-limit: extended` | 深度>0 + `tengu_lantern_spool` |
| `anthropic-dispatch-id` | `tengu_cedar_lattice` |
| `x-cc-fallback-from-model/-category/-trigger`、`x-cc-original-request-id` | fallback stamp |
| `X-Amzn-Bedrock-Service-Tier` / `anthropic-workspace-id` | Bedrock / GCP |

### A.3 认证分支（互斥）
firstParty OAuth→`Authorization: Bearer`(+oauth beta) · firstParty APIKey→`X-Api-Key` · `ANTHROPIC_AUTH_TOKEN`→Bearer · gateway→Bearer JWT · bedrock→SigV4/AWS bearer(常删 `X-Api-Key`) · mantle/vertex/foundry/WIF→各自云鉴权。

## 附录 C. Body 顶层字段完整枚举
- **恒有**：`model`、`messages`、`system`、`tools`、`tool_choice`、`metadata`、`max_tokens`、`stream`（在 create 处叠加）。
- **条件**：`thinking`（thinking 开）· `temperature`（无 thinking 且允许采样，默认 1）· `context_management`（thinking + beta 对称）· `output_config{effort/task_budget/format}` · `speed:"fast"` · 顶层 `cache_control{evict_on_complete}`（子代理）· `fallbacks`（server 端 refusal fallback）· `diagnostics`（cache-diagnosis）· `context_hint` · `anthropic_beta[]`（Bedrock body 通道）· `fallback_credit_token` · `stop_sequences`（仅 side_query）。
- **开放注入**：`CLAUDE_CODE_EXTRA_BODY` 可注入任意官方字段（`top_p`/`mcp_servers`/`service_tier`…）。
- **不进 body**：`betas`（转成 `anthropic-beta` 头）。

## 附录 D. system 段完整清单

### D.1 静态前导（return 数组，L543535–543550）
S0 SIMPLE 早退(`CWD:`+`Date:`) · S1a intro / S1b lean `# Harness` · S2 `# System` · S3 `# Doing tasks` · S4 `# Executing actions with care`(compact 短版) · S5 `# Using your tools` · S6 `# Tone and style` · S7 SDK checkpoint(仅 excludeDynamic) · S8 `__SYSTEM_PROMPT_DYNAMIC_BOUNDARY__`(发送前滤除) · S9 `<total_tokens>` footer。

### D.2 动态段 `cR`（L543496–543532，共 24 项）
anti_verbosity · pronouns · action_caution(仅 lean 有文) · task_continuity(本构建恒 null) · fable_identity · tool_param_json · investigate_first · session_guidance · memory · env_info_static/simple(互斥) · language · output_style · bg-session · scratchpad · context_management · brief · focus_mode · act_dont_rederive · delivering_work_max · overcorrection · subagent_steer_delegation · heron_brook(任意远程文本) · autonomy_append · endconv_deferred_hint。

### D.3 分支差异（system 增减）
SIMPLE(仅 CWD+Date) · lean `SE`(前导换 `# Harness`) · excludeDynamic/SDK(去 memory/scratchpad/env_simple，改 env_static + checkpoint) · investigate compact(care 短版) · 子代理 `rin`(不用完整前导；尾部 = leadSections + 委派 + Notes + `<env>` 块；Explore/Plan 剥 gitStatus) · bg(加 `# Background Session`)。`systemContext` 的 `gitStatus`/`perforceMode` 以 `key: value` 追加进 system 字符串（非 `#` 段、非 reminder）。

## 附录 E. messages content 块类型 + cache_control

### E.1 content type（指纹器 `Rxs`，`cli.renamed.js` L350217–350237，共 21 种）
`text` · `image` · `document` · `search_result` · `thinking` · `redacted_thinking` · `tool_use` · `tool_result` · `tool_reference` · `server_tool_use` · `web_search_tool_result` · `web_fetch_tool_result` · `advisor_tool_result` · `code_execution_tool_result` · `bash_code_execution_tool_result` · `text_editor_code_execution_tool_result` · `tool_search_tool_result` · `mcp_tool_use` · `mcp_tool_result` · `container_upload` · `compaction`。
常用构造字段：`text{text, cache_control?}` · `image`/`document{source:{type:"base64", media_type, data}}` · `thinking{thinking, signature?}` · `tool_use{id, name, input}` · `tool_result{tool_use_id, content, is_error?}`（其余多为 API 响应回放，本地构造字段见附录 H）。

### E.2 cache_control 打点
工厂 `YEe`：`{type:"ephemeral", ttl?, scope?}`；启用由 `Utp(model)`（`DISABLE_PROMPT_CACHING*` 可关）；TTL `tFe(querySource)`：`FORCE_PROMPT_CACHING_5M`→5m / `ENABLE_PROMPT_CACHING_1H`→1h / 非付费→5m / 白名单(`repl_main_thread*`,`sdk`,`auto_mode`,`memdir_relevance`)→1h。断点：system 若干块 CC + 消息 **≤2 个**断点（末尾可缓存消息；assistant 末块为 thinking/redacted 不打）；子代理顶层 body `evict_on_complete:true` + beta。**无硬编码 "max 4"**。

## 附录 F. 注入标签 / reminder 完整清单

### F.1 userContext（**仅 4 键**，包在前置 meta user 的 `<system-reminder>` 里，`G0` L253259）
`currentDate`（始终，`Today's date is YYYY-MM-DD.`）· `claudeMd` · `userEmail` · `attachedProject`。

### F.2 attachment → messages（`Qap`/`tPo`，44+ 类型，多经 `<system-reminder>`）
date_change · edited_text_file · compact_file_reference · audio_transcript · pdf_reference · selected_lines_in_ide/diff · opened_file_in_ide · plan_file_reference · nested_memory · read_truncation_notice · agent_mention · skill_listing · dynamic_skill · output_style · critical_system_reminder(任意) · plan_mode/exit · auto_mode/exit · token_usage · total_tokens_reminder(`<total_tokens>`) · budget_usd · output_token_usage · hook_*(blocking_error/additional_context/stopped/success) · ultrathink_effort · workflow_keyword_request · ultra_effort_enter/exit · workflow_size_guideline_change · directory(伪 ls) · file(伪 Read) · invoked_skills · todo_reminder · task_reminder · tool_search_usage_reminder · relevant_memories · queued_command · diagnostics/lsp · mcp_resource(`<mcp-resource>`) · task_status · deferred_tools_delta · agent_listing_delta · mcp_instructions_delta · mcp_dropped_tools_delta · memory_update · teammate_mailbox/team_context · async_hook_response。
**渲染为空**（类型存在但当前不注入）：already_read_file、command_permissions、edited_image_file、多种 hook_*、goal_status、structured_output、max_turns_reached，及 dormant 列表（todo/task_progress/thinking_reminder/compaction_reminder/…）。

### F.3 其它硬编码 `<system-reminder>`（不经 Qap）
已读文件短路（进 **tool_result**）· 空文件/offset 越界警告 · GitHub rate limit · 模型切换 · brief 开关 · side question · 非交互关团队 · 远程 plan 脚手架。

### F.4 非 system-reminder 的 `<...>` 标签
`<env>`(子代理环境) · `<total_tokens>` · `<task-notification>`(后台结果，user 角色 XML) · `<memory path>`(team memory index) · `<mcp-resource>` · `<cc-memory filenames>`(教模型引用) · `<bash-input>`/`<command-name|args|message>`/`<local-command-stdout|stderr>`(本地 UI 痕迹)。

## 附录 G. 请求变体（querySource）
主路径 `ifn`→`ztp`（body L545687）。多数非主线程变体复用 `yee`(side_query) / `bV`(小模型) / `runForkedAgent`，不是另一套 schema：
- **sideQuery `yee`**：`source:"side_query"`，精简 system，默认 `max_tokens 1024`。
- **`bV` 小模型结构化**：`tools:[]`，`thinking:disabled`，小模型，默认不缓存（title 等复用）。
- **count_tokens**：`POST /v1/messages/count_tokens?beta=true`，无 stream，工具剥离，失败 fallback 小 create。
- **compaction**：forked agent，`querySource:"compact"`，`maxTurns:1`，`skipCacheWrite`，强制 plain-text summary。
- **title / tool_use_summary / agent_classifier**：小模型 + 短 user + 结构化输出。
- **plan mode**：**非独立请求**——主 `/v1/messages` + meta user + ExitPlanMode 工具。
- **subagent**：同 `ztp`，`querySource:"agent:*"`，工具/system 更窄，attachments 子集。

`querySource` 字面量 30：agent:custom, agent_classifier, agent_namer, agent_summary, auto_dream, auto_mode(+critique/setup_propose), away_summary, bash_extract_prefix, compact, extract_memories, feedback, generate_session_title, hook_agent, hook_prompt, insights, mcp_datetime_parse, model_validation, permission_explainer, plugin_eval_judge, prompt_suggestion, rename_generate_name, repl_sampling, sdk, side_question, teleport_generate_title, tool_use_summary_generation, web_fetch_apply, web_search_tool；+ 动态前缀 `repl_main_thread*`、`agent:default|builtin`。

## 附录 H. 已知盲区（三代理自检合并 —— 需方法 B 抓包最终验证）
1. **Bedrock/Vertex/Foundry 的 SDK 内部头**（SigV4 签名头、`x-goog-*`）在依赖包里，未打开验证。
2. **Managed Agents / Files / Batches / CCR BYOC** 等其它 `/v1/messages` 旁路的 body 组装未逐行穷尽。
3. **`CLAUDE_CODE_EXTRA_BODY` / `ANTHROPIC_CUSTOM_HEADERS` / `ANTHROPIC_BETAS` / sdkBetas** 是开放集合，无法枚举取值。
4. **GrowthBook/feature flag 默认真值表**未展开（只追到调用点）。
5. **各 content 类型的完整本地构造字段**（尤其 `*_tool_result`/`search_result`/`container_upload`/`compaction`/`tool_reference`）未逐类型读完（多为 API 回放）。
6. **动态 `querySource`**（`repl_main_thread*`、`agent:default|builtin`）前缀未穷举；字面量 30 已扫全。
7. **User-Agent 双重来源**：未全局证明所有 `/v1/messages` 调用都经 `Fde` 覆盖（否则可能露 `Anthropic/JS 0.94.0`）。
8. **运行时任意内容**：`heron_brook`、`critical_system_reminder`、hook `systemMessage` 只有通道、无固定全文。

> 结论：请求侧的**结构与枚举**在 2.1.220 上已尽可能穷尽；剩余不确定项集中在"云 provider 内部头 / 开放注入集 / feature flag 默认值 / 响应回放块字段"，这些用**真实抓包（方法 B）逐字段对照**才能钉死。
