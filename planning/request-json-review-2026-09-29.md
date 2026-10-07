# Claude Code 2.1.245 请求对比

核查日期：2026-09-29。输入为 `.tmp/request-json/request-origin-0929-2.1.245.json` 和 `request-rebuild-0929-2.1.245.json`。

## 文件差异

递归比较结果：原始 JSON 与重组文件的 `body` 完全相等，无重复 JSON 键。模型、消息及其顺序、工具 schema、缓存标记、思考设置和 metadata 均保留。重组文件新增请求 ID、来源、目标模板、占位 Header 等预览元信息；`network_sent=false`。这份预览没有执行凭据及最终上行构建，实际发送应核对单独采集的最终上行正文及 Header。

## 官方协议核查

- `claude-opus-5` 支持中途 `role: system` 消息，无需 beta header。样本角色顺序为 `user → system`，system 位于末尾，符合排列要求；系统消息的字符串 content 也受当前官方 SDK 支持。保留其位置，不移动至顶层 system。
- Opus 5 接受 `thinking.type=disabled` 与顶层 `output_config.effort=high` 组合。
- 样本包含 26 个工具，名称互异、schema 为 object；没有 tool_use/tool_result 消息对，故不据此推断多轮工具配对行为。
- 三处 ephemeral 缓存标记在对比中完整保留。
- 公开 API 参考页仍残留“不存在 system role”的旧说明，但当前 schema、专门功能文档及 SDK 类型均包含 system，旧说明不作为拒绝依据。

来源：

1. [会话中途系统消息与排列限制](https://platform.claude.com/docs/en/build-with-claude/mid-conversation-system-messages)
2. [思考参数组合](https://platform.claude.com/docs/en/build-with-claude/thinking-troubleshooting)
3. [Claude Code 官方更新记录](https://code.claude.com/docs/en/changelog)：2.1.212 已记录中途 system block 对网关的兼容改进；2.1.280 修复相关排列错误。
4. [官方网关协议](https://code.claude.com/docs/en/llm-gateway-protocol)
5. [官方 TypeScript SDK](https://github.com/anthropics/anthropic-sdk-typescript/blob/main/src/resources/messages/messages.ts)：`MessageParam.role` 包含 user、assistant、system。

本次为结构比较和官方协议核查，没有将请求样本发送至上游；不据此断言实际账号、额度、模型可用性或缓存命中结果。
