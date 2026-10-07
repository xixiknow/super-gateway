# OpenAI provider 实施记录

更新日期：2026-09-20。

## 产品边界

支持官方 OpenAI API Key 和 ChatGPT/Codex OAuth 订阅账号。入口覆盖 Responses、Chat Completions、compact、模型目录和 Responses WebSocket。功能默认关闭；管理员导入账号、测试连接、配置分组与模型权限后启用。

每个分组固定一个 provider，旧数据和缺省接口参数归属 Anthropic。OpenAI 使用标准 TLS 和独立身份配置，复用平台鉴权、固定代理出口、调度、队列、Lease、审计及成本估算。Anthropic 继续沿用原有 Bundle。

## 已实现

- 数据迁移：provider 隔离、账号身份、OAuth 会话、模型目录、续接绑定和 OpenAI 遥测字段。保留旧凭据 ID、历史记录及密文读取路径。
- 账号管理：API Key 创建、Codex JSON 导入、浏览器 PKCE 授权、重新授权、手动刷新、后台刷新、测试连接、启停、健康恢复。公开接口隐藏凭据；修改采用修订号检查与事务审计。
- OAuth：按上游账号身份去重；刷新互斥和 token 版本检查；未返回新 refresh token 时保留旧值；access-only 账号标记手动更新。临时故障有界退避，永久失败或令牌轮换结果不确定时进入重新授权状态。
- 授权恢复：交换所得令牌加密保存；后续导入失败可从检查点重试。账号导入与授权完成状态同事务提交，防止进程退出留下半完成导入；并发重试仅一次成功。
- 设置：全局传输开关、超时和刷新周期；分组模型权限、限流、并发及推理强度上限；账号代理、并发、优先级、模型和 WebSocket 设置。默认保留客户端推理强度，配置上限后拒绝超限或按管理员选择降级。
- HTTP/SSE：API Key 使用官方原生接口；订阅账号走 Codex Responses，支持 Chat 请求及响应转换、非流式聚合和独立 compact JSON。原生协议保留响应内容，旁路提取用量。
- 会话：平台 Key、上游账号与客户端会话共同隔离身份；previous_response_id 持久绑定账号。账号失效返回错误，不删除续接上下文后换号重放。
- WebSocket：每条下游连接固定一个账号和一条上游连接；逐轮鉴权、限流、准入与记账，轮次串行。空闲时释放执行 Lease；限制连接数量与空闲时间；支持断线取消。后台额度更新不使有效连接失效，令牌、出口或传输配置变化要求重连。
- 故障与用量：统计实际写入字节；连接阶段允许有界重试，提交后停止重放。区分终止、失败和断流，缺失用量标记不完整；重复终止事件与同一官方用量观察幂等。缓存 token 从输入总量拆分，reasoning 保留为输出明细，避免重复计费。
- 模型与价格：provider 归属、SDK 标准模型列表、Codex 模型元数据及能力校验；目录同步失败保留已发布数据，额度查询失败保留最近快照并标记过期。
- 控制台与合同：OpenAI 账号、授权、配置和额度面板，中英文标签；管理和数据接口合同同步更新。

## 关键代码

- `crates/super-gatewayd/src/production_dispatcher/openai.rs`：请求调度、适配、续接、用量和记账。
- `crates/super-gatewayd/src/admin_backend/openai.rs`：账号、设置、连接验证、目录与额度。
- `crates/super-gatewayd/src/admin_backend/openai_oauth.rs`：PKCE、令牌交换、刷新和后台维护。
- `crates/gateway-transport/src/openai_http.rs`：标准 HTTP/SSE 与 WebSocket 传输。
- `crates/gateway-api/src/edge.rs`：端点、模型查询和 WebSocket 逐轮准入。
- `web/admin-console/src/OpenAiAccounts.tsx`：管理界面。

## 验证与产物

Rust workspace 全量测试、Clippy（全 workspace / all-targets，警告视为错误）、格式检查、前端 TypeScript 检查、全套前端测试及独立 Vite 构建均通过。合同校验通过 2,959 项，workspace 校验通过 483 项。OpenAI PostgreSQL 测试使用项目 target 内的独立 PostgreSQL 18 实例，覆盖迁移、provider 隔离、密文、账号管理、刷新 CAS、授权检查点恢复以及请求到用量落库；未配置各自数据库地址的其他 PostgreSQL 套件会跳过，此结果不代表这些套件已完成真实数据库验收。

测试完成后独立 PostgreSQL 实例已停止。最终回归日志位于 `target/openai-final-tests.log`。前端构建位于 `target/openai-admin-dist`，Rust 编译位于 `target`。Windows 中文路径下本地生成的 BoringSSL CMake 缓存使用 OPENSSL_NO_ASM=ON；生产 TLS 配置未改变，干净缓存构建仍需处理此路径环境问题。

真实 OpenAI 账号、Codex 多轮工具调用及 OpenAI SDK 上游验收尚未执行。本地测试验证实现与数据库生命周期，不替代真实服务兼容性验收。

## 启用步骤

1. 启动新版服务并完成数据库迁移，创建 OpenAI 分组，配置出口策略与模型权限。
2. 在 OpenAI 管理面板创建 API Key 账号、粘贴 Codex 凭据 JSON，或打开 OAuth 授权链接并粘贴浏览器最终回调 URL。当前采用手动粘贴回调，无本地 1455 端口监听器。
3. 测试连接，检查账号身份、模型目录和订阅额度，再启用账号。
4. 根据需要配置推理上限与 WebSocket，最后开启全局 OpenAI 开关。
5. 给绑定该分组的平台 Key 配置模型权限；SDK 使用平台 `/v1` 地址，Codex 使用 Responses 入口及其根路径别名。
6. 使用真实账号验收流式/非流式、工具与图片、compact、WebSocket 多轮与取消，核对请求记录、缓存及 reasoning 用量。

首期不支持第三方兼容地址、跨 provider 混组、Anthropic 与 OpenAI 协议互转、图像生成、音视频、共享 WebSocket 连接池及自动修改隐私设置。

