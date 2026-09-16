# 统一回归与提交记录 · 2026-09-16

本次以 `9123ae9` 为父基线，将 System 四模式、多 OS 配置、价格同步、正文记录、count_tokens、Key 属性与管理台改造一起收口，源码、契约、迁移、依赖锁文件和前端产物随同提交。

## 最终验证

| 检查 | 结果 |
|---|---|
| `cargo fmt --all -- --check` | 通过 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 通过，零警告 |
| `cargo test --workspace --locked` | 261 通过，0 失败，0 ignored；包含 gateway-transport |
| 实际 PostgreSQL 测试 | 11 项，使用独立 PostgreSQL 18.3 实例与每组独立空库，全部通过 |
| `npm ci` + `npm test` | 15 个测试文件，56/56 通过 |
| `npm run build` | TypeScript 与 Vite 生产构建通过 |
| 契约生成与校验 | 178 管理路由，47 个 JSON 文件，2922 项一致性检查通过 |
| 工作区边界 | 9 个 package，434 项检查通过 |
| 发布证据与迁移兼容负例测试 | 通过 |
| systemd / 升级策略工件 | 通过 |
| 父基线 release manifest → 当前 manifest | 通过：历史迁移未改写，追加 6 条，版本 20260901000100 → 20260907000100 |
| 重生成契约与重建前端产物 | 与暂存提交逐文件一致，无漂移 |

最终测试日志：`C:/codex-targets/sg-regression-20260916/`，主要为 `clippy-clean.log`、`workspace-final.log`、`frontend-test.log`、`frontend-build.log`。

## 本轮收尾修复

- 恢复已提交迁移 `20260901000100` 的原始内容，避免 SQLx checksum 不一致阻止已有库升级；工作区原改写版本留存在上述日志目录供溯源。
- 审计退役测试从父基线数据库版本开始，带历史审批、导出及任务执行后续迁移；加入到期历史审计导出和正常用量导出的混合清理回归。
- `expire_usage_exports` 只处理 `usage_requests_v1`，避免历史审计行的新 CHECK 约束导致整批回滚。
- 新增正文表与系统设置表授予 `gateway_backup` SELECT，并通过真实数据库断言核对。
- R2 测试支持独立 `TEST_R2_DATABASE_ADMIN_URL`，仍兼容原 `TEST_DATABASE_ADMIN_URL`，解决全工作区测试时 R2/R5 共享空库导致的初始化冲突。
- 收口严格 lint：文档与格式、等价控制流简化、测试夹具局部 lint 说明；修复测试中跨 await 持有同步锁。生产逻辑未统一关闭 lint。

## 范围与后续

本轮验证的是 Windows 本机 PostgreSQL 18.3；Linux / PostgreSQL 16 / 容器与远程 CI 仍待推送后执行。Vite 提示主 chunk 超过 500 kB，不影响构建通过。

下一步为三 OS 真机采集与线路验收；部署侧清理和历史规划文档统一仍按任务文档执行。本次只创建本地提交。
