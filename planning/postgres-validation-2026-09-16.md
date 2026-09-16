# PostgreSQL 验证记录 · 2026-09-16

A1 本机数据库验证完成。此次使用 Windows 本机 PostgreSQL 18.3，在独立临时实例上实际执行测试；所有数据库环境变量显式设置，未走缺少变量时的跳过分支。

后续统一回归已进一步核对历史迁移 checksum，升级测试起点改为已提交版本 `20260901000100`，并补充混合导出清理与备份权限断言；最终 11 项 PG 测试全绿，详见 [统一回归记录](regression-2026-09-16.md)。下文日志与测试起点描述保留首轮记录。

## 环境与结果

- 独立实例：`127.0.0.1:55439`，仅监听回环地址，测试专用 trust 认证。
- 数据与日志：`C:/codex-targets/sg-pg-validation-20260916/`。完成后停止实例，保留数据和日志供复核。
- 每组测试使用独立数据库；现有 PostgreSQL 服务和业务数据库未修改。
- 完整执行 50 条迁移，最新版本 `20260907000100`，全部成功；R2 实际表集合与契约的 112 张表严格一致。
- 11 个真实数据库测试通过；连同网关同次执行的其他测试，共 51 项通过。

| 测试目标 | PG 测试数 | 数据库 | 日志 |
|---|---:|---|---|
| gateway-storage / postgres_r2 | 1 | sg_r2 | r2.log |
| gateway-storage / credential_r5_pg | 1 | sg_r5 | storage.log |
| gateway-storage / telemetry_r7_pg | 1 | sg_r7 | storage.log |
| gateway-services / credential_enrollment_pg | 3 | sg_enrollment_final | enrollment-final.log |
| gateway-services / security_rotation_pg | 1 | sg_rotation | services.log |
| super-gatewayd / R4、R8、R9 | 3（整个 binary 43/43） | sg_r4、sg_r8、sg_r9 | gatewayd.log |
| gateway-storage / retire_content_audit_pg | 1 | sg_t6 | upgrade.log |

全部 Cargo 测试使用 `--locked`。初次编译遇到一次 Windows 临时归档目录清理错误，重试后通过。

## 新增验证

`retire_content_audit_pg.rs` 在执行最后一条迁移前写入历史数据，再调用正式迁移入口，确认：

- 两类审计任务的 scheduled / leased / retry_wait 状态全部取消，租约清空并记录完成时间。
- 已完成审计任务和普通用量导出任务保持原状态。
- 历史审批及 raw 审计导出记录可读，包括超过新用量导出长度上限的历史记录。
- 7 张退役表与 Key / Group 审计列全部移除。
- 新审计审批、审计导出被 CHECK 约束拒绝；设备重建/密钥提供方审批与 jsonl/csv 用量导出仍可写入。
- `NOT VALID` 只容忍既有行；历史审计审批后续状态更新同样受到新 CHECK 限制。
- 重复调用迁移入口得到相同版本与迁移数量。

`credential_enrollment_pg.rs` 在 OAuth 接入/恢复后补充检查：

- 没有 Linux 原型时不补建。
- 同一凭据补齐 macOS 与 Linux，重复及并发调用只各创建一套配置。
- 三 OS profile、设备、出口、原型的 OS 和凭据归属一致。
- 原 Windows profile / device / egress 标识保持不变，最终设备和出口各 3 条。

升级测试已加入 `.github/workflows/ci.yml` 的 PostgreSQL 16 车道，使用独立 `gateway_ci_t6` 库与 `TEST_T6_DATABASE_ADMIN_URL`。

## 验证边界

- 本次实测 PostgreSQL 18.3；CI PostgreSQL 16 尚未在本轮运行。
- 带数据升级覆盖审计退役；多 OS 检查使用测试原型，不替代三 OS 真机采集与线路验收。
- 本轮未执行生产库迁移、部署、服务器目录清理或 Git 提交。

复跑时先启动上述实例，并为每个目标创建新的空数据库，再设置对应 `TEST_*_DATABASE_ADMIN_URL`。R2 和升级测试要求空库；补建测试也应使用新库，避免前次原型资产影响缺失原型断言。
