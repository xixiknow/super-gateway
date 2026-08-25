# R3/R4 本地闭环证据

> 日期：2026-08-25  
> 范围：R3 Background Catalog / Group Enforcement 与 R4 动态 Group owner 运行时装配  
> 证据级别：local implementation evidence；不是 RC/GA promotion evidence

## 1. R3 Background Catalog

- `gateway-api` 提供不可变 `BackgroundCatalog` 编译对象；entry 固定为 `id + action + client_classes + match_all`。
- `match_all` 只接受有界 Header equals/contains 与 JSON Pointer scalar-equals/present；空信号、重复 ID、重复匹配定义、非法 Header/Pointer 和复合 JSON 比较值均在编译时拒绝。
- 重复 Header 不形成确定命中；多模板按信号数量和稳定 ID 确定性排序。
- Active Catalog 在管理运行时装载时编译，并随每个 `AccessGrant` 与 `RequestSnapshotSet.background_catalog` 冻结。
- 只有 Active Catalog 的确定性命中形成 `ExplicitProbe` 并执行该 entry 的 `observe|throttle|reject`；启发式 `SuspectedProbe` 始终绕过 action gate。

管理发布链：

```text
draft
→ validate（平台运行样本并记录 deterministic_sample_count）
→ publish-shadow（写 shadow_started_at 与 +7d 最短窗口）
→ activate / rollback（移动 immutable active pointer）
```

`throttle|reject` 的 7 天 Shadow 是硬门槛。样本达到 100 时消费 `background_catalog_activate` 双人审批；不足 100 时消费 `background_catalog_risk_acceptance` 双人审批。审批的 `action_snapshot_digest` 必须等于目标 Artifact 的 32-byte content hash。

## 2. R3 Group Enforcement

- `gateway.group_config.enforcement_artifact_id` 显式绑定同 Group 的 Active Enforcement Artifact。
- 新 Group 在创建事务内生成默认 preserve Artifact、rollout evidence、Artifact pointer 与 Group Config pointer。
- 旧 Active Group Config 由 forward migration 生成真实 Enforcement Artifact；已有合法 Active pointer 优先保留。
- validate 使用 typed `group_id + system` payload；`replace` 强制稳定 `platform_system_ref` 及 string/block-array content。
- activate/rollback 在同一事务完成：目标 Artifact 激活、旧 Artifact 退役、新 Group Config 创建、两个 pointer 切换、Group revision、Audit/Outbox。
- 运行时从 Artifact payload 编译 `SystemPolicy`，snapshot identity 使用 Artifact version 与 content hash；Artifact 缺失、scope/lifecycle/schema/payload 不匹配时 fail closed。
- `versioned_artifact` 与 `group_config` 均有数据库内容不可变 trigger；发布只改变 lifecycle/pointer。
- Policy 流水线在 RuleSet 后再次执行 Enforcement，测试证明 Key/Group RuleSet 不能恢复 `strip_all` 已删除的 System。

## 3. R4 动态 Group owner

- `ProductionDispatcher` 使用原子可替换 Group registry，并以单飞锁串行动态安装。
- 新 Active Group 被发现后执行 durable owner CAS、生成唯一 `owner_generation`、创建 Scheduler actor 后原子发布。
- create Group 提交后走同步 fast-path；30 秒 reconciliation 是漏事件自愈路径。
- disable/archive 停止 actor、释放精确 owner generation、注销 supervisor；reactivate 重新申请更高 generation。
- owner claim/heartbeat/release 不递增业务 `credential_group.revision`，管理 ETag 不受 lease churn 影响。

## 4. 本地执行结果

已通过：

```text
python -B tools/validate_contracts.py
  47 JSON files / 2981 consistency checks

cargo test -p gateway-api --locked
  23 passed

cargo test -p gateway-policy ruleset_cannot_weaken_group_system_enforcement --locked
  1 passed

cargo test -p super-gatewayd policy_artifact_payloads_are_typed --locked
  1 passed

cargo test -p gateway-services stopped_group_can_be_unregistered_and_reactivated_with_a_new_generation --locked
  passed

cargo clippy -p gateway-api -p super-gatewayd -p gateway-storage --all-targets --locked -- -D warnings
  passed
```

本文最初记录时 PostgreSQL-gated 测试在缺少 DSN 时显式 skip。后续 [R10 本地验证证据](r10-local-verification.md) 已使用隔离空库实际执行以下路径：

- `TEST_DATABASE_ADMIN_URL`：migration/bootstrap/role/owner generation 与 policy release schema；
- `TEST_R4_RUNTIME_DATABASE_ADMIN_URL`：Active Group install→disable→reactivate，无进程重启。

## 5. 仍需 promotion evidence

- PostgreSQL 18.3 空库 migration 与 R4 Active Group 运行时路径已通过；R3 并发 activate/rollback、deferred trigger 竞争仍需专项证据；
- 用可控数据库时钟覆盖 7 天 Shadow 前后边界、99/100 样本和风险接受分支；
- 两进程同时发现新 Group 时只有一个 owner winner，winner crash 后按既定 owner lease 规则收敛；
- 管理 API 的 MFA、step-up、双人审批、If-Match、Idempotency、Audit/Outbox 组合流量；
- Linux native 构建、长时间负载与 GA trace ledger。
