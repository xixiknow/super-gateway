# ADR-0003：首个 Schema-bearing Release 的升级基线

- 状态：已接受
- 日期：2026-08-24
- 影响阶段：R2、后续所有 Release Candidate

## 背景

R2 Exit 要求验证 N-1/N-2 升级，但当前仓库尚无任何已发布、携带数据库 Schema 的 release。把同一套空库 migration 复制成两个 predecessor fixture 会制造无效证据。

## 决策

首个 Schema-bearing release 的 R2 门禁由以下证据组成：

- PostgreSQL 16 空库执行全部 forward-only migration；
- migration checksum、运行时兼容范围和角色权限校验；
- 加密备份、隔离恢复及恢复后 Schema/行数/Audit/Outbox 校验；
- binary rollback 只回切二进制，不执行 down migration。

首个 release 发布后立即冻结其 schema seed、release manifest 和 migration checksum，作为下一版 N-1；第二个 release 发布后再形成 N-2。自第三个 Schema-bearing release 起，N-1/N-2 缺任一路径均阻止发布。

## 结果

这不是把两个相同空库样本标成历史版本。Requirement Trace Ledger 在真实 predecessor 出现前保持该项 `planned`，其余 R2 实现和后续阶段可继续推进。

