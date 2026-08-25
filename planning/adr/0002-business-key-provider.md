# ADR-0002：Business KeyProvider 首版选择

- 状态：已接受
- 日期：2026-08-24
- 影响阶段：R2、R9

## 背景

功能规划、技术架构和数据库设计均确认：首版普通业务密文允许使用数据库 Provider；运维变量表却把外部 Provider URI 或本地 key file 写成必选二选一。两者会导致空库启动、备份风险描述和实际部署合同不一致。

## 决策

`GATEWAY_BUSINESS_KEY_PROVIDER` 取值为 `database|file|uri`，默认 `database`：

- `database`：`security.business_key_material` 保存受限 key material、版本和生命周期；不得同时配置 URI 或文件。
- `file`：必须配置 `GATEWAY_APP_KEY_FILE`，数据库只保存版本引用和校验信息。
- `uri`：必须配置 `GATEWAY_KEY_PROVIDER_URI`，数据库只保存版本引用和校验信息。

Provider 选择与输入组合不一致时启动失败。URI、文件内容和数据库 key material 均不得进入 Debug、日志、指标、审计、Job 或导出。

Content Audit 继续使用独立用途域；Backup 与 Audit Integrity 根密钥继续位于业务数据库和备份仓库之外。

## 结果

数据库 Provider 符合首版已确认产品边界，但数据库备份同时覆盖业务密文和 Business key material，隔离强度低于外部 KMS。KeyProvider port 保持稳定，后续迁移到 file、Vault/KMS 时不改变 SecretEnvelope 格式和业务 Repository。

