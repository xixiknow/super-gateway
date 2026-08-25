# Claude Code Gateway 运维 Runbook

> 状态：Detailed Operations Baseline  
> 部署形态：Linux Rust 单体 + PostgreSQL  
> 关联文档：[技术架构](./technical-architecture.md)、[安全设计](./security-design.md)、[Transport Engine](./transport-engine.md)、[管理控制台](./admin-console.md)

## 1. 目的与适用范围

本文冻结首版生产安装、启动、巡检、容量、Proxy/Bundle、Credential维护、备份恢复、升级回滚、告警和事故处置。命令均为只读诊断或明确的离线流程模板；实现阶段需将占位 CLI 固化为受测命令。

## 2. 生产拓扑与故障边界

```text
Client → Linux super-gatewayd
              ├─ Edge/Admin/UI
              ├─ GroupExecutor/Queue/Lease/Reservation
              ├─ TransportCore/Pool
              ├─ Credential Maintenance/按需Browser child
              └─ Job/Outbox/Audit/Metrics
                   ├─ PostgreSQL（唯一强制在线外部服务）
                   ├─ Direct或可选CONNECT/SOCKS5 Proxy → Anthropic
                   ├─ 可选Content Audit Store
                   ├─ Backup Repository
                   └─ KeyProviders

Windows/macOS/Linux Capture Runner
→ 只在研发/CI离线生成签名Bundle
```

首版无Redis、外部MQ、服务发现或常驻跨OS Worker。Queue、Lease、socket、pool、in-flight SSE和临时response buffer重启后不恢复。

## 3. 值班角色与事件等级

角色：Incident Commander、Operations、Security、Scribe、Communications。一个人可兼任，但重大安全/恢复动作仍满足双人控制。

- SEV-1：全局DB/ready失效、核心KeyProvider、Audit/Deletion完整性、全路径Anthropic/Bundle事故、大规模secret泄漏；
- SEV-2：单Group、Proxy、Credential cohort不可用，持续容量拒绝，备份/演练失效；
- SEV-3：单Credential恢复、PLAN/通知/统计Job、非关键UI问题。

事件记录包含Incident ID、影响范围、开始/检测/缓解/恢复时间、SLO/error budget、证据hash和沟通节奏。

## 4. Linux账号、目录与权限

```text
/opt/super-gateway/releases/<release>/
/opt/super-gateway/current -> releases/<release>
/etc/super-gateway/super-gateway.env
/etc/super-gateway/credentials/
/var/lib/super-gateway/bundles/
/var/lib/super-gateway/content-audit/
/var/lib/super-gateway/response-tmp/
/var/lib/super-gateway/backup-staging/
```

长期进程使用无登录shell的`super-gateway`账号。配置/secret文件`root:super-gateway 0640`，根密钥文件`0600`。response tmp、Content Audit和backup staging分目录、分挂载监控、分密钥生命周期。release目录只读。

## 5. 主机与数据库前置条件

参考环境：应用8 vCPU/16 GiB/SSD/1Gbps；PostgreSQL 4 vCPU/8 GiB/SSD。生产支持Linux x86_64与arm64，但进入System Canary前都需完成native BoringSSL、sanitizer、安全和负载门禁。

主机要求：稳定UTC/NTP、足够nofile、禁core dump、swap关闭或加密、独立spill容量、可达Anthropic与配置Proxy、备份仓库与KeyProvider网络隔离。

PostgreSQL要求WAL归档、校验和、autovacuum、连接上限、磁盘/WAL监控、只读诊断角色和独立migrator/runtime角色。

## 6. 环境变量与Secret

统一`GATEWAY_`前缀，secret优先`_FILE`或systemd credential：

| 变量 | 用途 | Ready影响 |
|---|---|---|
| `GATEWAY_DATA_BIND` | 数据面监听 | 必需 |
| `GATEWAY_ADMIN_BIND` | 管理面，默认回环/管理网 | 必需 |
| `GATEWAY_DATABASE_URL_FILE` | runtime DSN | 必需 |
| `GATEWAY_MIGRATOR_DATABASE_URL_FILE` | migration DSN | migration必需 |
| `GATEWAY_KEY_PROVIDER_URI`/`GATEWAY_APP_KEY_FILE` | Business Key | 必需 |
| `GATEWAY_CONTENT_AUDIT_KEY_FILE` | Content Audit Key | 启用全文范围必需 |
| `GATEWAY_BACKUP_KEY_FILE` | Backup根密钥 | 缺失时备份冻结+critical |
| `GATEWAY_AUDIT_INTEGRITY_KEY_FILE` | Audit seal | 冷启动必需 |
| `GATEWAY_BUNDLE_TRUST_STORE` | Bundle公钥 | 必需 |
| `GATEWAY_BUNDLE_DIR` | Bundle存储 | 引用时必需 |
| `GATEWAY_RESPONSE_TMP_DIR` | spill | 必需 |
| `GATEWAY_CONTENT_AUDIT_DIR` | 全文对象 | 相应范围必需 |
| `GATEWAY_BACKUP_REPOSITORY` | filesystem/S3-compatible | 生产必配；故障不撤ready |
| `GATEWAY_MANAGED_BROWSER_TOOL` | 全自动浏览器授权 helper 的绝对路径；缺省时策略 Initialize/Reactivate 保持关闭 | 启用 Managed Browser 时必需 |
| `GATEWAY_MANAGED_BROWSER_TIMEOUT` | 单次浏览器授权总时限，默认 `300s`、最小 `30s` | 生命周期 |
| `GATEWAY_DRAIN_DEADLINE` | 默认300s | 生命周期 |
| `GATEWAY_BOOTSTRAP_ADMIN_USERNAME/PASSWORD` | 空库初始化 | 空库必需 |

`RUST_BACKTRACE`生产默认0。两组旧/新bootstrap变量同时出现时拒绝启动，避免歧义。

### 6.1 Managed Browser helper 进程合同

运行时固定执行：

```text
GATEWAY_MANAGED_BROWSER_TOOL reauthenticate --json-stdin --json-stdout
```

helper 必须由 root 部署、业务运行账号只读且不可替换。输入只从 stdin 接收，包含 intent、Credential/Account 标识、版本化 OAuth endpoints/scopes、冻结 Egress，以及存在时的 Cookie/Web Storage/Profile state；代理为 Credential 当前固定 HTTP CONNECT/SOCKS5 路由，未绑定代理时明确传 `direct`。不得从命令行参数、环境变量、stderr 或日志复制 token、Cookie、代理口令。

stdout 只允许一个、最大 32 MiB 的 JSON 对象：

```json
{
  "schema_version": 1,
  "access_token": "SECRET",
  "refresh_token": "SECRET",
  "expires_in_seconds": 3600,
  "cookie_jar_base64": "BASE64",
  "web_storage_base64": "BASE64_OR_NULL",
  "profile_state_base64": "BASE64",
  "adapter_version": "managed-browser-helper-VERSION"
}
```

退出码 `0` 表示候选产生成功，`75` 表示暂态失败并进入 Durable Job 重试，其余非零表示浏览器会话已失效或确定性失败。网关不会直接信任 helper 返回的 Account 字段；它使用同一个冻结 Egress 调用 Anthropic Profile API 复验 access token 与账号 UUID，验证通过后才分别加密 OAuth 和浏览器材料并执行原子 CAS。helper 进程带总超时、stderr 丢弃、取消/失租时终止。

## 7. systemd 单元与加固

- `super-gateway-migrate.service`：oneshot，使用`gateway_migrator`；
- `super-gateway.service`：唯一长期应用，使用`gateway_runtime`；
- `Type=simple`、`Restart=on-failure`、`RestartSec=5s`、`StartLimitBurst=3/300s`；
- `KillSignal=SIGTERM`、`TimeoutStopSec=330s`、`UMask=0077`、`LimitNOFILE=262144`、`LimitCORE=0`；
- `ProtectSystem=strict`、`ProtectHome=true`、`NoNewPrivileges=true`；
- 只将明确目录加入`ReadWritePaths`；
- 本地DB依赖postgresql.service，远程DB依赖network-online；
- Watchdog只在实现sd_notify后启用。

SIGTERM统一进入应用drain，不另设绕过状态机的ExecStop脚本。

## 8. PostgreSQL角色与连接

角色：

- `gateway_migrator`：DDL和migration metadata；只在oneshot使用；
- `gateway_runtime`：CRUD、sequence、advisory/row locks，无DDL；
- `gateway_readonly`：运维只读视图，排除secret ciphertext或缩小字段；
- backup账号：按工具所需最小权限。

应用pool要有连接/等待上限与statement timeout；管理慢查询、统计Job和数据面写入分pool或priority。事务期间无外部HTTP/OAuth/Browser/Proxy等待。

## 9. Migration 与首次初始化

物理migration位于`crates/gateway-storage/migrations/`，文件名`YYYYMMDDHHMMSS_description.sql`，发布后保持原内容。Release Manifest固化checksum与支持Schema范围。

规则：expand→checkpoint backfill→switch→contract；大索引单独CONCURRENTLY；contract至少跨一个已验证release和备份窗口；二进制回滚不回退Schema。

oneshot完成migration后，主进程只做checksum/兼容检查。空库时使用bootstrap env创建唯一Admin，之后删除password注入。测试覆盖空库与前两个release升级、dump/restore、Active Pointer、审计链和高负载migration影响。

## 10. 启动、Health 与 Ready

启动顺序：

1. migration oneshot；
2. 加载配置和KeyProvider；
3. runtime连接DB并检查Schema；
4. 空库Admin初始化；
5. 校验Audit Chain、外部seal、Deletion Ledger；
6. 清理遗留加密response tmp；
7. 加载Active Artifact/Profile/Egress/签名Bundle；
8. 恢复cooldown和Durable Job；检查分区/备份/演练；
9. 创建GroupExecutor/Transport pools/workers；
10. listener进入serving。

`/healthz`只证明事件循环存活。`/readyz`始终要求DB/Schema、Active配置、Business KeyProvider、Transport、必要Bundle和lifecycle serving；冷启动/恢复另需Audit Integrity KeyProvider，full encrypted范围另需ContentAudit KeyProvider。Backup KeyProvider/仓库故障只阻止新备份并告警。单Group无Credential、全部cooldown、Proxy、PLAN、通知、统计Job故障时实例仍ready。

冷启动Audit/Deletion校验失败为not-ready；已serving后发现Audit异常保持数据面ready并冻结高风险管理。

## 11. 容量与超时基线

| 项目 | 默认/目标 |
|---|---:|
| Key Messages/Models | 各60 RPM burst10 |
| Key硬并发 | 5 |
| Credential | 并发5、60 RPM |
| Group RPM/并发 | unlimited |
| Group queue | ≤2×effective concurrency |
| pre-upstream deadline | 30s |
| non-stream内存/硬上限 | 8/64 MiB |
| Reservation | 2 GiB/32槽，wait queue64 |
| SSE pending | 1 MiB |
| connect | 5s，可配1–30s |
| non-stream upstream | 300s共享 |
| stream idle | 30s，可配5–600s |
| client write idle | 120s |
| non-stream delivery | 300s |
| cancel grace | 2s |
| Messages Attempt / ConnectionAttempt | 各最多3 |
| affinity/Session idle | 24h/30m |
| 429 cooldown | 60/120/300/900s，单次≤15m |
| Job lease/heartbeat | 60/20s |

性能目标：≥200RPS、≥1000并发SSE、added latency p95/p99≤20/50ms、SSE relay p95/p99≤10/25ms。

## 12. 日常巡检与交接

每日：ready/版本/Schema、平台5xx/SLO burn、Queue/Lease/Reservation、DB/WAL/vacuum、磁盘/inode/tmp、Proxy/Bundle、Credential maintenance、Job/Outbox、Audit seal、backup age、critical alerts。

每周：备份完整性、secret/日志扫描趋势、权限/User/Key过期、分区与下月预建、slow query、容量预测、Bundle drift。

每月：隔离全量恢复、升级/rollback演练、24h soak趋势、KeyProvider历史版本引用、Content retention/Deletion Ledger、应急联系人。

交接包含所有open incident、静默、待审批、失败Job、即将过期grant、manual recovery Credential和外部evidence blocker。

## 13. Proxy 与 Direct 运维

- 每Credential始终有带epoch Binding；
- auto只在创建/显式重绑时选Proxy，无容量则Direct；
- proxy_required等待，direct固定直连；
- Active Credential不按请求切proxy/direct；
- Proxy默认最多5个Credential，无请求级总并发/RPM；
- Probe只做DNS/TCP/tunnel/TLS/ALPN，无token/Messages；
- 407首次标unhealthy_auth；TLS替换/ALPN破坏标unhealthy_tls_passthrough；
- 覆盖secret后立即全路径probe，再按60s周期，连续2次成功恢复；
- Static出口漂移阻断；Dynamic/Direct漂移审计。

重绑必须通过管理Command，递增egress+profile epoch并drain旧pool。

## 14. Bundle 运维

生命周期`draft→verified→canary→active→retired`，正交runtime `loadable|quarantined`。Loader验证JCS/SHA-256/Ed25519、provenance/privacy/ABI/engine/evidence，确定性编译、自检、原子pointer swap。

Canary必须绑定具体cohort/engine/report hash。在途Attempt持旧Arc；新Attempt使用新generation。quarantine立即阻止新Attempt并drain旧pool。Rollback切完整前一verified artifact；A→B→A也产生新activation generation。

Windows 2.1.241 H1当前为 `lifecycle=verified` 且 evidence gate 已通过（ReadyForCanary），尚未进入 `canary` 生命周期。macOS/Linux capture缺口只阻断对应Archetype；Linux native Engine、安全、负载是全局生产门禁。

## 15. OAuth、Setup 与 Browser 维护

提前refresh时旧token有效则继续；401/token失效时停止Credential新Lease。并发401 singleflight。Setup Token只作bootstrap；交换结果保留 `setup_token_subscription` auth kind，并复用相同的 token-version/refresh/CAS 维护机制。只有显式同账号认证迁移才改变 auth kind。

refresh invalid且Managed Browser Healthy时，silent authorize使用原Cookie/Storage和固定Egress；登录态有效则自动consent/exchange/verify/CAS。页面出现login、验证码、account chooser、Passkey、TOTP或SSO时进入ManualRecoveryRequired并告警。

Proxy故障时维护进入WaitingEgress，不临时直连。account UUID mismatch或CAS/epoch conflict时丢弃候选token/browser material。PLAN失败只影响展示。

## 16. Job、Outbox 与后台任务

Durable Job使用scheduled/lease/heartbeat/checkpoint/generation。worker领取事务提交后才执行外部工作；旧worker lease过期后的迟到结果因generation/CAS被丢弃。

Job与业务资源变化、Audit、Outbox在一个短事务提交。Outbox consumer幂等；外部通知退避1/5/15/30min，最终dead letter并告警，不回滚业务状态。

维护、PLAN、Proxy probe、backup、retention、aggregation使用独立限速和worker pool，不占Messages资源。重启恢复durable Job/cooldown，不恢复实时queue/lease/socket。

## 17. Queue、Lease、Reservation 与 SSE

- Key并发满立即429，不进Group；
- Group queue满503/2s，等待到共享30s deadline为503/5s；
- Group RPM等待到期429/5s；
- Lease年龄本身不是强制释放依据，长SSE可合法持有；
- Cancel先释放Key/Group，Lease等Transport确认或2s grace；
- Reservation leak告警时停止新non-stream admission，核对buffer owner/DEK，不手改DB计数；
- SSE 1MiB背压，pending非空时client write idle120s；背压暂停upstream idle；
- commit后错误只关闭流，不追加事件。

重启后未闭合Request/Attempt标`interrupted|commit_unknown|usage_unknown`。

## 18. Metrics、日志与 Trace

关键指标：route/status/source、platform5xx、added/SSE relay latency、queue depth/wait、Lease active/hold、Reservation bytes/wait、resource invariant、Transport pool/connect/protocol、Proxy/Bundle、DB pool/write/WAL/vacuum、backup/drill、audit chain、Job/Outbox、Browser/refresh、disk/inode/tmp。

Prometheus label仅使用route、status class、error class、Group tier、client class、Archetype version等低基数值。User/Key/Credential/Session/Request进入结构化日志/trace字段，不做label。日志只允许脱敏字段。

Trace span沿Request→Queue→Lease→ConnectionAttempt→Messages Attempt→Delivery，记录snapshot/epoch/digest，不记录secret/Body。

## 19. SLO 与性能发布门槛

- 月度数据面可用性99.5%；
- 合格请求平台自身5xx≤0.1%；
- 策略4xx/429、Anthropic原始错误、client cancel、计划维护分栏；
- added latency p95/p99≤20/50ms；SSE relay≤10/25ms；
- JSON/SSE原始字节一致性100%；
- 24h soak无task/socket/Lease/Reservation/buffer/tmp持续增长。

性能证据必须来自生产样式Linux、BoringSSL、DB、Proxy/direct和完整遥测路径。mock relay高吞吐只证明局部余量。

## 20. 告警、去重与静默

| 告警 | 默认 |
|---|---|
| PostgreSQL不可达 | critical，ready false |
| WAL archive age >300s | critical |
| baseline age >26h | critical |
| restore drill >45d | critical |
| Audit/Deletion mismatch | critical |
| resource invariant violation | 任意一次critical |
| 下月分区缺失 | 月界前7天critical |
| Group queue | >70% 10m warning；>90%/拒绝 critical |
| Reservation | ≥24/32 10m warning；≥30/32或持续wait critical |
| disk/inode | <20% warning、<10% critical、<5%撤ready |
| Group owner unavailable | critical |
| Group无可调度Credential | high；全Group则critical |
| Proxy auth/TLS | 首次确定性失败 affected-scope critical |
| Active Bundle quarantine | affected Archetype critical |
| Manual Recovery | warning；Group全部则critical |
| Job/Outbox dead letter | critical |

静默只抑制外部通知，不隐藏Alert/Event。恢复时发送recovery。SLO burn建议14.4×/1h+5m和6×/6h+30m page。

## 21. Release 工件与升级预检

Release包含binary、UI assets、migration manifest、SBOM、provenance、signature/hash、支持Schema/Bundle ABI与客户端兼容矩阵。

预检：Release签名；新旧binary Schema共同范围；Active Bundle ABI；WAL≤5m、baseline≤26h、drill<45d；Audit/Deletion正常；disk/inode/Reservation余量；无critical安全/完整性告警；expand migration测试；rollback artifact可用。

依赖、BoringSSL/H2或编译选项变化需重跑wire/Bundle Canary门禁。

## 22. Drain、切换与 Rollback

Drain默认300s：

1. lifecycle→draining，立即撤ready；
2. 停新Messages；
3. 已排队请求继续至原deadline；
4. 已提交请求/SSE尽量完成；
5. Job停止领取新lease并checkpoint；
6. deadline到期取消剩余；
7. flush Request/Audit/Outbox、关闭pool并退出。

安装到新release目录，原子切`current`，60s内启动并通过health/ready、管理preflight、Bundle self-test。ready/平台5xx/latency/resource invariant/DB写异常触发回滚。

回滚切前一binary；Schema保持；Bundle pointer独立保持或显式回滚。destructive contract不与切换同release。单实例升级有短暂入口中断，属于计划维护而非HA。

## 23. WAL、基线与备份校验

- 持续WAL，成功归档年龄≤5m；
- 每日加密base backup；
- 至少一份异机/异存储；
- 默认保留7日、4周、12月基线及覆盖所需WAL；
- 覆盖DB/WAL、Content Audit密文/元数据、Bundle/附件、Deletion Ledger、Audit seal、release/schema lineage；
- Queue/Lease/socket/tmp/in-flight SSE/Browser临时目录排除；
- Backup根密钥在DB与仓库之外；
- 每周完整性校验；
- manifest绑定system/timeline/LSN、hash、key version、ledger watermark和lineage。

backup故障不撤ready，但立即critical并消耗恢复安全预算。

## 24. 离线生产恢复与演练

1. 隔离生产listener、Browser、Anthropic、外部通知；
2. 选择manifest并验signature/AEAD/hash/key version/system/timeline/LSN；
3. 在隔离新PostgreSQL恢复base+WAL至目标点；
4. 校验Schema/FK/count/Active Pointer/Audit seal；
5. 恢复Audit/Bundle对象；
6. 重放Deletion Ledger并再次销毁旧备份复活对象；
7. maintenance/no-egress/no-notification启动；
8. readiness preflight与本地serving simulation；
9. 切换生产并确认ready；
10. 第一条审计引用manifest、旧链根和restore lineage；
11. 记录RPO/RTO并销毁隔离材料。

RPO≤5m，RTO≤60m。每月全量隔离演练；45天无成功演练保持critical。演练不连接Anthropic、不启动Browser reauth、不发外部通知。

## 25. Content Audit 与 Deletion Ledger

Full范围要求Original和首次Final在首字节前durable；失败503/5s且上游调用为零。首字节后审计故障记audit_gap，保持retry/响应。Retention默认7天，Legal Hold阻止删除。

删除：检查hold→先append Ledger→销毁wrapped DEK/密文→记录结果→Audit/Outbox。Ledger自身hash chain并进入backup manifest。恢复ready前必须重放。

Content Audit Store/Key故障只影响full相关请求；metadata-only可继续。审计对象与response tmp分目录。

## 26. DB、磁盘、KeyProvider 与 Audit 故障

| 事故 | 自动行为 | 运维动作 | Ready |
|---|---|---|---|
| DB失联 | 停新请求；已commit流尽量完成 | 查连接/锁/WAL/容量，恢复后reload | false |
| disk<安全线 | 停新Reservation/相关写 | 定位DB/WAL/spill/audit，只清理已确认对象 | 最低线false |
| Business Key失效 | 停解密和新serving | 恢复当前/历史version，检查日志 | false |
| Backup Key缺失 | 停备份 | 恢复外部key，补备份/验证 | true+critical |
| Audit chain异常 | 冻结reveal/全文/密钥/权限/策略写 | 比对外部seal，保全证据 | 运行true；启动false |
| Content Audit故障 | full请求503或started后gap | 修复store/key、核对gap | true |

Lease/Reservation故障不通过手工SQL改实时counter；以actor/trace/invariant证据定位，必要时drain/restart并将未闭合请求标未知。

## 27. Proxy、Bundle 与 Anthropic事故

Proxy 407：自动unhealthy_auth、绑定Credential transport blocker；覆盖secret、全路径probe、连续2次成功恢复。TLS interception：撤除终止、查证书/ALPN，认证状态保持。

Bundle invalid/drift：quarantine、阻止新Attempt、drain旧pool；回滚完整verified artifact或停对应cohort。网络/Bundle事故不触发token refresh或改变Profile/OS/Egress。

Anthropic事故：按direct/proxy/DNS/TLS多路径证据判断；使用真实业务结果和非Messages路径probe，不生成合成Messages。维持有界retry/cooldown；ready保持，受影响Group告警。

## 28. 安全值班与事后复盘

先缩小对象域/撤ready，再保存日志、manifest、hash、seal、timeline。工单、聊天、命令行和截图排除token/Cookie/Proxy密码/Session HMAC。审计异常保留历史，不重封旧链。

恢复/回滚产生新recovery event，不删除Alert。复盘包含影响/SLO、时间线、commit边界、RPO/RTO、证据hash、根因、促成因素、检测差距、完成项和带owner/date/验证条件的行动项。

## 29. 只读诊断命令模板

```bash
systemctl status super-gateway.service --no-pager
systemctl show super-gateway.service -p MainPID -p ActiveState -p SubState
journalctl -u super-gateway.service --since "TIME" --until "TIME" -o json-pretty
curl --fail --silent http://127.0.0.1:DATA_PORT/healthz
curl --silent --write-out '%{http_code}\n' http://127.0.0.1:DATA_PORT/readyz
ss -lntp
ps -o pid,ppid,etime,%cpu,%mem,rss,vsz,nlwp,cmd -p MAIN_PID
df -h /var/lib/super-gateway POSTGRES_DATA
df -i /var/lib/super-gateway POSTGRES_DATA
du -x -h --max-depth=2 /var/lib/super-gateway
```

```bash
PGSERVICE=gateway_readonly psql -X -v ON_ERROR_STOP=1 -c "SELECT version,name,checksum,outcome,completed_at FROM ops.schema_migration ORDER BY version DESC LIMIT 20;"
PGSERVICE=gateway_readonly psql -X -v ON_ERROR_STOP=1 -c "SELECT kind_code,state_code,count(*),min(coalesce(next_retry_at,scheduled_at)) AS oldest FROM ops.durable_job GROUP BY kind_code,state_code ORDER BY oldest;"
PGSERVICE=gateway_readonly psql -X -v ON_ERROR_STOP=1 -c "SELECT archived_count,failed_count,last_archived_wal,last_archived_time,last_failed_wal,last_failed_time FROM pg_stat_archiver;"
PGSERVICE=gateway_readonly psql -X -v ON_ERROR_STOP=1 -c "SELECT severity,state,object_type,rule_id,first_seen,last_seen FROM ops.alert WHERE state IN ('open','acknowledged','silenced') ORDER BY severity DESC,last_seen DESC;"
```

```bash
super-gatewayd bundle verify --artifact BUNDLE_PATH --trust-store TRUST_STORE --offline
super-gatewayd release verify --manifest RELEASE_MANIFEST --artifact RELEASE_BINARY --offline
super-gatewayd transport probe --egress EGRESS_ID --dns --tcp --tunnel --tls --alpn --no-credential --no-messages
BACKUP_TOOL verify --manifest MANIFEST --offline
BACKUP_TOOL restore --manifest MANIFEST --target ISOLATED_TARGET --recovery-point RECOVERY_POINT --network disabled
```

末组是待实现/选型CLI合同；secret通过credential file/PGSERVICE传递，不进命令行。

## 30. Checklist 与 Reader Check

升级前：artifact签名/SBOM、Schema/ABI、migration、WAL/base/drill、Audit/Deletion、disk/inode/Reservation、Bundle evidence、rollback与值班。恢复放行前：隔离、manifest/key、base+WAL、Schema/Audit/Ledger、对象擦除、Bundle hash、no-egress/no-notification simulation、RPO/RTO、lineage、ready。事故关闭前：Alert resolved/recovery、incomplete状态收敛、资源/tmp无泄漏、timeline/hash归档、follow-up owner/date。

Reader Check：生产服务数量；backup故障是否ready；DB故障；重启恢复范围；auto/direct；Bundle rollback；macOS/Linux与Linux native两类门禁；Browser人工恢复；SSE背压；长Lease；离线恢复；Deletion Ledger；Audit运行/启动语义；binary/Schema/Bundle rollback边界；Windows Canary与GA区别。
