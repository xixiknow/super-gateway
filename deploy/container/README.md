# 容器部署

该镜像只运行一个长期进程：`super-gatewayd`。React 管理台在构建阶段生成并嵌入二进制，因此数据面、管理 API 和 `/admin/` 页面属于同一个镜像和同一个运行容器。PostgreSQL 是外部持久依赖；`migrate` 使用同一镜像作为一次性 Compose service。

## 1. 前置条件

- Linux AMD64 或 ARM64 容器主机；
- PostgreSQL 16+；
- 独立的 `gateway_migrator` 与 `gateway_runtime` 登录连接，runtime 连接的 `current_user` 必须为 `gateway_runtime`；
- Bundle Ed25519 Trust Store；
- 至少一个与镜像目标架构、Engine ABI 和 Capability 匹配的 Linux 签名 Transport Bundle；
- Docker Engine 24+ 与 Docker Compose v2。

镜像采用 Debian/glibc。Alpine/musl 不在受支持 target 中。

## 2. 准备本地部署目录

```bash
mkdir -p deploy/container/secrets deploy/container/config deploy/container/bundles
cp deploy/container/.env.example deploy/container/.env
chmod 700 deploy/container/secrets deploy/container/bundles
```

创建四个仅包含单个值的 Secret 文件：

```text
deploy/container/secrets/migrator-database-url
deploy/container/secrets/runtime-database-url
deploy/container/secrets/digest-key
deploy/container/secrets/audit-integrity-key
```

示例 DSN 结构：

```text
postgres://gateway_migrator:PASSWORD@POSTGRES_HOST:5432/super_gateway
postgres://gateway_runtime:PASSWORD@POSTGRES_HOST:5432/super_gateway
```

生成本地高熵 Digest/Audit key：

```bash
openssl rand -hex 32 > deploy/container/secrets/digest-key
openssl rand -hex 32 > deploy/container/secrets/audit-integrity-key
chmod 600 deploy/container/secrets/*
```

将正式 Trust Store 写入：

```text
deploy/container/config/bundle-trust-store.json
```

将签名 Linux Bundle JSON 放入空目录 `deploy/container/bundles/`。目录中不得混放 README、临时文件或未签名 JSON；启动时会逐个解析并验证。该目录必须允许容器 UID/GID `10001:10001` 写入，以支持后续管理面发布 Bundle。

首次空库启动时，在 `deploy/container/.env` 同时设置：

```dotenv
GATEWAY_BOOTSTRAP_ADMIN_USERNAME=admin
GATEWAY_BOOTSTRAP_ADMIN_PASSWORD=至少十四个字符的随机初始密码
```

首次登录并改密、注册 TOTP 后，从部署环境删除这两个变量。已有管理员的数据库保持为空即可。

## 3. 启动

```bash
docker login ghcr.io
docker compose --env-file deploy/container/.env pull
docker compose --env-file deploy/container/.env up -d
```

Compose 先运行一次性 `migrate`，成功后启动 `gateway`。长期容器在 serving 前依次执行静态配置检查和 Schema 兼容性检查。

- 数据面：`http://HOST:8080`
- Health：`http://HOST:8080/healthz`
- Readiness：`http://HOST:8080/readyz`
- 管理台：`http://127.0.0.1:8081/admin/`

检查状态：

```bash
docker compose --env-file deploy/container/.env ps
docker compose --env-file deploy/container/.env logs --tail=200 gateway
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

## 4. 升级与回滚

修改 `SUPER_GATEWAY_IMAGE` 为不可变版本或 digest，随后执行：

```bash
docker compose --env-file deploy/container/.env pull
docker compose --env-file deploy/container/.env up -d
```

推荐生产使用 digest：

```dotenv
SUPER_GATEWAY_IMAGE=ghcr.io/xixiknow/super-gateway@sha256:IMAGE_DIGEST
```

数据库 migration 只前进，不执行 down migration。二进制回滚前必须通过项目的 Schema compatibility 检查。

## 5. 安全默认值

- 容器使用固定非 root UID/GID `10001:10001`；
- 根文件系统只读，只开放 Bundle 和 response tmp 写目录；
- Drop 全部 Linux capabilities，启用 `no-new-privileges`；
- 管理端口默认只绑定宿主 `127.0.0.1`；
- Secret 只通过 `/run/secrets` 文件读取；
- `tini` 转发 SIGTERM，应用最多使用 300 秒 drain，Compose 等待 330 秒；
- Proxy、Content Audit、Backup 和 Managed Browser 均为显式配置能力，不随基础 Compose 自动启用。

GHCR 新 package 默认可能是 private。公开拉取前需要在 GitHub Package 设置中将可见性调整为 public；私有部署应先完成 `docker login ghcr.io`。
