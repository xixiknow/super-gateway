# 容器蓝绿部署

本目录定义生产容器的蓝绿拓扑。它需要一个外置流量入口（示例为 Nginx 或 HAProxy）、两套同时运行的网关容器和同一个 PostgreSQL。蓝、绿使用固定镜像 digest，切流只改变代理上游；旧颜色在观察窗内保留，便于快速回滚。

## 流式请求约束

代理必须关闭请求和响应缓冲、缓存、压缩以及响应改写，使用 HTTP/1.1 keep-alive。Nginx 的 `proxy_read_timeout`、`proxy_send_timeout` 和 HAProxy 的 `timeout client/server` 设为 150 秒，高于应用的 30 秒上游空闲和 120 秒客户端写空闲语义。它们是相邻字节空闲保护，不是整流总时限。

`/readyz` 检查间隔至少 1 秒。排空期间返回 503 是预期行为；代理摘流只阻止新请求，真正的在途请求排空由应用收到 SIGTERM 后执行。旧颜色停止时使用 330 秒宽限期（300 秒应用排空 + 余量）。

## 发布流程

1. 固定 `GREEN_IMAGE` 为候选多架构 manifest digest，保存当前 `BLUE_IMAGE` 和 release evidence。
2. 只运行一次候选迁移，且必须满足 expand-only、旧/新二进制都能通过 schema check。Schema 只前进，回滚只回应用镜像。
3. 启动绿环境，连续 60 秒通过 `/readyz`，再执行一次无副作用数据面 smoke 和一条流式首字节探测。
4. 执行 `./switch-color.sh green`。代理停止把新请求送到蓝环境，已有连接继续由蓝环境处理。
5. 观察错误率、SSE 首字节延迟、流中断、连接数、数据库/WAL 和 readiness。确认稳定后再停止蓝环境。
6. 绿环境失败时，在蓝环境仍健康的情况下执行 `./switch-color.sh blue`，再优雅停止绿环境。不要执行 down migration。

## 使用方式

复制 `runtime.env`、secret、trust store 和 bundles 到本目录，设置两个不可变 digest：

```dotenv
BLUE_IMAGE=ghcr.io/xixiknow/super-gateway@sha256:OLD_DIGEST
GREEN_IMAGE=ghcr.io/xixiknow/super-gateway@sha256:CANDIDATE_DIGEST
PUBLIC_DATA_PORT=8080
PUBLIC_ADMIN_PORT=8081
```

```bash
docker compose -f docker-compose.yml --env-file runtime.env up -d proxy gateway_blue
./switch-color.sh green
```

`switch-color.sh` 会先启动候选、验证 readiness、执行 Nginx 配置检查，再 reload 代理。HAProxy 用户应使用 `haproxy.cfg`，通过 runtime socket enable/disable 对应 server；不要把两个颜色同时设为 active。

## 回滚与清理

切流后的观察窗内保留旧颜色和旧 digest。回滚先切换代理，再等待旧颜色 readiness，最后执行 `docker compose stop -t 330 gateway_green`。旧环境已停止时，先启动并通过 readiness，再恢复流量。所有切换记录 active/candidate digest、migration 版本、预检 run id、切流时间、观察结果和回滚原因。
