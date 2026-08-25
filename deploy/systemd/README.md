# systemd 部署工件

`super-gateway-migrate.service` 使用独立的 `super-gateway-migrate` Unix 身份和 `/etc/super-gateway/migrate.env` 执行前向 schema 迁移；长期运行的 `super-gateway.service` 使用 `super-gateway` 身份和 `/etc/super-gateway/runtime.env`。两个文件必须是 systemd 及 Bash `source` 均可解析的 `KEY=VALUE` 格式，且分别只包含 migrator/runtime 数据库凭据。运行账号仅写入 `/var/lib/super-gateway` 和 `/var/log/super-gateway`。

升级命令：

```bash
sudo ./super-gateway-upgrade.sh /opt/super-gateway/releases/VERSION
```

脚本依次校验发布证据和静态配置、使用隔离的 migrator 环境执行 expand migration、通过 `SIGTERM` 等待应用 drain、原子切换 `current` 链接，并在 60 秒 readiness 窗口失败时回退二进制。回滚后再校验上一版 readiness；候选版和回滚版均不就绪时以独立退出码报警。Schema 不随二进制回滚。
