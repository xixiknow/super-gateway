# R7 本地验证记录

> 日期：2026-08-25  
> 结论：R7 本地实现与自动化门禁通过；R6 的 Linux production promotion 和外部 wire evidence 继续按独立门禁追踪。

## 已实现

- SSE 原始字节中继，1 MiB 在途字节预算与 120 秒客户端写空闲超时；
- 非流式 8 MiB 内存阈值、64 MiB 硬上限、32 个大响应保障槽、64 个等待位与 30 秒等待；
- AES-256-GCM 分帧加密 spill、交付后删除和启动孤儿清扫；
- Platform Key permit 持有到客户端交付终态；
- response commit fence、一次性 delivery terminal callback 与生产者终态信号；
- response Header allowlist/hop-by-hop 清理，Body/SSE 不改写；
- SSE 与非流式 usage 旁路观察，`source × completeness` 正交且不补零；
- 客户端取消估算只累计完整终止的 SSE 事件；半事件不解析，未知内容 delta 标记 gap，signature/citation 不计作文本；
- upstream EOF 与取消并发时固定落为客户端取消，已知 delta 缺少必需载荷时同样标记 gap，避免静默低估；
- 同一取消估算自然键重放必须与原 evidence 完全一致；不同内容显式冲突，后补成本按唯一 Usage Observation 幂等写入；
- `Usage Observation` 通过 `request_month + request_id + attempt_id` 复合外键绑定精确 Attempt；已知 cancel estimate 可替代 official unknown，但不覆盖 official partial/complete；
- 上游编码 Body 接收字节与客户端交付字节分开记录，并以单调更新处理 usage/terminal 竞态；
- official/Console/local/cancel usage 选择顺序和定点 pico-USD 成本计算；
- Request、Submission Intent、Delivery、Usage、Cost 持久化及 CAS/单终态约束；
- 低基数请求、交付、usage 指标快照。

## 验证结果

| 门禁 | 结果 |
|---|---|
| `python tools/validate_contracts.py` | 47 个 JSON、2981 项一致性检查通过 |
| `cargo test -p gateway-services --lib` | 54 个测试通过 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 通过 |
| R7 fresh PostgreSQL telemetry gate | migration 8、commit/usage/cost/单终态通过 |
| SSE arbitrary-chunk golden | 输出字节与输入拼接完全一致，usage 仅旁路观察 |
| SSE cancel boundary golden | 完整事件计入、尾部半事件排除、未知 delta fail-unknown |
| 8/64 MiB 与 spill boundary | 阈值、阈值+1、上限+1 均通过 |
| 32 active / 64 waiting / 第 65 个拒绝 | 通过 |
| Platform Key permit 交付生命周期 | 客户端 Body 未完成时不释放，drop 后释放 |

## 环境说明

后续已在纯 ASCII `CARGO_TARGET_DIR` 下完成 Windows `boring-backend` 全 feature 的 19/19 测试和 Clippy；这消除了本机路径/工具链阻断，但 Linux x86_64/arm64 native transport lane 仍是独立 production promotion gate。
