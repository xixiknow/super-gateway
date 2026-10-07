import { Locale } from "./i18n";

/* ============================================================
   通用资源展示工具:列名与枚举值的中文映射 + 单元格渲染
   （供 App.tsx 通用表格与各详情对话框共用）
   ============================================================ */

export const zhColumns: Record<string, string> = {
  request_type: "请求类型", request_timing: "耗时", first_content_ms: "首字", duration_ms: "总耗时", tps: "TPS",
  platform_key_name: "平台 Key", group_name: "分组", model: "模型", reasoning_effort: "思考强度", client_class: "客户端", token_usage: "TOKEN",
  cache_read_input_tokens: "读缓存 Token", cache_creation_input_tokens: "写缓存 Token", endpoint: "端点", phase: "阶段", outcome: "结果",
  id: "ID", name: "名称", username: "用户名", display_name: "显示名称", email: "邮箱", role: "角色", status: "状态", revision: "版本",
  created_at: "创建时间", updated_at: "更新时间", owner_user_id: "所有者用户", group_id: "分组", owner_executor_id: "归属执行器",
  owner_generation: "归属代次", credential_count: "凭据数量", expires_at: "过期时间", session_id: "会话 ID", model_id: "模型 ID",
  request_id: "请求 ID", state: "状态", kind: "类型", reason: "原因", upstream_model_id: "上游模型 ID", source: "目录来源",
  capability_version: "能力版本", capability_state: "能力状态", last_seen_at: "最近发现时间",
  account_uuid: "账号", purpose: "用途", auth_kind: "认证方式", lifecycle_state: "生命周期", scheduling_state: "调度状态",
  bucket_start: "日期", request_count: "请求数", input_tokens: "输入 Token", output_tokens: "输出 Token",
  estimated_amount: "估算金额（美元）", completeness: "完整度", usage_completeness: "用量完整度",
  intent_state: "提交意图", started_at: "开始时间", completed_at: "完成时间", http_status: "HTTP 状态",
  priority: "优先级", weight: "权重", concurrency: "并发上限", messages_rpm: "每分钟消息数",
  profile_epoch: "配置代次", egress_epoch: "出口代次", device_epoch: "设备代次", token_version: "令牌版本",
  management_class: "管理类别", plan_tier: "订阅等级", last_error_code: "最近错误", operation_id: "操作 ID",
  archetype_version_id: "原型版本", capture_cohort: "采集批次", scheduled_at: "计划时间", finished_at: "结束时间",
  trigger: "触发方式", attempt_count: "尝试次数", outcome_code: "结果", error_category: "错误类别",
  browser_provider: "浏览器提供方", job_state: "任务状态", strategy_state: "策略状态", conflict_class: "冲突类别",
  generation: "操作代次", next_retry_at: "下次重试", adapter: "适配器", adapter_version: "适配器版本",
  material_version: "材料版本", material_expires_at: "材料过期时间", last_verified_at: "最近验证",
  next_health_at: "下次健康检查", credential_id: "凭据 ID", active_material_version_id: "生效材料版本 ID",
  version: "版本", lifecycle: "生命周期", is_active: "当前生效", pointer_revision: "指针版本", content_hash: "内容哈希",
  accepted_clients: "接受的客户端", proxy_policy: "代理策略", proxy_policy_code: "代理策略", fully_managed_required: "要求全托管",
  validated_at: "校验时间", published_at: "发布时间",
  default_rpm: "默认 RPM", default_rpm_burst: "默认 RPM 突发", queue_capacity: "队列容量", queue_timeout_ms: "队列超时(ms)",
  pre_upstream_wait_ms: "上游前等待(ms)", preferred_capacity_wait_ms: "容量偏好等待(ms)", upstream_connect_ms: "上游连接(ms)",
  upstream_non_stream_total_ms: "非流式总时限(ms)", upstream_stream_idle_ms: "流式空闲(ms)", min_retry_budget_ms: "最小重试预算(ms)",
  cancel_grace_ms: "取消宽限(ms)", queue_full_retry_after_ms: "队满重试间隔(ms)", queue_wait_retry_after_ms: "排队重试间隔(ms)",
  default_credential_concurrency: "凭据默认并发", default_credential_rpm: "凭据默认 RPM", max_concurrency: "并发上限",
  rpm_limit: "RPM 上限", rpm_burst: "RPM 突发", queue_used: "队列占用", effective_concurrency: "有效并发",
  configured_concurrency: "配置并发", total_credential_capacity: "凭据总容量", active_group_permits: "组级活跃许可",
  active_leases: "活跃租约", active_session_claims: "活跃会话占位", resource_balance: "资源余量", owner_valid: "Owner 有效",
  group_revision: "分组版本", scheduling_config_version: "调度配置版本", scheduling_weight: "调度权重",
  credential_available: "可用凭据", credential_abnormal: "异常凭据", egress_mode: "出口模式", model_scope: "模型范围",
  month_tokens: "本月 Token", month_amount: "本月金额（美元）", last_success_at: "最后成功", recent_failures: "24 小时失败",
  scope: "作用域", rule_count: "规则数", entry_count: "条目数", high_risk: "高风险动作", group: "分组",
  system_prompt_mode: "System 模式", os_family: "客户端 OS", egress_stability: "出口稳定性",
  price_version: "价格版本", currency: "币种", effective_from: "生效自", effective_to: "失效至", source_uri: "来源",
  rule_id: "规则标识", path: "字段路径", risk: "风险",
};

export function columnLabel(column: string, locale: Locale): string {
  if (locale === "zh-CN") return zhColumns[column] ?? column.replaceAll("_", " ");
  return column.replaceAll("_", " ").replace(/\b\w/g, (value) => value.toUpperCase());
}

export const zhValues: Record<string, string> = {
  claude_code_cli: "Claude Code", non_claude_code_cli: "其他客户端", adaptive: "自适应", enabled: "已启用", xhigh: "超高", minimal: "最低", none: "无", max: "最高",
  active: "活跃", disabled: "已禁用", archived: "已归档", revoked: "已吊销", pending: "待处理", mfa_pending: "待完成安全设置",
  platform_admin: "平台管理员", key_owner: "密钥所有者", complete: "完整", partial: "部分", unknown: "未知",
  claude_subscription: "Claude 订阅", count_tokens: "令牌计数", oauth_subscription: "OAuth 订阅", setup_token_subscription: "Setup Token 订阅",
  console_api_key: "控制台 API 密钥", healthy: "健康", eligible: "可调度", cooldown: "冷却中", blocked: "已阻止",
  anthropic_public_docs: "Anthropic 公开目录", anthropic_models_api: "凭据验证", builtin_snapshot: "内置目录快照", reviewing: "审核中", published: "已发布", discovered: "已发现",
  transport_unavailable: "传输不可用", pending_profile: "等待配置", pending_egress: "等待出口", manual_recovery_required: "需要人工恢复",
  all_published: "全部已发布", allowlist: "白名单", auto: "自动", direct_only: "仅直连", proxy_only: "仅代理",
  draft: "草稿", validated: "已校验", retired: "已退役", quarantined: "已隔离",
  observe: "观察", throttle: "限速", reject: "拒绝", preserve: "保留", strip_client: "剥离客户端", strip_all: "全部剥离",
  replace: "替换", low: "低", medium: "中", high: "高", true: "是", false: "否",
};

export const enValues: Record<string, string> = {
  claude_code_cli: "Claude Code", non_claude_code_cli: "Other client",
  anthropic_public_docs: "Anthropic public catalog",
  anthropic_models_api: "Credential verified",
  builtin_snapshot: "Built-in catalog snapshot",
};

export function displayCell(value: unknown, locale: Locale): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value).slice(0, 120);
  const raw = String(value);
  const normalized = raw === "shadow" ? "eligible" : raw === "canary" ? "validated" : raw;
  return locale === "zh-CN" ? zhValues[normalized] ?? normalized : enValues[normalized] ?? normalized.replaceAll("_", " ");
}
