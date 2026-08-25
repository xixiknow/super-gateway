import { FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import {
  ApiError,
  MfaEnrollment,
  Principal,
  api,
  changePassword,
  confirmMfa,
  currentPrincipal,
  enrollMfa,
  login,
  logout,
  verifyMfa,
} from "./api";

type NavEntry = { path: string; label: string; icon: string; adminOnly?: boolean; section: string };

const navigation: NavEntry[] = [
  { path: "/", label: "首页", icon: "home", section: "总览" },
  { path: "/users", label: "用户", icon: "users", adminOnly: true, section: "访问与凭据" },
  { path: "/platform-keys", label: "Platform Key", icon: "key", section: "访问与凭据" },
  { path: "/groups", label: "Credential Group", icon: "layers", adminOnly: true, section: "访问与凭据" },
  { path: "/credentials", label: "Credential", icon: "shield", adminOnly: true, section: "访问与凭据" },
  { path: "/egress", label: "Proxy / Egress", icon: "globe", adminOnly: true, section: "流量" },
  { path: "/models", label: "模型与能力", icon: "box", adminOnly: true, section: "流量" },
  { path: "/requests", label: "请求与用量", icon: "activity", section: "流量" },
  { path: "/bundles", label: "Archetype / Bundle", icon: "package", adminOnly: true, section: "流量" },
  { path: "/governance", label: "规则与治理", icon: "sliders", adminOnly: true, section: "治理" },
  { path: "/security", label: "审批与内容审计", icon: "lock", adminOnly: true, section: "治理" },
  { path: "/alerts", label: "告警与通知", icon: "bell", adminOnly: true, section: "治理" },
  { path: "/operations", label: "运维与系统", icon: "settings", adminOnly: true, section: "系统" },
  { path: "/exports", label: "我的导出", icon: "download", section: "系统" },
  { path: "/account", label: "账号安全", icon: "user", section: "系统" },
];

function Icon({ name }: { name: string }) {
  return <svg className="icon sm" aria-hidden="true"><use href={`#i-${name}`} /></svg>;
}

export function App() {
  const principal = useQuery({ queryKey: ["principal"], queryFn: currentPrincipal, retry: false });
  if (principal.isLoading) return <BootScreen />;
  if (principal.isError || !principal.data) return <LoginScreen />;
  if (principal.data.password_change_required) return <SessionSetupScreen principal={principal.data} initialStage="password-change" />;
  if (!principal.data.mfa_verified) return <SessionSetupScreen principal={principal.data} initialStage="mfa-enroll" />;
  return <ConsoleShell principal={principal.data} />;
}

function BootScreen() {
  return <main className="boot" aria-live="polite"><div className="radar" /><p className="mono">正在校验管理会话与控制面状态…</p></main>;
}

function LoginScreen() {
  const queryClient = useQueryClient();
  const [stage, setStage] = useState<"password" | "mfa">("password");
  const [message, setMessage] = useState("");
  const signIn = useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) => login(username, password),
    onSuccess: (result) => {
      if (result.next_action === "verify_mfa") setStage("mfa");
      else void queryClient.invalidateQueries({ queryKey: ["principal"] });
    },
    onError: () => setMessage("用户名、密码或账号状态不正确。"),
  });
  const mfa = useMutation({
    mutationFn: verifyMfa,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["principal"] }),
    onError: () => setMessage("验证码无效或已使用，请等待下一组验证码。"),
  });
  function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    signIn.mutate({ username: String(data.get("username")), password: String(data.get("password")) });
  }
  function submitMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    mfa.mutate(String(new FormData(event.currentTarget).get("code")));
  }
  return (
    <main className="login-stage">
      <section className="login-story" aria-label="平台说明">
        <div className="brand-mark"><span>SG</span></div>
        <p className="eyebrow mono">CLAUDE TRAFFIC CONTROL / 01</p>
        <h1>让每一次上游调用<br /><em>可解释、可追溯。</em></h1>
        <p className="story-copy">凭据、会话、出口与传输证据在同一条时间线上收敛。控制塔只展示已经发生的事实。</p>
        <div className="signal-strip"><span /><span /><span /><small>CONTROL PLANE READY</small></div>
      </section>
      <section className="login-panel">
        <div className="login-card card">
          <p className="eyebrow">安全入口</p>
          <h2>{stage === "password" ? "登录控制塔" : "验证第二因素"}</h2>
          <p className="muted">Session 使用 HttpOnly Cookie；凭据不会进入浏览器存储。</p>
          {message && <div className="alert alert-err" role="alert"><div><div className="at">验证未通过</div><div className="ad">{message}</div></div></div>}
          {stage === "password" ? (
            <form onSubmit={submitPassword}>
              <div className="field"><label htmlFor="username">用户名</label><input className="inp" id="username" name="username" autoComplete="username" required /></div>
              <div className="field"><label htmlFor="password">密码</label><input className="inp" id="password" name="password" type="password" autoComplete="current-password" required /></div>
              <button className="btn btn-primary btn-lg login-submit" disabled={signIn.isPending}>{signIn.isPending ? "验证中…" : "继续"}</button>
            </form>
          ) : (
            <form onSubmit={submitMfa}>
              <div className="field"><label htmlFor="code">六位验证码</label><input className="inp mono otp" id="code" name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required autoFocus /></div>
              <button className="btn btn-primary btn-lg login-submit" disabled={mfa.isPending}>{mfa.isPending ? "校验中…" : "进入控制塔"}</button>
            </form>
          )}
        </div>
      </section>
    </main>
  );
}

function SessionSetupScreen({ principal, initialStage }: { principal: Principal; initialStage: "password-change" | "mfa-enroll" }) {
  const queryClient = useQueryClient();
  const [stage, setStage] = useState(initialStage);
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [message, setMessage] = useState("");
  const password = useMutation({
    mutationFn: ({ current, next }: { current: string; next: string }) => changePassword(current, next),
    onSuccess: () => {
      setMessage("");
      setStage("mfa-enroll");
      void queryClient.invalidateQueries({ queryKey: ["principal"] });
    },
    onError: () => setMessage("当前密码不正确，或新密码未满足 14–128 个字符的要求。"),
  });
  const beginEnrollment = useMutation({
    mutationFn: enrollMfa,
    onSuccess: (result) => {
      setMessage("");
      setEnrollment(result);
    },
    onError: () => setMessage("TOTP 注册初始化未完成；若已生成种子，请继续使用原种子完成确认。"),
  });
  const confirmation = useMutation({
    mutationFn: (code: string) => enrollment ? confirmMfa(enrollment.id, code) : Promise.reject(new Error("missing enrollment")),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["principal"] }),
    onError: () => setMessage("验证码无效或已使用，请等待下一组验证码。"),
  });

  function submitPasswordChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const next = String(data.get("new_password"));
    if (next !== String(data.get("confirm_password"))) {
      setMessage("两次输入的新密码不一致。");
      return;
    }
    password.mutate({ current: String(data.get("current_password")), next });
  }

  function submitConfirmation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    confirmation.mutate(String(new FormData(event.currentTarget).get("code")));
  }

  return (
    <main className="login-stage">
      <section className="login-story" aria-label="安全初始化说明">
        <div className="brand-mark"><span>SG</span></div>
        <p className="eyebrow mono">SECURITY INITIALIZATION / {principal.id.slice(0, 8)}</p>
        <h1>先建立可信管理会话，<br /><em>再进入控制塔。</em></h1>
        <p className="story-copy">首次登录只执行强制改密和 TOTP 注册。原始密码与 TOTP 种子只停留在当前安全流程中。</p>
      </section>
      <section className="login-panel">
        <div className="login-card card">
          <p className="eyebrow">账号安全</p>
          <h2>{stage === "password-change" ? "修改初始密码" : "注册第二因素"}</h2>
          {message && <div className="alert alert-err" role="alert"><div><div className="at">操作未完成</div><div className="ad">{message}</div></div></div>}
          {stage === "password-change" ? (
            <form onSubmit={submitPasswordChange}>
              <div className="field"><label htmlFor="current-password">当前密码</label><input className="inp" id="current-password" name="current_password" type="password" autoComplete="current-password" required /></div>
              <div className="field"><label htmlFor="new-password">新密码</label><input className="inp" id="new-password" name="new_password" type="password" autoComplete="new-password" minLength={14} maxLength={128} required /></div>
              <div className="field"><label htmlFor="confirm-password">确认新密码</label><input className="inp" id="confirm-password" name="confirm_password" type="password" autoComplete="new-password" minLength={14} maxLength={128} required /></div>
              <button className="btn btn-primary btn-lg login-submit" disabled={password.isPending}>{password.isPending ? "提交中…" : "保存并继续"}</button>
            </form>
          ) : enrollment ? (
            <form onSubmit={submitConfirmation}>
              <p className="muted">在验证器中扫描 URI 或输入下面的 Base32 种子。确认成功后，种子不再展示。</p>
              <div className="field"><label htmlFor="totp-seed">TOTP 种子</label><input className="inp mono" id="totp-seed" value={enrollment.secret} readOnly aria-describedby="seed-note" /></div>
              <p id="seed-note" className="muted mono">{enrollment.otpauth_uri}</p>
              <div className="field"><label htmlFor="confirm-code">六位验证码</label><input className="inp mono otp" id="confirm-code" name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required autoFocus /></div>
              <button className="btn btn-primary btn-lg login-submit" disabled={confirmation.isPending}>{confirmation.isPending ? "确认中…" : "确认并进入控制塔"}</button>
            </form>
          ) : (
            <div>
              <p className="muted">系统将生成一次性 TOTP 种子。请在当前流程内保存到验证器，再输入首个验证码确认。</p>
              <button className="btn btn-primary btn-lg login-submit" onClick={() => beginEnrollment.mutate()} disabled={beginEnrollment.isPending}>{beginEnrollment.isPending ? "生成中…" : "生成 TOTP 种子"}</button>
            </div>
          )}
        </div>
      </section>
    </main>
  );
}

function ConsoleShell({ principal }: { principal: Principal }) {
  const location = useLocation();
  const queryClient = useQueryClient();
  const allowedNavigation = useMemo(
    () => navigation.filter((item) => !item.adminOnly || principal.role === "platform_admin"),
    [principal.role],
  );
  const active = allowedNavigation.find((item) => item.path === location.pathname)?.label ?? "控制塔";
  const sections = useMemo(() => {
    const groups: { section: string; items: NavEntry[] }[] = [];
    for (const item of allowedNavigation) {
      const group = groups.find((g) => g.section === item.section);
      if (group) group.items.push(item);
      else groups.push({ section: item.section, items: [item] });
    }
    return groups;
  }, [allowedNavigation]);
  return (
    <div className="console-shell">
      <a className="skip-link" href="#main-content">跳到主要内容</a>
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark small"><span>SG</span></div><div><b>SUPER GATEWAY</b><small>CONTROL TOWER</small></div></div>
        <nav aria-label="主导航">
          {sections.map((group) => (
            <div key={group.section} role="group" aria-label={group.section}>
              <div className="nav-label">{group.section}</div>
              {group.items.map((entry) => (
                <NavLink key={entry.path} to={entry.path} end={entry.path === "/"} className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}>
                  <Icon name={entry.icon} /><span>{entry.label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot"><span className="live-dot" />单实例 · 受控运行</div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div><p className="crumb">控制塔 / <strong>{active}</strong> · UTC</p></div>
          <div className="top-actions"><button className="search-pill" type="button" aria-label="全局搜索"><Icon name="search" /><span>Search…</span><kbd>⌘K</kbd></button><button className="ibtn soft" aria-label="告警中心"><Icon name="bell" /><i className="ib-dot" /></button><div className="user-chip"><span className="avatar teal">{principal.role === "platform_admin" ? "A" : "O"}</span><div><b>{principal.role === "platform_admin" ? "Platform Admin" : "Key Owner"}</b><small className="mono">{principal.id.slice(0, 8)}</small></div></div><button className="tbtn" onClick={() => void logout().then(() => queryClient.clear())}>退出</button></div>
        </header>
        <main id="main-content" className="main-content" tabIndex={-1}>
          <Routes>
            <Route index element={<Dashboard principal={principal} />} />
            <Route path="groups" element={<GroupPage />} />
            <Route path="credentials" element={<CredentialPage />} />
            <Route path="requests" element={<RequestUsagePage />} />
            {allowedNavigation.filter((entry) => !["/", "/groups", "/credentials", "/requests"].includes(entry.path)).map((entry) => <Route key={entry.path} path={entry.path.slice(1)} element={<ResourcePage entry={entry} />} />)}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

function Dashboard({ principal }: { principal: Principal }) {
  const status = useQuery({ queryKey: ["system-status"], queryFn: () => api<Record<string, unknown>>("/admin/v1/system/status"), enabled: principal.role === "platform_admin" });
  return (
    <div className="page-stack">
      <header className="page-heading"><div><p className="eyebrow mono">LIVE OPERATIONS · UTC</p><h1>系统总览</h1></div><span className="tag t-teal dotled">控制面正常</span></header>
      {status.isError && <div className="alert alert-warn"><Icon name="alert" /><div><div className="at">系统投影暂不可用</div><div className="ad">局部 Widget 失败不会清空其余页面，请稍后重试。</div></div></div>}
      <section className="metric-grid" aria-label="核心指标">
        <Metric label="当前请求" value="—" note="Key / Group / Credential" tone="teal" />
        <Metric label="流式并发" value="—" note="SSE delivery" tone="sky" />
        <Metric label="排队" value="—" note="公平队列" tone="amber" />
        <Metric label="异常凭据" value="—" note="需管理员确认" tone="coral" />
      </section>
      <section className="split-grid">
        <div className="card pad signal-card"><div className="section-head"><div><p className="eyebrow">调用链</p><h2>入口到上游</h2></div><span className="tag t-teal dotled">透明响应</span></div><div className="pipeline"><span>CLIENT</span><i /><span>EDGE</span><i /><span>EXECUTOR</span><i /><span>TRANSPORT</span><i /><span>ANTHROPIC</span></div><div className="timeline compact"><div className="tl-item ok"><b>Header 隐私边界</b><p>来源、Platform Key 与代理认证不会南向泄漏。</p></div><div className="tl-item ok"><b>Body / SSE 原始透传</b><p>旁路 Usage 观察不参与响应构造。</p></div><div className="tl-item warn"><b>外部 Evidence</b><p>Linux native 与 Active Archetype 按独立门禁追踪。</p></div></div></div>
        <div className="card pad"><div className="section-head"><div><p className="eyebrow">需关注</p><h2>运行提示</h2></div><button className="tbtn">查看全部</button></div><ul className="attention-list"><li><span className="tag t-amber">EVIDENCE</span><div><b>Transport promotion gate</b><small>对应能力保持配置关闭</small></div><time>持续</time></li><li><span className="tag t-sky">PLAN</span><div><b>订阅等级仅展示</b><small>不影响权重、路由与资格</small></div><time>规则</time></li><li><span className="tag t-teal">SECURE</span><div><b>审计链启动校验</b><small>高风险操作故障关闭</small></div><time>正常</time></li></ul></div>
      </section>
    </div>
  );
}

function Metric({ label, value, note, tone }: { label: string; value: string; note: string; tone: string }) {
  return <article className={`scard metric ${tone}`}><div className="sh"><span>{label}</span><span className={`signal ${tone}`} /></div><div className="sn">{value}</div><div className="sm">{note}</div></article>;
}

const groupTabs = ["概览", "Credential", "调度与限流", "请求治理", "能力与出口", "用量与审计"];
const credentialTabs = ["概览", "用量与配额", "会话与调度", "身份与传输", "维护与审计"];

function GroupPage() { return <TabbedResource title="Credential Group" eyebrow="GROUP OWNER EXECUTOR" tabs={groupTabs} apiPath="/admin/v1/groups" description="固定 owner Executor 管理状态、调度、刷新与重试；配置候选按 Shadow → Canary → Active 发布。" />; }
function CredentialPage() { return <TabbedResource title="Credential" eyebrow="SUBSCRIPTION IDENTITY" tabs={credentialTabs} apiPath="/admin/v1/credentials" description="OAuth / Setup Token、Profile、Device、Archetype 与 Egress 是同一生命周期对象的正交视图。" />; }

function TabbedResource({ title, eyebrow, tabs, apiPath, description }: { title: string; eyebrow: string; tabs: string[]; apiPath: string; description: string }) {
  const [tab, setTab] = useState(tabs[0]);
  const items = useQuery({ queryKey: [apiPath], queryFn: () => api<unknown[]>(apiPath) });
  return <div className="page-stack"><header className="page-heading"><div><p className="eyebrow mono">{eyebrow}</p><h1>{title}</h1><p>{description}</p></div><button className="btn btn-primary"><Icon name="plus" />新建</button></header><div className="tabs-line" role="tablist" aria-label={`${title} 视图`}>{tabs.map((item) => <button key={item} role="tab" aria-selected={tab === item} className={`tab-line ${tab === item ? "active" : ""}`} onClick={() => setTab(item)}>{item}</button>)}</div>{items.isError && <ErrorState error={items.error} />}<ResourceTable loading={items.isLoading} items={items.data} title={tab} /></div>;
}

function RequestUsagePage() {
  const [view, setView] = useState("请求明细");
  const requests = useQuery({ queryKey: ["requests"], queryFn: () => api<unknown[]>("/admin/v1/requests"), enabled: view === "请求明细" });
  const usage = useQuery({ queryKey: ["usage-summary"], queryFn: () => api<Record<string, unknown>>("/admin/v1/usage/summary"), enabled: view === "聚合分析" });
  const items = view === "请求明细" ? requests.data : usage.data ? [usage.data] : undefined;
  const loading = view === "请求明细" ? requests.isLoading : usage.isLoading;
  const error = view === "请求明细" ? requests.error : usage.error;
  return <div className="page-stack"><header className="page-heading"><div><p className="eyebrow mono">REQUEST / USAGE</p><h1>请求与用量</h1><p>请求时间线与聚合分析共享时间范围；partial / unknown 永远不会以 0 填充。</p></div><button className="btn btn-outline"><Icon name="download" />导出当前筛选</button></header><div className="segmented local"><button className={view === "请求明细" ? "active" : ""} onClick={() => setView("请求明细")}>请求明细</button><button className={view === "聚合分析" ? "active" : ""} onClick={() => setView("聚合分析")}>聚合分析</button></div><div className="filter-rail"><div className="field"><label htmlFor="search-request">搜索 Request ID</label><input id="search-request" className="inp" placeholder="req_…" /></div><div className="field"><label htmlFor="usage-state">Usage 完整度</label><select id="usage-state" className="inp"><option>全部</option><option>complete</option><option>partial</option><option>unknown</option></select></div><button className="btn btn-ghost">应用筛选</button></div>{error && <ErrorState error={error} />}<ResourceTable loading={loading} items={items} title={view} /></div>;
}

function ResourcePage({ entry }: { entry: NavEntry }) {
  const endpoints: Record<string, string | null> = {
    "/users":"/admin/v1/users", "/platform-keys":"/admin/v1/platform-keys", "/egress":"/admin/v1/proxies",
    "/models":"/admin/v1/models", "/governance":"/admin/v1/rulesets", "/bundles":"/admin/v1/environment-archetypes",
    "/security":"/admin/v1/approval-cases", "/alerts":"/admin/v1/alerts", "/operations":"/admin/v1/operations/jobs",
    "/exports":null, "/account":"/admin/v1/auth/sessions",
  };
  const endpoint = endpoints[entry.path] ?? null;
  const result = useQuery({ queryKey: [endpoint], queryFn: () => api<unknown[]>(endpoint ?? ""), enabled: endpoint !== null, retry: false });
  const items = endpoint === null ? [] : result.data;
  return <div className="page-stack"><header className="page-heading"><div><p className="eyebrow mono">CONTROL PLANE RESOURCE</p><h1>{entry.label}</h1><p>所有筛选、详情、聚合与导出都由服务端再次执行 Owner scope 与字段裁剪。</p></div><button className="btn btn-primary"><Icon name="plus" />创建</button></header>{result.isError && <ErrorState error={result.error} />}{endpoint === null && <div className="alert alert-warn"><Icon name="alert" /><div><div className="at">按需创建</div><div className="ad">此资源没有全量列表接口；从相应业务页面发起后按任务 ID 查看。</div></div></div>}<ResourceTable loading={result.isLoading} items={items} title={entry.label} /></div>;
}

function ResourceTable({ loading, items, title }: { loading: boolean; items?: unknown[]; title: string }) {
  const records = (items ?? []).filter((item): item is Record<string, unknown> => typeof item === "object" && item !== null);
  const columns = Array.from(new Set(records.flatMap((record) => Object.keys(record)))).slice(0, 7);
  return <section className="card table-card" aria-busy={loading}><div className="cardbar"><div className="cbl"><h2>{title}</h2><span className="tag t-gray">稳定排序</span></div><div className="cbr"><button className="ibtn outline" aria-label="刷新"><Icon name="refresh" /></button><button className="ibtn outline" aria-label="筛选"><Icon name="filter" /></button></div></div>{loading ? <div className="loading-lines"><span className="skel title" /><span className="skel line" /><span className="skel line" /></div> : records.length === 0 ? <div className="empty"><div className="empty-orbit"><Icon name="inbox" /></div><h3>这里还没有记录</h3><p>初始空态与筛选空态会分别说明；系统不会伪造演示数据。</p></div> : <div className="tbl-wrap"><table className="tbl"><caption className="sr-only">{title}，共 {records.length} 条</caption><thead><tr>{columns.map((column) => <th key={column} scope="col">{column.replaceAll("_", " ")}</th>)}</tr></thead><tbody>{records.map((record, index) => <tr key={String(record.id ?? index)}>{columns.map((column) => <td key={column} className="mono">{displayCell(record[column])}</td>)}</tr>)}</tbody></table></div>}</section>;
}

function displayCell(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value).slice(0, 120);
  return String(value);
}

function ErrorState({ error }: { error: Error }) {
  const status = error instanceof ApiError ? error.status : 0;
  return <div className="alert alert-warn" role="alert"><Icon name="alert" /><div><div className="at">局部数据加载失败</div><div className="ad">{status ? `HTTP ${status} · ` : ""}{error.message}</div></div></div>;
}
