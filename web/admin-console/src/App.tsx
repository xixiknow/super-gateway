import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Drawer } from "./drawer";
import { CopyRequestContent, RequestHeaders, RequestMetrics, requestClient, formatRequestDuration, formatRequestTime, type RequestCapture } from "./RequestContent";
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
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
import { ResourceActionButton, ResourceActionKey } from "./ResourceAction";
import { OpenAiSettings } from "./OpenAiAccounts";
import { AccountsPage } from "./AccountsPage";
import { PlatformKeysTable } from "./PlatformKeys";
import { UsersTable } from "./Users";
import { ModelsTable } from "./ModelsTable";
import { ArchetypeBundlePage } from "./ArchetypeBundles";
import { GovernancePage } from "./GovernancePage";
import { useToast } from "./feedback";
import { RowActionDef } from "./row-actions";
import { useResourceRowActions } from "./resource-actions";
import { TablePager, usePagination } from "./pagination";
import { columnLabel, displayCell } from "./display";
import { LanguageSwitch, Locale, MessageKey, useI18n } from "./i18n";
import { GalaxyTransition } from "./GalaxyTransition";
import { SelectField } from "./select-field";
import { Starfield } from "./Starfield";
import { useTheme } from "./theme";
import { CredentialsPage } from "./CredentialsPage";
import { ErrorState, ResourceTable } from "./resource-table";

type NavEntry = { path: string; labelKey: MessageKey; icon: string; adminOnly?: boolean; sectionKey: MessageKey };

const navigation: NavEntry[] = [
  { path: "/", labelKey: "nav.home", icon: "home", sectionKey: "nav.overview" },
  { path: "/users", labelKey: "nav.users", icon: "users", adminOnly: true, sectionKey: "nav.access" },
  { path: "/platform-keys", labelKey: "nav.platformKeys", icon: "key", sectionKey: "nav.access" },
  { path: "/credentials", labelKey: "nav.credentials", icon: "shield", adminOnly: true, sectionKey: "nav.access" },
  { path: "/accounts", labelKey: "nav.accounts", icon: "grid", adminOnly: true, sectionKey: "nav.access" },
  { path: "/egress", labelKey: "nav.egress", icon: "globe", adminOnly: true, sectionKey: "nav.traffic" },
  { path: "/models", labelKey: "nav.models", icon: "box", adminOnly: true, sectionKey: "nav.traffic" },
  { path: "/requests", labelKey: "nav.requests", icon: "activity", sectionKey: "nav.traffic" },
  { path: "/bundles", labelKey: "nav.bundles", icon: "package", adminOnly: true, sectionKey: "nav.traffic" },
  { path: "/governance", labelKey: "nav.governance", icon: "sliders", adminOnly: true, sectionKey: "nav.governanceSection" },
  { path: "/security", labelKey: "nav.security", icon: "lock", adminOnly: true, sectionKey: "nav.governanceSection" },
  { path: "/alerts", labelKey: "nav.alerts", icon: "bell", adminOnly: true, sectionKey: "nav.governanceSection" },
  { path: "/operations", labelKey: "nav.operations", icon: "settings", adminOnly: true, sectionKey: "nav.system" },
  { path: "/exports", labelKey: "nav.exports", icon: "download", sectionKey: "nav.system" },
  { path: "/account", labelKey: "nav.account", icon: "user", sectionKey: "nav.system" },
];

function Icon({ name }: { name: string }) {
  return <svg className="icon sm" aria-hidden="true"><use href={`#i-${name}`} /></svg>;
}

function ThemeToggle({ variant = "soft" }: { variant?: "soft" | "outline" }) {
  const { theme, toggle } = useTheme();
  const { t } = useI18n();
  const label = theme === "dark" ? t("theme.toLight") : t("theme.toDark");
  return (
    <button
      type="button"
      className={`ibtn ${variant}${theme === "dark" ? " theme-dark" : " theme-light"}`}
      aria-label={label}
      title={label}
      onClick={toggle}
    >
      <Icon name={theme === "dark" ? "sun" : "moon"} />
    </button>
  );
}

export function App() {
  const principal = useQuery({ queryKey: ["principal"], queryFn: currentPrincipal, retry: false });
  const phase = principal.isLoading
    ? "boot"
    : principal.isError || !principal.data
      ? "login"
      : principal.data.password_change_required
        ? "password-change"
        : !principal.data.mfa_verified
          ? "mfa-enroll"
          : "console";
  const screen = principal.isLoading
    ? <BootScreen />
    : principal.isError || !principal.data
      ? <LoginScreen />
      : principal.data.password_change_required
        ? <SessionSetupScreen principal={principal.data} initialStage="password-change" />
        : !principal.data.mfa_verified
          ? <SessionSetupScreen principal={principal.data} initialStage="mfa-enroll" />
          : <ConsoleShell principal={principal.data} />;
  return <>{screen}{phase === "boot" ? <GalaxyTransition hold /> : null}</>;
}

function BootScreen() {
  const { t } = useI18n();
  return <main className="boot" aria-live="polite"><div className="boot-card"><Icon name="activity" /><p className="mono">{t("boot.validating")}</p></div></main>;
}

function LoginScreen() {
  const { t } = useI18n();
  const queryClient = useQueryClient();
  const [stage, setStage] = useState<"password" | "mfa">("password");
  const [message, setMessage] = useState("");
  const signIn = useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) => login(username, password),
    onSuccess: (result) => {
      if (result.next_action === "verify_mfa") setStage("mfa");
      else void queryClient.invalidateQueries({ queryKey: ["principal"] });
    },
    onError: () => setMessage(t("auth.loginError")),
  });
  const mfa = useMutation({
    mutationFn: verifyMfa,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["principal"] }),
    onError: () => setMessage(t("auth.mfaError")),
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
      <Starfield />
      <section className="login-story" aria-label={t("auth.platformStory")}>
        <div className="login-blobs" aria-hidden="true"><span /><span /><span /></div>
        <div className="brand-mark"><span>SG</span></div>
        <p className="eyebrow mono">{t("auth.storyEyebrow")}</p>
        <h1>{t("auth.storyTitle")}<br /><em>{t("auth.storyEmphasis")}</em></h1>
        <p className="story-copy">{t("auth.storyCopy")}</p>
        <ul className="story-points">
          <li><span className="pt-ico" aria-hidden="true"><Icon name="shield" /></span><div><b>{t("auth.point1")}</b><small>{t("auth.point1Body")}</small></div></li>
          <li><span className="pt-ico" aria-hidden="true"><Icon name="activity" /></span><div><b>{t("auth.point2")}</b><small>{t("auth.point2Body")}</small></div></li>
          <li><span className="pt-ico" aria-hidden="true"><Icon name="lock" /></span><div><b>{t("auth.point3")}</b><small>{t("auth.point3Body")}</small></div></li>
        </ul>
        <div className="signal-strip"><span /><span /><span /><small>{t("auth.ready")}</small></div>
      </section>
      <section className="login-panel">
        <div className="login-topline"><ThemeToggle variant="outline" /><LanguageSwitch /></div>
        <div>
          <div className="login-card card">
            <div className="login-steps" aria-hidden="true">
              <span className={`lstep ${stage === "password" ? "on" : "done"}`}><i>{stage === "password" ? "01" : "✓"}</i>{t("auth.stepAccount")}</span>
              <span className="lsep" />
              <span className={`lstep ${stage === "mfa" ? "on" : ""}`}><i>02</i>{t("auth.stepMfa")}</span>
            </div>
            <h2>{stage === "password" ? t("auth.loginTitle") : t("auth.mfaTitle")}</h2>
            <p className="muted">{t("auth.secureEntry")}</p>
            {message && <div className="alert alert-err" role="alert"><div><div className="at">{t("auth.validationFailed")}</div><div className="ad">{message}</div></div></div>}
            {stage === "password" ? (
              <form onSubmit={submitPassword}>
                <div className="field"><label htmlFor="username">{t("auth.username")}</label><input className="inp" id="username" name="username" autoComplete="username" required /></div>
                <div className="field"><label htmlFor="password">{t("auth.password")}</label><input className="inp" id="password" name="password" type="password" autoComplete="current-password" required /></div>
                <button className="btn btn-primary btn-lg login-submit" disabled={signIn.isPending}>{signIn.isPending ? t("auth.validating") : t("auth.continue")}</button>
              </form>
            ) : (
              <form onSubmit={submitMfa}>
                <div className="field"><label htmlFor="code">{t("auth.code")}</label><input className="inp mono otp" id="code" name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required autoFocus /></div>
                <button className="btn btn-primary btn-lg login-submit" disabled={mfa.isPending}>{mfa.isPending ? t("auth.checking") : t("auth.enter")}</button>
              </form>
            )}
          </div>
          <p className="login-foot"><Icon name="shield" />{t("auth.sessionNote")}</p>
        </div>
      </section>
    </main>
  );
}

function SessionSetupScreen({ principal, initialStage }: { principal: Principal; initialStage: "password-change" | "mfa-enroll" }) {
  const { t } = useI18n();
  const queryClient = useQueryClient();
  const [stage, setStage] = useState(initialStage);
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [message, setMessage] = useState("");
  const password = useMutation({
    mutationFn: ({ current, next }: { current: string; next: string }) => changePassword(current, next),
    onSuccess: () => { setMessage(""); setStage("mfa-enroll"); void queryClient.invalidateQueries({ queryKey: ["principal"] }); },
    onError: () => setMessage(t("setup.passwordError")),
  });
  const beginEnrollment = useMutation({
    mutationFn: enrollMfa,
    onSuccess: (result) => { setMessage(""); setEnrollment(result); },
    onError: () => setMessage(t("setup.enrollError")),
  });
  const confirmation = useMutation({
    mutationFn: (code: string) => enrollment ? confirmMfa(enrollment.id, code) : Promise.reject(new Error("missing enrollment")),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["principal"] }),
    onError: () => setMessage(t("setup.confirmError")),
  });
  function submitPasswordChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const next = String(data.get("new_password"));
    if (next !== String(data.get("confirm_password"))) { setMessage(t("setup.passwordMismatch")); return; }
    password.mutate({ current: String(data.get("current_password")), next });
  }
  function submitConfirmation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    confirmation.mutate(String(new FormData(event.currentTarget).get("code")));
  }
  return (
    <main className="login-stage">
      <section className="login-story" aria-label={t("setup.storyLabel")}>
        <div className="login-blobs" aria-hidden="true"><span /><span /><span /></div>
        <div className="brand-mark"><span>SG</span></div>
        <p className="eyebrow mono">SECURITY INITIALIZATION / {principal.id.slice(0, 8)}</p>
        <h1>{t("setup.storyTitle")}<br /><em>{t("setup.storyEmphasis")}</em></h1>
        <p className="story-copy">{t("setup.storyCopy")}</p>
      </section>
      <section className="login-panel">
        <div className="login-topline"><ThemeToggle variant="outline" /><LanguageSwitch /></div>
        <div className="login-card card">
          <div className="login-steps" aria-hidden="true">
            <span className={`lstep ${stage === "password-change" ? "on" : "done"}`}><i>{stage === "password-change" ? "01" : "✓"}</i>{t("setup.stepPassword")}</span>
            <span className="lsep" />
            <span className={`lstep ${stage === "mfa-enroll" ? "on" : ""}`}><i>02</i>{t("setup.stepMfa")}</span>
          </div>
          <h2>{stage === "password-change" ? t("setup.changePassword") : t("setup.enrollMfa")}</h2>
          {message && <div className="alert alert-err" role="alert"><div><div className="at">{t("setup.notCompleted")}</div><div className="ad">{message}</div></div></div>}
          {stage === "password-change" ? (
            <form onSubmit={submitPasswordChange}>
              <div className="field"><label htmlFor="current-password">{t("setup.currentPassword")}</label><input className="inp" id="current-password" name="current_password" type="password" autoComplete="current-password" required /></div>
              <div className="field"><label htmlFor="new-password">{t("setup.newPassword")}</label><input className="inp" id="new-password" name="new_password" type="password" autoComplete="new-password" minLength={14} maxLength={128} required /></div>
              <div className="field"><label htmlFor="confirm-password">{t("setup.confirmPassword")}</label><input className="inp" id="confirm-password" name="confirm_password" type="password" autoComplete="new-password" minLength={14} maxLength={128} required /></div>
              <button className="btn btn-primary btn-lg login-submit" disabled={password.isPending}>{password.isPending ? t("common.submitting") : t("setup.saveContinue")}</button>
            </form>
          ) : enrollment ? (
            <form onSubmit={submitConfirmation}>
              <p className="muted">{t("setup.totpGuide")}</p>
              <div className="field"><label htmlFor="totp-seed">{t("setup.totpSeed")}</label><input className="inp mono" id="totp-seed" value={enrollment.secret} readOnly aria-describedby="seed-note" /></div>
              <p id="seed-note" className="muted mono">{enrollment.otpauth_uri}</p>
              <div className="field"><label htmlFor="confirm-code">{t("auth.code")}</label><input className="inp mono otp" id="confirm-code" name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required autoFocus /></div>
              <button className="btn btn-primary btn-lg login-submit" disabled={confirmation.isPending}>{confirmation.isPending ? t("setup.confirming") : t("setup.confirmEnter")}</button>
            </form>
          ) : (
            <div><p className="muted">{t("setup.generateGuide")}</p><button className="btn btn-primary btn-lg login-submit" onClick={() => beginEnrollment.mutate()} disabled={beginEnrollment.isPending}>{beginEnrollment.isPending ? t("setup.generating") : t("setup.generateSeed")}</button></div>
          )}
        </div>
      </section>
    </main>
  );
}

function ConsoleShell({ principal }: { principal: Principal }) {
  const { t } = useI18n();
  const toast = useToast();
  const location = useLocation();
  const queryClient = useQueryClient();
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [notificationDetail, setNotificationDetail] = useState<NotificationRecord | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const notificationAnchorRef = useRef<HTMLDivElement>(null);
  const navToggleRef = useRef<HTMLButtonElement>(null);
  const notifications = useQuery({ queryKey: ["notifications"], queryFn: () => api<NotificationRecord[]>("/admin/v1/notifications"), retry: false });
  const unreadCount = (notifications.data ?? []).filter((item) => !item.read_at).length;
  const allowedNavigation = useMemo(() => navigation.filter((item) => !item.adminOnly || principal.role === "platform_admin"), [principal.role]);
  const active = allowedNavigation.find((item) => item.path === location.pathname);
  const sections = useMemo(() => {
    const groups: { sectionKey: MessageKey; items: NavEntry[] }[] = [];
    for (const item of allowedNavigation) {
      const group = groups.find((candidate) => candidate.sectionKey === item.sectionKey);
      if (group) group.items.push(item);
      else groups.push({ sectionKey: item.sectionKey, items: [item] });
    }
    return groups;
  }, [allowedNavigation]);
  // ≤760px 汉堡抽屉:路由切换即收起;从窄屏跨回桌面时自动关闭
  useEffect(() => {
    setNavOpen(false);
  }, [location.pathname]);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(max-width: 760px)");
    const sync = (event: MediaQueryListEvent) => {
      if (!event.matches) setNavOpen(false);
    };
    query.addEventListener?.("change", sync);
    return () => query.removeEventListener?.("change", sync);
  }, []);
  useEffect(() => {
    if (!notificationsOpen && !notificationDetail) return;
    // Esc 优先关闭详情对话框，其次关闭通知浮层
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      if (notificationDetail) setNotificationDetail(null);
      else setNotificationsOpen(false);
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [notificationsOpen, notificationDetail]);
  useEffect(() => {
    if (!notificationsOpen) return;
    // 点击浮层与铃铛之外的区域关闭通知；详情对话框打开时不干预
    const closeOnOutside = (event: MouseEvent) => {
      if (notificationDetail) return;
      if (notificationAnchorRef.current?.contains(event.target as Node)) return;
      setNotificationsOpen(false);
    };
    document.addEventListener("mousedown", closeOnOutside);
    return () => document.removeEventListener("mousedown", closeOnOutside);
  }, [notificationsOpen, notificationDetail]);
  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen(true);
      }
    };
    document.addEventListener("keydown", handleShortcut);
    return () => document.removeEventListener("keydown", handleShortcut);
  }, []);
  // 桌面侧栏与 ≤760px 汉堡抽屉共用同一份导航内容
  const navBody = (
    <>
      <div className="brand"><div className="brand-mark small"><span>SG</span></div><div><b>SUPER GATEWAY</b><small>CONTROL TOWER</small></div></div>
      <nav aria-label={t("shell.mainNav")}>
        {sections.map((group) => <div key={group.sectionKey} role="group" aria-label={t(group.sectionKey)}><div className="nav-label">{t(group.sectionKey)}</div>{group.items.map((entry) => <NavLink key={entry.path} to={entry.path} end={entry.path === "/"} className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}><Icon name={entry.icon} /><span>{t(entry.labelKey)}</span></NavLink>)}</div>)}
      </nav>
      <div className="sidebar-foot"><span className="live-dot" />{t("shell.status")}</div>
    </>
  );
  return (
    <div className="console-shell">
      <a className="skip-link" href="#main-content">{t("shell.skip")}</a>
      <aside className="sidebar">{navBody}</aside>
      {navOpen && (
        <Drawer title={t("shell.controlTower")} onRequestClose={() => setNavOpen(false)}>
          <div className="sidebar in-drawer">{navBody}</div>
        </Drawer>
      )}
      <div className="workspace">
        <header className="topbar">
          <div className="topbar-lead">
            <button ref={navToggleRef} className="ibtn nav-toggle" type="button" aria-label={t("shell.menu")} aria-expanded={navOpen} onClick={() => setNavOpen(true)}><Icon name="menu" /></button>
            <p className="crumb"><span className="crumb-prefix">{t("shell.controlTower")} / </span><strong>{active ? t(active.labelKey) : t("shell.controlTower")}</strong><span className="crumb-suffix"> · {active?.path === "/requests" ? "UTC+8" : "UTC"}</span></p>
          </div>
          <div className="top-actions">
            <LanguageSwitch compact />
            <ThemeToggle />
            <button className="search-pill" type="button" aria-label={t("shell.search")} onClick={() => setSearchOpen(true)}><Icon name="search" /><span>{t("shell.searchPlaceholder")}</span><kbd>⌘K</kbd></button>
            <div className="notification-anchor" ref={notificationAnchorRef}>
              <button className={`ibtn soft ${notificationsOpen ? "on" : ""}`} type="button" aria-label={t("shell.alertCenter")} aria-expanded={notificationsOpen} aria-controls="notification-popover" onClick={() => setNotificationsOpen((open) => !open)}><Icon name="bell" />{unreadCount > 0 && <i className="ib-dot" />}</button>
              {notificationsOpen && <NotificationPopover result={notifications} unreadCount={unreadCount} onClose={() => setNotificationsOpen(false)} onOpenDetail={setNotificationDetail} />}
            </div>
            <div className="user-chip"><span className="avatar teal">{principal.role === "platform_admin" ? "A" : "O"}</span><div><b>{principal.role === "platform_admin" ? t("shell.platformAdmin") : t("shell.keyOwner")}</b><small className="mono">{principal.id.slice(0, 8)}</small></div></div>
            <button className="tbtn" onClick={() => void logout().then(() => queryClient.clear()).catch(() => toast.error(t("common.requestFailed")))}>{t("shell.logout")}</button>
          </div>
        </header>
        <main id="main-content" className="main-content" tabIndex={-1}>
          <Routes>
            <Route index element={<Dashboard principal={principal} />} />
            {/* 凭据分组已并入凭据页:旧 /groups 路由重定向 */}
            <Route path="groups" element={<Navigate to="/credentials" replace />} />
            <Route path="credentials" element={<CredentialsPage principal={principal} />} />
            <Route path="accounts" element={<AccountsPage principal={principal} />} />
            <Route path="requests" element={<RequestUsagePage />} />
            <Route path="exports" element={<ExportsPage />} />
            <Route path="bundles" element={<ArchetypeBundlePage />} />
            <Route path="governance" element={<GovernancePage />} />
            {allowedNavigation.filter((entry) => !["/", "/credentials", "/accounts", "/requests", "/exports", "/bundles", "/governance"].includes(entry.path)).map((entry) => <Route key={entry.path} path={entry.path.slice(1)} element={<ResourcePage entry={entry} principal={principal} />} />)}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
      {searchOpen && <SearchPalette entries={allowedNavigation} onClose={() => setSearchOpen(false)} />}
      {notificationDetail && <NotificationDetailDialog item={notificationDetail} onClose={() => setNotificationDetail(null)} />}
    </div>
  );
}

function SearchPalette({ entries, onClose }: { entries: NavEntry[]; onClose(): void }) {
  const { locale, t } = useI18n();
  const [query, setQuery] = useState("");
  const matches = entries.filter((entry) => {
    const needle = query.trim().toLocaleLowerCase(locale);
    return !needle || `${t(entry.labelKey)} ${t(entry.sectionKey)}`.toLocaleLowerCase(locale).includes(needle);
  });
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  return <div className="overlay show search-overlay" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="search-palette" role="dialog" aria-modal="true" aria-label={t("search.title")}><div className="search-input"><Icon name="search" /><input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("search.placeholder")} aria-label={t("search.input")} /><kbd>ESC</kbd></div><div className="search-results">{matches.length === 0 ? <p>{t("search.empty")}</p> : matches.map((entry) => <NavLink key={entry.path} to={entry.path} onClick={onClose}><Icon name={entry.icon} /><span><b>{t(entry.labelKey)}</b><small>{t(entry.sectionKey)}</small></span><span aria-hidden="true">→</span></NavLink>)}</div></section></div>;
}

interface NotificationRecord {
  id: string;
  alert_id: string | null;
  severity: "info" | "warning" | "critical";
  title: string;
  summary: string;
  read_at: string | null;
  created_at: string;
}

function NotificationPopover({ result, unreadCount, onClose, onOpenDetail }: { result: UseQueryResult<NotificationRecord[], Error>; unreadCount: number; onClose: () => void; onOpenDetail: (item: NotificationRecord) => void }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const items = result.data ?? [];
  const markRead = useMutation({
    mutationFn: (item: NotificationRecord) => api<NotificationRecord>(`/admin/v1/notifications/${encodeURIComponent(item.id)}:read`, { method: "POST", headers: { "If-Match": '"rev-1"' }, body: "{}" }),
    onSuccess: (updated) => {
      queryClient.setQueryData<NotificationRecord[]>(["notifications"], (current) => current?.map((item) => item.id === updated.id ? updated : item));
    },
    onError: () => toast.error(t("notifications.markReadFailed")),
  });
  const markAllRead = useMutation({
    mutationFn: () => api<{ updated_count: number }>("/admin/v1/notifications:read-all", { method: "POST", body: "{}" }),
    onSuccess: () => {
      const readAt = new Date().toISOString();
      queryClient.setQueryData<NotificationRecord[]>(["notifications"], (current) => current?.map((item) => item.read_at ? item : { ...item, read_at: readAt }));
    },
    onError: () => toast.error(t("notifications.markAllFailed")),
  });
  function openItem(item: NotificationRecord) {
    onOpenDetail(item);
    if (!item.read_at && !(markRead.isPending && markRead.variables?.id === item.id)) markRead.mutate(item);
  }
  return <section id="notification-popover" className="notification-popover" role="dialog" aria-labelledby="notification-title">
    <div className="notification-head"><div><p className="eyebrow mono">INBOX</p><h2 id="notification-title">{t("notifications.title")}</h2><small>{unreadCount > 0 ? t("notifications.unreadCount", { count: unreadCount }) : t("notifications.allRead")}</small></div><div className="notification-head-actions">{unreadCount > 0 && <button type="button" className="tbtn" disabled={markAllRead.isPending || markRead.isPending} onClick={() => markAllRead.mutate()}><Icon name="check" />{markAllRead.isPending ? t("notifications.markingAll") : t("notifications.markAll")}</button>}<button type="button" className="ibtn outline sm" aria-label={t("common.close")} onClick={onClose}>×</button></div></div>
    {result.isLoading ? <div className="notification-state"><span className="skel title" /><span className="skel line" /><span className="skel line" /></div>
      : result.isError ? <div className="notification-state"><Icon name="alert" /><b>{t("notifications.loadFailed")}</b><button type="button" className="tbtn" onClick={() => void result.refetch()}>{t("common.retry")}</button></div>
        : items.length === 0 ? <div className="notification-state"><span className="notification-empty-icon"><Icon name="bell" /></span><b>{t("notifications.emptyTitle")}</b><p>{t("notifications.emptyBody")}</p></div>
          : <><p className="notification-hint">{t("notifications.expandHint")}</p><ul className="notification-list">{items.slice(0, 8).map((item) => {
            const marking = markRead.isPending && markRead.variables?.id === item.id;
            const read = Boolean(item.read_at);
            const statusClass = marking ? "marking" : read ? "read" : "unread";
            return <li key={item.id} className={read ? "read" : "unread"}><button type="button" className="notification-row" disabled={markAllRead.isPending} onClick={() => openItem(item)}><span className={`notification-severity ${item.severity}`} aria-hidden="true" /><span className="notification-content"><span className="notification-item-head"><b>{item.title}</b><span className={`notification-status ${statusClass}`}>{marking ? t("notifications.marking") : !read ? t("notifications.unread") : t("notifications.read")}</span></span><span className="notification-preview">{item.summary}</span><time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString(locale)}</time></span><span className="notification-chevron" aria-hidden="true">→</span></button></li>;
          })}</ul></>}
  </section>;
}

function NotificationDetailDialog({ item, onClose }: { item: NotificationRecord; onClose(): void }) {
  const { locale, t } = useI18n();
  return (
    <div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section className="modal notification-detail-modal" role="dialog" aria-modal="true" aria-labelledby="notification-detail-title">
        <div className="modal-head"><div><p className="eyebrow mono">{t("notifications.details")}</p><h3 id="notification-detail-title">{item.title}</h3></div><button type="button" className="ibtn outline" aria-label={t("common.close")} onClick={onClose}>×</button></div>
        <div className="modal-body">
          <p className="notification-detail-summary">{item.summary}</p>
          <dl className="notification-detail-grid">
            <div><dt>{t("notifications.severity")}</dt><dd><span className={`notification-severity ${item.severity}`} aria-hidden="true" />{t(`notifications.severity.${item.severity}`)}</dd></div>
            <div><dt>{t("notifications.occurredAt")}</dt><dd><time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString(locale)}</time></dd></div>
            {item.alert_id && <div><dt>{t("notifications.relatedAlert")}</dt><dd className="mono">{item.alert_id}</dd></div>}
          </dl>
        </div>
      </section>
    </div>
  );
}

function Dashboard({ principal }: { principal: Principal }) {
  const { t } = useI18n();
  const status = useQuery({ queryKey: ["system-status"], queryFn: () => api<Record<string, unknown>>("/admin/v1/system/status"), enabled: principal.role === "platform_admin" });
  const metrics = status.data?.metrics && typeof status.data.metrics === "object" ? status.data.metrics as Record<string, unknown> : {};
  const count = (key: string) => typeof metrics[key] === "number" ? metrics[key] as number : 0;
  const activeRequests = Math.max(0, count("accepted") - count("completed") - count("client_disconnected") - count("client_write_timeout") - count("upstream_body_error"));
  const streaming = Math.max(0, count("response_committed") - count("completed") - count("client_disconnected") - count("client_write_timeout"));
  const anomalies = count("client_write_timeout") + count("upstream_body_error");
  const readiness = status.data?.readiness && typeof status.data.readiness === "object" ? status.data.readiness as Record<string, unknown> : {};
  const healthy = !status.isError && Object.values(readiness).filter((value) => typeof value === "boolean").every(Boolean);
  const metricValue = (value: number) => status.isLoading || status.isError ? "—" : value.toLocaleString();
  return (
    <div className="page-stack">
      <header className="page-heading"><div><p className="eyebrow mono">LIVE OPERATIONS · UTC</p><h1>{t("dashboard.title")}</h1></div><span className={`tag ${healthy ? "t-teal" : "t-amber"} dotled`}>{healthy ? t("dashboard.healthy") : t("dashboard.degraded")}</span></header>
      {status.isError && <div className="alert alert-warn"><Icon name="alert" /><div><div className="at">{t("dashboard.statusErrorTitle")}</div><div className="ad">{t("dashboard.statusErrorBody")}</div></div></div>}
      <section className="metric-grid" aria-label={t("dashboard.metrics")}><Metric label={t("dashboard.currentRequests")} value={metricValue(activeRequests)} note={t("dashboard.resourceAxis")} tone="teal" /><Metric label={t("dashboard.streaming")} value={metricValue(streaming)} note="SSE delivery" tone="sky" /><Metric label={t("dashboard.completed")} value={metricValue(count("completed"))} note={t("dashboard.deliveredBytes", { value: count("delivered_bytes").toLocaleString() })} tone="amber" /><Metric label={t("dashboard.anomalies")} value={metricValue(anomalies)} note={t("dashboard.adminReview")} tone="coral" /></section>
      <section className="split-grid">
        <div className="card pad signal-card"><div className="section-head"><div><p className="eyebrow">{t("dashboard.callChain")}</p><h2>{t("dashboard.entryUpstream")}</h2></div><span className="tag t-teal dotled">{t("dashboard.transparent")}</span></div><div className="pipeline"><span>CLIENT</span><i /><span>EDGE</span><i /><span>EXECUTOR</span><i /><span>TRANSPORT</span><i /><span>ANTHROPIC</span></div><div className="timeline compact"><div className="tl-item ok"><b>{t("dashboard.headerBoundary")}</b><p>{t("dashboard.headerBoundaryBody")}</p></div><div className="tl-item ok"><b>{t("dashboard.rawPass")}</b><p>{t("dashboard.rawPassBody")}</p></div><div className="tl-item warn"><b>{t("dashboard.externalEvidence")}</b><p>{t("dashboard.externalEvidenceBody")}</p></div></div></div>
        <div className="card pad"><div className="section-head"><div><p className="eyebrow">{t("dashboard.attention")}</p><h2>{t("dashboard.runtimeTips")}</h2></div><NavLink className="tbtn" to="/operations">{t("dashboard.viewAll")}</NavLink></div><ul className="attention-list"><li><span className="tag t-amber">EVIDENCE</span><div><b>{t("dashboard.transportGate")}</b><small>{t("dashboard.transportGateBody")}</small></div><time>{t("dashboard.continuous")}</time></li><li><span className="tag t-sky">PLAN</span><div><b>{t("dashboard.planDisplay")}</b><small>{t("dashboard.planDisplayBody")}</small></div><time>{t("dashboard.rule")}</time></li></ul></div>
      </section>
    </div>
  );
}

function Metric({ label, value, note, tone }: { label: string; value: string; note: string; tone: string }) {
  return <article className={`scard metric ${tone}`}><div className="sh"><span>{label}</span><span className={`signal ${tone}`} /></div><div className="sn">{value}</div><div className="sm">{note}</div></article>;
}

interface TimeseriesBucket extends Record<string, unknown> {
  bucket_start: string;
  request_count: number;
  input_tokens: number | null;
  output_tokens: number | null;
  estimated_amount: string | null;
  completeness: string;
}

function formatCount(value: unknown, locale: Locale): string {
  return typeof value === "number" ? value.toLocaleString(locale) : "—";
}

function formatAmount(value: unknown): string {
  return typeof value === "string" && value ? `$${Number(value).toFixed(2)}` : "—";
}

function UsageChart({ points }: { points: TimeseriesBucket[] }) {
  const { t } = useI18n();
  const width = 720;
  const height = 190;
  const padX = 8;
  const padTop = 18;
  const padBottom = 26;
  const max = Math.max(1, ...points.map((point) => point.request_count));
  const innerHeight = height - padTop - padBottom;
  const barWidth = (width - padX * 2) / Math.max(1, points.length);
  return (
    <svg className="usage-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={t("usage.chartLabel")}>
      <text x={padX} y={12}>{max.toLocaleString()}</text>
      {points.map((point, index) => {
        const barHeight = Math.max(2, Math.round((innerHeight * point.request_count) / max));
        return (
          <rect key={point.bucket_start} x={padX + index * barWidth + 1} y={height - padBottom - barHeight} width={Math.max(2, barWidth - 2)} height={barHeight} rx={2} className={`usage-bar ${point.completeness}`}>
            <title>{`${point.bucket_start.slice(0, 10)} · ${point.request_count.toLocaleString()}`}</title>
          </rect>
        );
      })}
      {points.length > 0 && <>
        <text x={padX} y={height - 8}>{points[0].bucket_start.slice(0, 10)}</text>
        <text x={width - padX} y={height - 8} textAnchor="end">{points[points.length - 1].bucket_start.slice(0, 10)}</text>
      </>}
    </svg>
  );
}

interface RequestRecord extends Record<string, unknown> {
  id: string;
  platform_key_name: string | null;
  group_name: string | null;
  model: string | null;
  reasoning_effort: string | null;
  client_class: string;
  client_name: string | null;
  client_version: string | null;
  request_type: "streaming" | "sync" | "websocket" | null;
  first_content_ms: number | null;
  duration_ms: number | null;
  tps: number | null;
  tps_estimated: boolean;
  input_tokens: number | null;
  output_tokens: number | null;
  cache_read_input_tokens: number | null;
  cache_creation_input_tokens: number | null;
}

const requestColumns = ["created_at", "platform_key_name", "group_name", "model", "reasoning_effort", "client_class", "request_type", "token_usage", "request_timing", "usage_completeness"];
const requestDetailColumns = [...requestColumns.filter((key) => key !== "token_usage" && key !== "request_timing"), "input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "endpoint", "http_status", "first_content_ms", "duration_ms", "tps", "phase", "outcome", "completed_at"];

function requestCell(key: string, value: unknown, locale: Locale, record: Record<string, unknown> = {}): string {
  if (key === "client_class") return requestClient(record, locale);
  if (value == null) return "—";
  if (["created_at", "completed_at"].includes(key)) return formatRequestTime(value);
  if (["platform_key_name", "group_name", "model", "reasoning_effort"].includes(key)) return String(value);
  if (key === "first_content_ms" || key === "duration_ms") return formatRequestDuration(value);
  if (key === "tps" && typeof value === "number") return `${value.toFixed(1)} token/s`;
  if (key === "request_type") return ({ streaming: locale === "zh-CN" ? "\u6d41\u5f0f" : "Streaming", sync: locale === "zh-CN" ? "\u540c\u6b65" : "Synchronous", websocket: "WebSocket" } as Record<string, string>)[String(value)] ?? String(value);
  return displayCell(value, locale);
}

interface AttemptMessages {
  ordinal: number | null;
  reason: string | null;
  state: string | null;
  http_status: number | null;
  retry_decision: string | null;
}

interface AttemptRecord extends Record<string, unknown> {
  id: string;
  ordinal: number;
  state: string;
  intent_state: string;
  retry_safe: boolean;
  started_at: string;
  completed_at: string | null;
  messages_attempt: AttemptMessages | null;
}

function formatRequestBody(value: unknown): string {
  if (value === undefined || value === null) return "—";
  if (typeof value === "string") return value;
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}

function RequestDetailDrawer({ requestId, onClose }: { requestId: string; onClose(): void }) {
  const { locale, t } = useI18n();
  const [bodyTab, setBodyTab] = useState<"original_request" | "policy_request" | "final_upstream_request" | "upstream_response" | "upstream_response_final">("original_request");
  const detailEndpoint = `/admin/v1/requests/${encodeURIComponent(requestId)}`;
  const detail = useQuery({ queryKey: [detailEndpoint], queryFn: () => api<Record<string, unknown>>(detailEndpoint), retry: false });
  const attempts = useQuery({ queryKey: [`${detailEndpoint}/attempts`], queryFn: () => api<AttemptRecord[]>(`${detailEndpoint}/attempts`), retry: false });
  const body = useQuery({ queryKey: [`${detailEndpoint}/body`], queryFn: () => api<RequestCapture>(`${detailEndpoint}/body`), retry: false });
  const [previewOpen, setPreviewOpen] = useState(false);
  const preview = useQuery({ queryKey: [`${detailEndpoint}/preview`], queryFn: () => api<Record<string, unknown>>(`${detailEndpoint}/preview`), enabled: previewOpen, retry: false });
  const record = detail.data ?? {};
  const fields = requestDetailColumns.map((key) => [key, record[key]] as const);
  const rows = (attempts.data ?? []).filter((item): item is AttemptRecord => typeof item === "object" && item !== null);
  return <Drawer eyebrow="REQUEST / TIMELINE" title={t("request.detailTitle")} subtitle={requestId}
    className="request-detail-drawer" onRequestClose={onClose}
    foot={<button type="button" className="btn btn-ghost" onClick={onClose}>{t("common.close")}</button>}>
          {detail.isLoading ? <div className="loading-lines"><span className="skel line" /><span className="skel line" /></div>
            : detail.isError ? <div className="alert alert-warn" role="alert"><Icon name="alert" /><div><div className="at">{t("error.loadTitle")}</div></div></div>
              : <dl className="key-data-grid">{fields.map(([key, value]) => <div key={key}><dt>{columnLabel(key, locale)}</dt><dd className="mono breakable">{requestCell(key, value, locale, record)}</dd></div>)}</dl>}
          <section className="request-body-panel">
            <div className="section-head"><div><p className="eyebrow mono">REQUEST / BODY</p><h4>{t("request.bodyTitle")}</h4></div><div className="section-actions"><CopyRequestContent text={body.data?.[bodyTab] == null ? null : formatRequestBody(body.data[bodyTab])} label={t(`request.body.${bodyTab}`)} />{body.data?.body_digest_mismatch === true && <span className="tag t-amber">{t("request.bodyMismatch")}</span>}<button type="button" className="btn btn-ghost" onClick={() => setPreviewOpen((value) => !value)}>{previewOpen ? t("request.preview.hide") : t("request.preview.open")}</button></div></div>
            <div className="segmented local request-body-tabs">
              {(["original_request", "policy_request", "final_upstream_request", "upstream_response", "upstream_response_final"] as const).map((tab) => <button key={tab} type="button" className={bodyTab === tab ? "active" : ""} onClick={() => setBodyTab(tab)}>{t(`request.body.${tab}` as MessageKey)}</button>)}
            </div>
            {body.isLoading ? <div className="loading-lines"><span className="skel line" /></div> : body.isError ? (body.error instanceof ApiError && body.error.status === 404
              ? <p className="muted">{t("request.bodyUnavailable")}</p> : <ErrorState error={body.error} />)
              : body.data?.capture_status === "unavailable" ? <div className="request-body-empty">
                <p>{t("request.bodyUnavailable")}</p>
                <p className="muted">{t(body.data.capture_enabled === false ? "request.captureDisabled" : "request.captureEnabled")}</p>
                <p className="muted">{t("request.captureLimits", { days: Number(body.data.retention_days), bytes: Number(body.data.max_bytes).toLocaleString(locale) })}</p>
              </div> : body.data?.[bodyTab] == null ? <p className="muted">{t("request.bodyStageUnavailable")}</p>
                : <pre className="request-body-content">{formatRequestBody(body.data?.[bodyTab])}</pre>}
            {previewOpen && <section className="request-preview-panel"><div className="section-head"><div><p className="eyebrow mono">REQUEST / PREVIEW</p><h4>{t("request.preview.title")}</h4></div><div className="section-actions"><span className="tag t-amber">{t("request.preview.simulated")}</span><CopyRequestContent text={preview.data?.preview_status === "available" ? formatRequestBody(preview.data) : null} label={t("request.preview.title")} /></div></div>{preview.isLoading ? <div className="loading-lines"><span className="skel line" /></div> : preview.isError ? <ErrorState error={preview.error} /> : preview.data?.preview_status === "missing_capture" ? <p className="muted">{t("request.preview.unavailable")}</p> : <><p className="muted">{t("request.previewScope")}</p><pre className="request-body-content">{formatRequestBody(preview.data)}</pre></>}</section>}
          </section>
          <RequestHeaders capture={body.data} loading={body.isLoading} failed={body.isError} />
          <h4 className="request-timeline-heading">{t("request.timeline")}</h4>
          {attempts.isLoading ? <div className="loading-lines"><span className="skel line" /><span className="skel line" /></div>
            : attempts.isError ? <div className="alert alert-warn" role="alert"><Icon name="alert" /><div><div className="at">{t("error.loadTitle")}</div></div></div>
              : rows.length === 0 ? <p className="muted">{t("request.noAttempts")}</p>
                : <div className="timeline">{rows.map((item) => {
                  const messages = item.messages_attempt;
                  const success = messages?.state === "succeeded" || item.state === "succeeded";
                  const failed = messages?.state === "failed" || item.state === "failed";
                  return <div key={item.id} className={`tl-item ${success ? "ok" : failed ? "err" : "warn"}`}>
                    <div className="tl-time mono">{formatRequestTime(item.started_at)}</div>
                    <div className="tl-title">{t("request.connectionAttempt")} #{item.ordinal} · {displayCell(item.state, locale)}{messages?.http_status ? ` · HTTP ${messages.http_status}` : ""}</div>
                    <div className="tl-desc">{displayCell(item.intent_state, locale)}{messages ? ` · ${t("request.messagesAttempt")} ${displayCell(messages.state, locale)}${messages.retry_decision ? ` · ${displayCell(messages.retry_decision, locale)}` : ""}` : ""}</div>
                  </div>;
                })}</div>}
  </Drawer>;
}

function RequestUsagePage() {
  const { locale, t } = useI18n();
  const [view, setView] = useState<"requests" | "analytics">("requests");
  const [requestQuery, setRequestQuery] = useState("");
  const [completeness, setCompleteness] = useState("");
  const [appliedFilters, setAppliedFilters] = useState({ query: "", completeness: "" });
  const [detailId, setDetailId] = useState<string | null>(null);
  const requests = useQuery({ queryKey: ["requests"], queryFn: () => api<RequestRecord[]>("/admin/v1/requests"), enabled: view === "requests" });
  const usage = useQuery({ queryKey: ["usage-summary"], queryFn: () => api<Record<string, unknown>>("/admin/v1/usage/summary"), enabled: view === "analytics" });
  const timeseries = useQuery({ queryKey: ["/admin/v1/usage/timeseries"], queryFn: () => api<TimeseriesBucket[]>("/admin/v1/usage/timeseries"), enabled: view === "analytics" });
  const filteredRequests = (requests.data ?? [])
    .filter((record) => {
      const id = String(record.request_id ?? record.id ?? "").toLocaleLowerCase();
      const state = String(record.completeness ?? record.usage_completeness ?? "");
      return (!appliedFilters.query || id.includes(appliedFilters.query.toLocaleLowerCase()))
        && (!appliedFilters.completeness || state === appliedFilters.completeness);
    })
    .map((record) => ({ ...Object.fromEntries(requestColumns.map((key) => [key, null])), ...record, token_usage: true, id: String(record.request_id ?? record.id ?? "") }));
  const requestRowActions: RowActionDef<Record<string, unknown>>[] = [
    { key: "detail", labelKey: "request.viewDetail", icon: "activity", primary: true, requiresRevision: false, custom: (row) => setDetailId(String(row.id)) },
  ];
  // 时序桶为倒序返回,图表按时间正序绘制
  const chartPoints = [...(timeseries.data ?? [])].reverse();
  return <div className="page-stack">
    <header className="page-heading"><div><p className="eyebrow mono">{t("request.eyebrow")}</p><h1>{t("nav.requests")}</h1><p>{t("request.description")}</p></div></header>
    <div className="segmented local"><button type="button" className={view === "requests" ? "active" : ""} onClick={() => setView("requests")}>{t("request.detail")}</button><button type="button" className={view === "analytics" ? "active" : ""} onClick={() => setView("analytics")}>{t("request.analytics")}</button></div>
    {view === "requests" && <>
      <form className="filter-rail" onSubmit={(event) => { event.preventDefault(); setAppliedFilters({ query: requestQuery.trim(), completeness }); }}><div className="field"><label htmlFor="search-request">{t("request.searchId")}</label><input id="search-request" className="inp" value={requestQuery} onChange={(event) => setRequestQuery(event.target.value)} placeholder={t("request.searchPlaceholder")} /></div><div className="field"><label htmlFor="usage-state">{t("request.completeness")}</label><SelectField id="usage-state" value={completeness} onChange={setCompleteness} options={[{ value: "", label: t("request.all") }, { value: "complete", label: t("request.complete") }, { value: "partial", label: t("request.partial") }, { value: "unknown", label: t("request.unknown") }]} /></div><button type="submit" className="btn btn-ghost">{t("request.apply")}</button></form>
      {requests.error && <ErrorState error={requests.error} />}
      <ResourceTable tableClassName="requests-table" loading={requests.isLoading} items={filteredRequests} title={t("request.detail")} columnKeys={requestColumns} renderCell={(column, record) => column === "token_usage"
        ? <dl className="request-token-grid">{([ ["input_tokens", "read"], ["output_tokens", "write"], ["cache_read_input_tokens", "cacheRead"], ["cache_creation_input_tokens", "cacheWrite"] ] as const).map(([key, label]) => <div key={key}><dt>{t(`request.tokens.${label}`)}</dt><dd>{typeof record[key] === "number" ? record[key].toLocaleString(locale) : "—"}</dd></div>)}</dl>
        : column === "request_timing" ? <RequestMetrics record={record} /> : requestCell(column, record[column], locale, record)} rowActions={requestRowActions} onRefresh={() => void requests.refetch()} refreshing={requests.isFetching} toolbar={<ResourceActionButton action="export" iconOnly />} />
    </>}
    {view === "analytics" && <>
      {(usage.error ?? timeseries.error) && <ErrorState error={(usage.error ?? timeseries.error) as Error} />}
      <section className="metric-grid" aria-label={t("request.analytics")}>
        <Metric label={t("usage.summary.requests")} value={formatCount(usage.data?.request_count, locale)} note={t("usage.summary.note")} tone="teal" />
        <Metric label={t("usage.summary.inputTokens")} value={formatCount(usage.data?.input_tokens, locale)} note="TOKENS" tone="sky" />
        <Metric label={t("usage.summary.outputTokens")} value={formatCount(usage.data?.output_tokens, locale)} note="TOKENS" tone="amber" />
        <Metric label={t("usage.summary.amount")} value={formatAmount(usage.data?.estimated_amount)} note={displayCell(usage.data?.completeness, locale)} tone="coral" />
      </section>
      {chartPoints.length > 0 && <section className="card pad usage-chart-card"><div className="section-head"><div><p className="eyebrow mono">USAGE / DAILY</p><h2>{t("usage.chartTitle")}</h2></div><span className="tag t-gray">{t("usage.chartWindow", { count: chartPoints.length })}</span></div><UsageChart points={chartPoints} /></section>}
      <ResourceTable loading={timeseries.isLoading} items={timeseries.data} title={t("usage.chartTitle")} columnKeys={["bucket_start", "request_count", "input_tokens", "output_tokens", "estimated_amount", "completeness"]} onRefresh={() => { void usage.refetch(); void timeseries.refetch(); }} refreshing={usage.isFetching || timeseries.isFetching} toolbar={<ResourceActionButton action="export" iconOnly />} />
    </>}
    {detailId && <RequestDetailDrawer requestId={detailId} onClose={() => setDetailId(null)} />}
  </div>;
}

const endpoints: Record<string, string | null> = {
  "/users":"/admin/v1/users", "/platform-keys":"/admin/v1/platform-keys", "/egress":"/admin/v1/proxies",
  "/models":"/admin/v1/models",
  "/security":"/admin/v1/approval-cases", "/alerts":"/admin/v1/alerts", "/operations":"/admin/v1/operations/jobs", "/account":"/admin/v1/auth/sessions",
};
const actions: Partial<Record<string, ResourceActionKey>> = {
  "/users":"user", "/platform-keys":"platform-key", "/egress":"proxy", "/models":"model-refresh",
  "/security":"approval", "/alerts":"alert-silence", "/operations":"upgrade-check",
};
// 页面列宽有限时的推荐列:优先人类可读字段,省略内部键与冗余状态列;为 null 的列回退到对象键顺序
const recommendedColumns: Record<string, string[]> = {
  "/users": ["username", "display_name", "status", "created_at"],
  "/egress": ["name", "hostname", "base_url", "lifecycle", "updated_at"],
  "/models": ["upstream_model_id", "display_name", "source", "lifecycle", "capability_version", "capability_state", "last_seen_at"],
  "/security": ["requested_by", "kind", "state", "created_at"],
  "/alerts": ["severity", "type", "state", "summary", "created_at"],
  "/operations": ["kind", "state", "created_at"],
  "/account": ["user_agent_summary", "created_at"],
};
function ResourcePage({ entry, principal }: { entry: NavEntry; principal: Principal }) {
  const { t } = useI18n();
  const endpoint = endpoints[entry.path] ?? null;
  const action = actions[entry.path];
  const result = useQuery({ queryKey: [endpoint], queryFn: () => api<unknown[]>(endpoint ?? ""), enabled: endpoint !== null, retry: false });
  const items = endpoint === null ? [] : result.data;
  const title = t(entry.labelKey);
  const { rowActions, rowDialogs } = useResourceRowActions(entry.path, principal);
  const toolbar = action
    ? <ResourceActionButton action={action} iconOnly={entry.path !== "/models"} className="btn btn-outline btn-sm" />
    : undefined;
  const table = entry.path === "/platform-keys"
    ? <PlatformKeysTable loading={result.isLoading} items={items} title={title} principalRole={principal.role} onRefresh={() => void result.refetch()} refreshing={result.isFetching} toolbar={toolbar} />
    : entry.path === "/users"
      ? <UsersTable loading={result.isLoading} items={items} title={title} rowActions={rowActions} onRefresh={() => void result.refetch()} refreshing={result.isFetching} toolbar={toolbar} />
      : entry.path === "/models"
        ? <ModelsTable loading={result.isLoading} items={items} title={title} rowActions={rowActions} onRefresh={() => void result.refetch()} refreshing={result.isFetching} toolbar={toolbar} />
        : <ResourceTable loading={result.isLoading} items={items} title={title} rowActions={rowActions} columnKeys={recommendedColumns[entry.path]} onRefresh={() => void result.refetch()} refreshing={result.isFetching} toolbar={toolbar} />;
  return <div className="page-stack"><header className="page-heading"><div><p className="eyebrow mono">{t("resource.eyebrow")}</p><h1>{title}</h1><p>{t("resource.description")}</p></div></header>{result.isError && <ErrorState error={result.error} />}{entry.path === "/operations" && <><OpenAiSettings /><BodyCaptureSettingsPanel /><RuntimeSettingsPanel /></>}{endpoint === null && <div className="alert alert-warn"><Icon name="alert" /><div><div className="at">{t("resource.onDemand")}</div><div className="ad">{t("resource.onDemandBody")}</div></div></div>}{table}{rowDialogs}</div>;
}

function BodyCaptureSettingsPanel() {
  const { t } = useI18n();
  const query = useQuery({ queryKey: ["body-capture-settings"], queryFn: () => api<Record<string, unknown>>("/admin/v1/settings/body-capture"), retry: false });
  const mutation = useMutation({ mutationFn: (value: { enabled: boolean; retention_days: number; max_bytes: number }) => api("/admin/v1/settings/body-capture", { method: "PUT", body: JSON.stringify(value) }), onSuccess: () => void query.refetch() });
  const value = query.data ?? {};
  return <section className="card pad body-capture-settings"><div className="section-head"><div><p className="eyebrow mono">SYSTEM / BODY</p><h2>{t("settings.bodyCapture.title")}</h2><p>{t("settings.bodyCapture.description")}</p></div></div>{query.isLoading ? <p className="muted">{t("common.loading")}</p> : query.isError ? <p className="muted">{t("common.requestFailed")}</p> : query.isSuccess ? <form key={query.dataUpdatedAt} className="settings-grid" onSubmit={(event) => { event.preventDefault(); const data = new FormData(event.currentTarget); mutation.mutate({ enabled: data.get("enabled") === "on", retention_days: Number(data.get("retention_days")), max_bytes: Number(data.get("max_bytes")) }); }}><label className="check-row"><input type="checkbox" name="enabled" defaultChecked={value.enabled === true} /><span>{t("settings.bodyCapture.enabled")}</span></label><label className="field"><span>{t("settings.bodyCapture.retention")}</span><input className="inp" type="number" name="retention_days" min="1" max="365" defaultValue={Number(value.retention_days ?? 7)} /></label><label className="field"><span>{t("settings.bodyCapture.maxBytes")}</span><input className="inp" type="number" name="max_bytes" min="1" max="67108864" defaultValue={Number(value.max_bytes ?? 4194304)} /></label><button className="btn btn-primary" type="submit" disabled={mutation.isPending}>{t("common.save")}</button></form> : null}</section>;
}

/** 运行时阈值:价格同步周期与第三方拒绝告警阈值,写入 ops.system_setting */
function RuntimeSettingsPanel() {
  const { t } = useI18n();
  const query = useQuery({ queryKey: ["runtime-settings"], queryFn: () => api<Record<string, unknown>>("/admin/v1/settings/runtime"), retry: false });
  const mutation = useMutation({ mutationFn: (value: Record<string, number>) => api("/admin/v1/settings/runtime", { method: "PUT", body: JSON.stringify(value) }), onSuccess: () => void query.refetch() });
  const value = query.data ?? {};
  const fields: Array<{ name: string; labelKey: MessageKey; min: number; max: number; fallback: number }> = [
    { name: "price_sync_interval_hours", labelKey: "settings.runtime.priceSyncInterval", min: 1, max: 168, fallback: 24 },
    { name: "third_party_window_minutes", labelKey: "settings.runtime.thirdPartyWindow", min: 1, max: 1440, fallback: 15 },
    { name: "third_party_min_rejections", labelKey: "settings.runtime.thirdPartyMinRejections", min: 1, max: 1000, fallback: 3 },
    { name: "third_party_ratio_percent", labelKey: "settings.runtime.thirdPartyRatio", min: 1, max: 100, fallback: 20 },
  ];
  return <section className="card pad body-capture-settings"><div className="section-head"><div><p className="eyebrow mono">SYSTEM / RUNTIME</p><h2>{t("settings.runtime.title")}</h2><p>{t("settings.runtime.description")}</p></div></div>{query.isLoading ? <p className="muted">{t("common.loading")}</p> : query.isError ? <p className="muted">{t("common.requestFailed")}</p> : query.isSuccess ? <form key={query.dataUpdatedAt} className="settings-grid" onSubmit={(event) => { event.preventDefault(); const data = new FormData(event.currentTarget); mutation.mutate(Object.fromEntries(fields.map((field) => [field.name, Number(data.get(field.name))]))); }}>{fields.map((field) => <label key={field.name} className="field"><span>{t(field.labelKey)}</span><input className="inp" type="number" name={field.name} min={field.min} max={field.max} required defaultValue={Number(value[field.name] ?? field.fallback)} /></label>)}<button className="btn btn-primary" type="submit" disabled={mutation.isPending}>{t("common.save")}</button></form> : null}</section>;
}

interface ExportRecord {
  id: string;
  dataset: string;
  format: string;
  scope: string;
  state: "queued" | "running" | "succeeded" | "failed" | "expired";
  row_count: number | null;
  created_at: string;
  completed_at: string | null;
  expires_at: string | null;
  download_count: number;
  download_available: boolean;
}

function ExportsPage() {
  const { locale, t } = useI18n();
  const result = useQuery({
    queryKey: ["/admin/v1/exports"],
    queryFn: () => api<ExportRecord[]>("/admin/v1/exports"),
    retry: false,
    // 有排队/生成中的任务时每 5 秒轮询,全部进入终态后停止
    refetchInterval: (query) => ((query.state.data ?? []).some((item) => item.state === "queued" || item.state === "running") ? 5000 : false),
  });
  const records = (result.data ?? []).filter((item): item is ExportRecord => typeof item === "object" && item !== null);
  const pager = usePagination(records);
  function download(item: ExportRecord) {
    window.open(`/admin/v1/exports/${encodeURIComponent(item.id)}/download`, "_blank", "noopener");
    // 下载是一次性的,稍后刷新让 download_available 状态翻转
    window.setTimeout(() => void result.refetch(), 2_000);
  }
  return <div className="page-stack">
    <header className="page-heading"><div><p className="eyebrow mono">{t("export.eyebrow")}</p><h1>{t("nav.exports")}</h1><p>{t("export.description")}</p></div></header>
    {result.isError && <ErrorState error={result.error} />}
    <section className="card table-card" aria-busy={result.isLoading}>
      <div className="cardbar"><div className="cbl"><h2>{t("nav.exports")}</h2><span className="tag t-gray">{t("export.oneTime")}</span></div><div className="cbr"><ResourceActionButton action="export" iconOnly /><button className={`ibtn outline${result.isFetching ? " loading" : ""}`} type="button" aria-label={t("table.refresh")} disabled={result.isFetching} onClick={() => void result.refetch()}><Icon name="refresh" /></button></div></div>
      {result.isLoading ? <div className="loading-lines"><span className="skel title" /><span className="skel line" /><span className="skel line" /></div>
        : records.length === 0 ? <div className="empty"><div className="empty-orbit"><Icon name="download" /></div><h3>{t("export.emptyTitle")}</h3><p>{t("export.emptyBody")}</p></div>
          : <><div className="tbl-wrap"><table className="tbl exports-table"><caption className="sr-only">{t("table.caption", { title: t("nav.exports"), count: records.length })}</caption>
            <thead><tr><th scope="col">{t("export.column.dataset")}</th><th scope="col">{t("action.export.format")}</th><th scope="col">{t("action.export.scope")}</th><th scope="col">{t("export.column.state")}</th><th scope="col">{t("export.column.created")}</th><th scope="col">{t("export.column.completed")}</th><th scope="col">{t("export.column.rows")}</th><th scope="col" className="row-actions-heading">{t("table.actions")}</th></tr></thead>
            <tbody>{pager.pageRows.map((item) => <tr key={item.id}>
              <td className="mono">{item.dataset}</td>
              <td className="mono">{item.format}</td>
              <td>{item.scope === "all" ? t("action.export.all") : t("action.export.own")}</td>
              <td><span className={`key-status ${item.state === "succeeded" ? "active" : item.state === "failed" || item.state === "expired" ? "revoked" : "disabled"}`}>{t(`export.state.${item.state}`)}</span></td>
              <td>{new Date(item.created_at).toLocaleString(locale)}</td>
              <td>{item.completed_at ? new Date(item.completed_at).toLocaleString(locale) : "—"}</td>
              <td>{item.row_count === null ? "—" : item.row_count.toLocaleString(locale)}</td>
              <td><div className="row-actions">{item.download_available
                ? <button type="button" className="ibtn outline" data-tip={t("export.download")} aria-label={t("export.download")} onClick={() => download(item)}><Icon name="download" /></button>
                : <span className="muted">{item.download_count > 0 ? t("export.downloaded") : item.state === "succeeded" ? t("export.unavailable") : "—"}</span>}</div></td>
            </tr>)}</tbody></table></div><TablePager page={pager.page} pageCount={pager.pageCount} total={pager.total} onPage={pager.setPage} /></>}
    </section>
  </div>;
}
