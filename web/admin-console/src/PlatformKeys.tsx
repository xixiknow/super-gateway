import { FormEvent, ReactNode, useEffect, useId, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, setCsrfToken } from "./api";
import { useToast } from "./feedback";
import { Locale, MessageKey, useI18n } from "./i18n";
import { RowActionDef, RowActionsCell } from "./row-actions";
import { TablePager, usePagination } from "./pagination";
import { SelectField } from "./select-field";
import { useCompactLayout } from "./use-compact-layout";

interface PlatformKeyRecord {
  id: string;
  name: string;
  group_id: string;
  display_prefix: string | null;
  group_name: string;
  status: "active" | "disabled" | "expired" | "revoked";
  expires_at: string | null;
  revision: number;
  max_concurrency: number | null;
  messages_rpm: number | null;
  spend_limit_amount: string | null;
  today_spend_amount: string;
  thirty_day_spend_amount: string;
  lifetime_spend_amount: string;
  last_used_at: string | null;
}

interface KeyConfigVersion {
  is_active?: unknown;
  messages_enabled?: unknown;
  models_enabled?: unknown;
  model_allowlist?: unknown;
  ip_allowlist?: unknown;
}

interface ModelOption { id?: unknown; display_name?: unknown; upstream_model_id?: unknown; lifecycle?: unknown }

interface GroupOption { id?: unknown; name?: unknown; status?: unknown }

type KeyAction = "edit" | "reveal" | "disable" | "reactivate" | "revoke" | "client-config" | "config-history";

function isPlatformKeyRecord(value: unknown): value is PlatformKeyRecord {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return typeof record.id === "string" && typeof record.name === "string" && typeof record.group_name === "string"
    && typeof record.status === "string" && typeof record.revision === "number";
}

function formatDate(value: string | null, locale: Locale, never: string): string {
  return value ? new Date(value).toLocaleString(locale) : never;
}

function formatMoney(value: string | null, locale: Locale, unlimited: string): string {
  if (value === null) return unlimited;
  const amount = Number(value);
  return Number.isFinite(amount)
    ? new Intl.NumberFormat(locale, { style: "currency", currency: "USD", maximumFractionDigits: 2 }).format(amount)
    : value;
}

function localDateTimeValue(value: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function actionTitleKey(action: KeyAction) {
  return `key.action.${action}.title` as const;
}

function actionConfirmKey(action: KeyAction): MessageKey {
  switch (action) {
    case "edit": return "key.action.edit.confirm";
    case "reveal": return "key.action.reveal.confirm";
    case "disable": return "key.action.disable.confirm";
    case "reactivate": return "key.action.reactivate.confirm";
    case "revoke": return "key.action.revoke.confirm";
    default: return "common.done";
  }
}

function viewEndpoint(action: KeyAction, keyId: string): string | null {
  const base = `/admin/v1/platform-keys/${encodeURIComponent(keyId)}`;
  if (action === "client-config") return `${base}/client-config`;
  if (action === "config-history") return `${base}/config-versions`;
  return null;
}

function baseForKey(keyId: string): string {
  return `/admin/v1/platform-keys/${encodeURIComponent(keyId)}`;
}

interface RevealedSecret {
  secret: string;
  secondsLeft: number;
}

function splitSecretMask(value: string): { head: string; middle: string; tail: string } {
  const trimmed = value.trim();
  if (trimmed.length <= 2) return { head: "", middle: trimmed, tail: "" };
  const tailLen = Math.min(4, Math.max(1, Math.floor(trimmed.length / 5)));
  const headLen = Math.min(7, Math.max(1, trimmed.length - tailLen - 1));
  if (headLen + tailLen >= trimmed.length) return { head: trimmed.slice(0, 1), middle: trimmed.slice(1, -1), tail: trimmed.slice(-1) };
  return { head: trimmed.slice(0, headLen), middle: trimmed.slice(headLen, trimmed.length - tailLen), tail: trimmed.slice(trimmed.length - tailLen) };
}

function KeySecretCell({ item, revealed, copied, onReveal, onHide, onCopy }: { item: PlatformKeyRecord; revealed?: RevealedSecret; copied: boolean; onReveal(intent: "show" | "copy"): void; onHide(): void; onCopy(secret: string): void }) {
  const { t } = useI18n();
  const revoked = item.status === "revoked";
  const shown = revealed?.secret;
  const masked = !shown && item.display_prefix ? splitSecretMask(item.display_prefix) : null;
  return (
    <div className="key-secret-cell">
      <div className="key-secret-main">
        <span className={`key-secret-text${shown ? " revealed" : ""}`}>
          {shown ? shown : masked ? <>
            <span className="key-secret-edge">{masked.head}</span>
            {masked.middle ? <span className="key-secret-blur">{masked.middle}</span> : null}
            <span className="key-secret-edge">{masked.tail}</span>
          </> : "—"}
        </span>
        {shown ? <small className="key-secret-countdown">{t("key.secret.countdown", { seconds: revealed.secondsLeft })}</small> : null}
      </div>
      <span className="key-secret-actions">
        <button type="button" className={`ibtn outline sm${shown ? " on" : ""}`} data-tip={shown ? t("key.secret.hide") : t("key.action.reveal")} aria-label={shown ? t("key.secret.hide") : t("key.action.reveal")} aria-pressed={Boolean(shown)} disabled={revoked} onClick={() => { if (shown) onHide(); else onReveal("show"); }}>
          <svg className="icon" aria-hidden="true"><use href={shown ? "#i-eye-off" : "#i-eye"} /></svg>
        </button>
        <button type="button" className="ibtn outline sm" data-tip={copied ? t("key.reveal.copied") : t("key.reveal.copy")} aria-label={copied ? t("key.reveal.copied") : t("key.reveal.copy")} disabled={revoked} onClick={() => { if (shown) onCopy(shown); else onReveal("copy"); }}>
          <svg className="icon" aria-hidden="true"><use href={copied ? "#i-check" : "#i-copy"} /></svg>
        </button>
      </span>
    </div>
  );
}

function actionError(error: unknown, locale: Locale): string {
  if (error instanceof ApiError) {
    if (locale === "zh-CN") {
      if (error.status === 401) return "当前密码不正确，请重新输入。";
      if (error.status === 412) return "数据已发生变化，请关闭窗口并刷新后重试。";
      if (error.status === 409) return "当前状态不允许执行该操作。";
      if (error.status === 403) return "当前账号没有执行该操作的权限。";
      return `请求失败（状态码 ${error.status}）：${error.message}`;
    }
    return `Request failed (${error.status}): ${error.message}`;
  }
  return error instanceof Error ? error.message : locale === "zh-CN" ? "操作未完成，请稍后重试。" : "The operation did not complete. Try again.";
}

export function PlatformKeysTable({ loading, items, title, principalRole = "platform_admin", onRefresh, refreshing = false, toolbar }: { loading: boolean; items?: unknown[]; title: string; principalRole?: string; onRefresh(): void; refreshing?: boolean; toolbar?: ReactNode }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const compact = useCompactLayout();
  const [dialog, setDialog] = useState<{ action: KeyAction; key: PlatformKeyRecord; revealIntent?: "show" | "copy" } | null>(null);
  const [revealed, setRevealed] = useState<Record<string, RevealedSecret>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const records = (items ?? []).filter(isPlatformKeyRecord);
  const pager = usePagination(records);
  const revealedCount = Object.keys(revealed).length;
  useEffect(() => {
    if (revealedCount === 0) return;
    const timer = window.setInterval(() => {
      setRevealed((current) => {
        const next: Record<string, RevealedSecret> = {};
        for (const [id, entry] of Object.entries(current)) {
          if (entry.secondsLeft > 1) next[id] = { secret: entry.secret, secondsLeft: entry.secondsLeft - 1 };
        }
        return next;
      });
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [revealedCount]);
  async function copySecret(id: string, secret: string) {
    try {
      await navigator.clipboard.writeText(secret);
      setCopiedId(id);
      window.setTimeout(() => setCopiedId((current) => current === id ? null : current), 2_000);
    } catch {
      toast.error(t("key.secret.copyFailed"));
    }
  }
  return <>
    <section className="card table-card key-table-card" aria-busy={loading}>
      <div className="cardbar"><div className="cbl"><h2>{title}</h2><span className="tag t-gray">{t("table.stableSort")}</span></div><div className="cbr">{toolbar}<button className={`ibtn outline${refreshing ? " loading" : ""}`} type="button" aria-label={t("table.refresh")} disabled={refreshing} onClick={onRefresh}><svg className="icon" aria-hidden="true"><use href="#i-refresh" /></svg></button></div></div>
      {loading ? <div className="loading-lines"><span className="skel title" /><span className="skel line" /><span className="skel line" /></div>
        : records.length === 0 ? <div className="empty"><div className="empty-orbit"><svg className="icon" aria-hidden="true"><use href="#i-inbox" /></svg></div><h3>{t("table.emptyTitle")}</h3><p>{t("table.emptyBody")}</p></div>
          : <>{compact ? <div className="tbl-cards">{pager.pageRows.map((key) => <article className="tbl-card" key={key.id}><header className="tbl-card-head"><div><strong>{key.name}</strong><small>{t("key.lastUsed", { value: formatDate(key.last_used_at, locale, t("key.neverUsed")) })}</small></div><span className={`key-status ${key.status}`}>{t(`key.status.${key.status}`)}</span></header><div className="tbl-card-secret"><KeySecretCell item={key} revealed={revealed[key.id]} copied={copiedId === key.id} onReveal={(intent) => setDialog({ action: "reveal", key, revealIntent: intent })} onHide={() => setRevealed((current) => { const next = { ...current }; delete next[key.id]; return next; })} onCopy={(secret) => void copySecret(key.id, secret)} /></div><dl className="tbl-card-grid"><div><dt>{t("key.column.group")}</dt><dd>{key.group_name}</dd></div><div><dt>{t("key.column.expires")}</dt><dd>{formatDate(key.expires_at, locale, t("key.expires.never"))}</dd></div><div><dt>{t("key.column.concurrency")}</dt><dd>{key.max_concurrency?.toLocaleString(locale) ?? "—"}</dd></div><div><dt>{t("key.column.rpm")}</dt><dd>{key.messages_rpm?.toLocaleString(locale) ?? "—"}</dd></div><div><dt>{t("key.column.spendLimit")}</dt><dd>{formatMoney(key.spend_limit_amount, locale, t("key.spend.unlimited"))}</dd></div><div><dt>{t("key.column.todaySpend")}</dt><dd>{formatMoney(key.today_spend_amount, locale, "—")}</dd></div><div><dt>{t("key.column.thirtyDaySpend")}</dt><dd>{formatMoney(key.thirty_day_spend_amount, locale, "—")}</dd></div><div><dt>{t("key.column.lifetimeSpend")}</dt><dd>{formatMoney(key.lifetime_spend_amount, locale, "—")}</dd></div></dl><footer className="tbl-card-foot"><KeyRowActions item={key} onAction={(action) => setDialog({ action, key })} /></footer></article>)}</div>
          : <div className="tbl-wrap"><table className="tbl key-table"><caption className="sr-only">{t("table.caption", { title, count: records.length })}</caption><thead><tr><th scope="col">{t("key.column.name")}</th><th scope="col">{t("key.column.secret")}</th><th scope="col">{t("key.column.group")}</th><th scope="col">{t("key.column.status")}</th><th scope="col">{t("key.column.expires")}</th><th scope="col">{t("key.column.concurrency")}</th><th scope="col">{t("key.column.rpm")}</th><th scope="col">{t("key.column.spendLimit")}</th><th scope="col">{t("key.column.todaySpend")}</th><th scope="col">{t("key.column.thirtyDaySpend")}</th><th scope="col">{t("key.column.lifetimeSpend")}</th><th scope="col" className="row-actions-heading">{t("key.column.actions")}</th></tr></thead><tbody>{pager.pageRows.map((key) => <tr key={key.id}><td><strong>{key.name}</strong><small>{t("key.lastUsed", { value: formatDate(key.last_used_at, locale, t("key.neverUsed")) })}</small></td><td><KeySecretCell item={key} revealed={revealed[key.id]} copied={copiedId === key.id} onReveal={(intent) => setDialog({ action: "reveal", key, revealIntent: intent })} onHide={() => setRevealed((current) => { const next = { ...current }; delete next[key.id]; return next; })} onCopy={(secret) => void copySecret(key.id, secret)} /></td><td>{key.group_name}</td><td><span className={`key-status ${key.status}`}>{t(`key.status.${key.status}`)}</span></td><td>{formatDate(key.expires_at, locale, t("key.expires.never"))}</td><td>{key.max_concurrency?.toLocaleString(locale) ?? "—"}</td><td>{key.messages_rpm?.toLocaleString(locale) ?? "—"}</td><td>{formatMoney(key.spend_limit_amount, locale, t("key.spend.unlimited"))}</td><td>{formatMoney(key.today_spend_amount, locale, "—")}</td><td>{formatMoney(key.thirty_day_spend_amount, locale, "—")}</td><td>{formatMoney(key.lifetime_spend_amount, locale, "—")}</td><td><KeyRowActions item={key} onAction={(action) => setDialog({ action, key })} /></td></tr>)}</tbody></table></div>}<TablePager page={pager.page} pageCount={pager.pageCount} total={pager.total} onPage={pager.setPage} /></>}
    </section>
    {dialog && <KeyActionDialog action={dialog.action} item={dialog.key} canChangeGroup={principalRole === "platform_admin"} onClose={() => setDialog(null)} onRevealed={(secret, seconds) => { const id = dialog.key.id; const intent = dialog.revealIntent; setRevealed((current) => ({ ...current, [id]: { secret, secondsLeft: seconds } })); if (intent === "copy") void copySecret(id, secret); }} />}
  </>;
}

function KeyRowActions({ item, onAction }: { item: PlatformKeyRecord; onAction(action: KeyAction): void }) {
  const actions = useMemo<RowActionDef<PlatformKeyRecord>[]>(() => {
    const notRevoked = (key: PlatformKeyRecord) => key.status !== "revoked";
    const open = (action: KeyAction) => ({ custom: () => onAction(action) });
    return [
      { key: "edit", labelKey: "key.action.edit", icon: "edit", primary: true, when: notRevoked, ...open("edit") },
      { key: "disable", labelKey: "key.action.disable", icon: "pause", danger: true, primary: true, when: (key) => key.status === "active", ...open("disable") },
      { key: "reactivate", labelKey: "key.action.reactivate", icon: "play", primary: true, when: (key) => key.status === "disabled" || key.status === "expired", ...open("reactivate") },
      { key: "client-config", labelKey: "key.action.clientConfig", icon: "file-text", ...open("client-config") },
      { key: "config-history", labelKey: "key.action.configHistory", icon: "clock", ...open("config-history") },
      { key: "revoke", labelKey: "key.action.revoke", icon: "lock", danger: true, when: notRevoked, ...open("revoke") },
    ];
  }, [onAction]);
  return <RowActionsCell row={item as unknown as Record<string, unknown>} actions={actions as unknown as RowActionDef<Record<string, unknown>>[]} />;
}

function KeyActionDialog({ action, item, canChangeGroup, onClose, onRevealed }: { action: KeyAction; item: PlatformKeyRecord; canChangeGroup: boolean; onClose(): void; onRevealed(secret: string, seconds: number): void }) {
  const { locale, t } = useI18n();
  const queryClient = useQueryClient();
  const titleId = useId();
  const endpoint = viewEndpoint(action, item.id);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const [copied, setCopied] = useState(false);
  const [selectedGroupId, setSelectedGroupId] = useState(item.group_id);
  const details = useQuery({ queryKey: [endpoint], queryFn: () => api<unknown>(endpoint ?? ""), enabled: endpoint !== null, retry: false });
  const groups = useQuery({ queryKey: ["/admin/v1/groups"], queryFn: () => api<GroupOption[]>("/admin/v1/groups"), enabled: action === "edit" && canChangeGroup, retry: false });
  const configHistory = useQuery({ queryKey: [`${baseForKey(item.id)}/config-versions`], queryFn: () => api<KeyConfigVersion[]>(`${baseForKey(item.id)}/config-versions`), enabled: action === "edit", retry: false });
  const models = useQuery({ queryKey: ["/admin/v1/models"], queryFn: () => api<ModelOption[]>("/admin/v1/models"), enabled: action === "edit", retry: false });
  const [endpointPermissions, setEndpointPermissions] = useState<string[]>(["messages", "models"]);
  const [selectedModels, setSelectedModels] = useState<string[]>([]);
  const [ipAllowlist, setIpAllowlist] = useState("");
  useEffect(() => {
    if (action !== "edit" || !configHistory.data) return;
    const active = configHistory.data.find((version) => version.is_active) ?? configHistory.data[0];
    if (!active) return;
    setEndpointPermissions([...(active.messages_enabled ? ["messages"] : []), ...(active.models_enabled ? ["models"] : [])]);
    setSelectedModels(Array.isArray(active.model_allowlist) ? active.model_allowlist.map(String) : []);
    setIpAllowlist(Array.isArray(active.ip_allowlist) ? active.ip_allowlist.map(String).join("\n") : "");
  }, [action, configHistory.data]);
  const mutation = useMutation({
    mutationFn: async (form: FormData) => {
      const headers = { "If-Match": `"rev-${item.revision}"` };
      if (action === "edit") {
        const expires = String(form.get("expires_at") ?? "");
        const spendLimit = String(form.get("spend_limit_amount") ?? "").trim();
        const permissions = form.getAll("endpoint_permissions").map(String);
        if (permissions.length === 0) throw new Error(t("key.action.edit.permissionsRequired"));
        return api(`/admin/v1/platform-keys/${encodeURIComponent(item.id)}`, { method: "PATCH", headers, body: JSON.stringify({
          name: String(form.get("name") ?? "").trim(),
          expires_at: expires ? new Date(expires).toISOString() : null,
          ...(canChangeGroup ? { group_id: String(form.get("group_id") ?? "") } : {}),
          max_concurrency: Number(form.get("max_concurrency")),
          messages_rpm: Number(form.get("messages_rpm")),
          spend_limit_amount: spendLimit || null,
          endpoint_permissions: permissions,
          model_allowlist: form.getAll("model_allowlist").map(String),
          ip_allowlist: String(form.get("ip_allowlist") ?? "").split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
        }) });
      }
      const reason = String(form.get("reason") ?? "").trim();
      let stepUpGrantId: string | undefined;
      if (action === "reveal" || action === "revoke") {
        const purpose = action === "reveal" ? "key_secret_reveal" : "irreversible_lifecycle";
        const grant = await api<{ id: string; csrf_token: string }>("/admin/v1/auth/step-up", { method: "POST", body: JSON.stringify({ purpose, current_password: String(form.get("current_password") ?? "") }) });
        setCsrfToken(grant.csrf_token);
        stepUpGrantId = grant.id;
      }
      if (action === "reveal") return api<{ secret: string; expires_in_seconds: number }>(`/admin/v1/platform-keys/${encodeURIComponent(item.id)}:reveal`, { method: "POST", headers, body: JSON.stringify({ step_up_grant_id: stepUpGrantId, reason }) });
      const suffix = action === "reactivate" ? "reactivate" : action === "revoke" ? "revoke" : "disable";
      return api(`/admin/v1/platform-keys/${encodeURIComponent(item.id)}:${suffix}`, { method: "POST", headers, body: JSON.stringify({ reason, expected_revision: item.revision, ...(stepUpGrantId ? { step_up_grant_id: stepUpGrantId } : {}) }) });
    },
    onSuccess: (result) => {
      if (action === "reveal") {
        const payload = result as { secret?: string; expires_in_seconds?: number };
        if (payload.secret) {
          onRevealed(payload.secret, payload.expires_in_seconds ?? 60);
          onClose();
          return;
        }
        setSecondsLeft(payload.expires_in_seconds ?? 60);
        return;
      }
      void queryClient.invalidateQueries({ queryKey: ["/admin/v1/platform-keys"] });
    },
  });
  useEffect(() => {
    if (secondsLeft <= 0) return;
    const timer = window.setInterval(() => setSecondsLeft((value) => Math.max(0, value - 1)), 1_000);
    return () => window.clearInterval(timer);
  }, [secondsLeft]);
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape" && !mutation.isPending) onClose(); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [mutation.isPending, onClose]);
  const secret = action === "reveal" && mutation.isSuccess && secondsLeft > 0 ? (mutation.data as { secret?: string }).secret : undefined;
  const isView = endpoint !== null;
  const needsPassword = action === "reveal" || action === "revoke";
  const needsReason = !isView && action !== "edit";
  async function copySecret() {
    if (!secret) return;
    await navigator.clipboard.writeText(secret);
    setCopied(true);
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    mutation.mutate(new FormData(event.currentTarget));
  }
  return createPortal(<div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget && !mutation.isPending) onClose(); }}><section className="modal key-action-modal" role="dialog" aria-modal="true" aria-labelledby={titleId}>
    <div className="modal-head"><div><p className="eyebrow mono">{t("key.action.eyebrow")}</p><h3 id={titleId}>{t(actionTitleKey(action))}</h3><p className="muted">{item.name}</p></div><button type="button" className="ibtn outline" aria-label={t("common.close")} onClick={onClose} disabled={mutation.isPending}>×</button></div>
    {isView ? <div className="modal-body key-readonly-body">{details.isLoading ? <div className="loading-lines"><span className="skel title" /><span className="skel line" /></div> : details.isError ? <div className="alert alert-err" role="alert">{actionError(details.error, locale)}</div> : <LocalizedData value={details.data} locale={locale} />}</div>
      : mutation.isSuccess ? <><div className="modal-body">{action === "reveal" ? <div className="secret-reveal"><div className="alert alert-warn"><div><div className="at">{t("key.reveal.notice")}</div><div className="ad">{t("key.reveal.countdown", { seconds: secondsLeft })}</div></div></div>{secret ? <><code>{secret}</code><button type="button" className="btn btn-primary" onClick={() => void copySecret()}>{copied ? t("key.reveal.copied") : t("key.reveal.copy")}</button></> : <p className="muted">{t("key.reveal.hidden")}</p>}</div> : <div className="alert alert-ok" role="status"><div><div className="at">{t("key.action.success")}</div><div className="ad">{t("key.action.successBody")}</div></div></div>}</div><div className="modal-foot"><button type="button" className="btn btn-primary" onClick={onClose}>{t("common.done")}</button></div></>
        : <form onSubmit={submit}><div className="modal-body resource-action-grid">{mutation.isError && <div className="alert alert-err action-error" role="alert"><div><div className="at">{t("action.submitFailed")}</div><div className="ad">{actionError(mutation.error, locale)}</div></div></div>}{action === "revoke" && <div className="alert alert-warn action-error"><div><div className="at">{t("key.revoke.warning")}</div><div className="ad">{t("key.revoke.warningBody")}</div></div></div>}{action === "edit" && <>
          <div className="field"><label htmlFor={`${titleId}-name`}>{t("action.key.name")}</label><input id={`${titleId}-name`} name="name" className="inp" defaultValue={item.name} required maxLength={128} autoFocus /></div>
          {canChangeGroup && <div className="field"><label htmlFor={`${titleId}-group`}>{t("action.key.group")}</label><SelectField id={`${titleId}-group`} name="group_id" required value={selectedGroupId} onChange={setSelectedGroupId} disabled={groups.isLoading || groups.isError} options={groups.data === undefined ? [{ value: item.group_id, label: item.group_name }] : groups.data.filter((group) => group.status === "active").map((group) => ({ value: String(group.id), label: String(group.name) }))} />{groups.isError && <small className="field-error">{t("action.optionLoadFailed")}</small>}</div>}
          <div className="field"><label htmlFor={`${titleId}-concurrency`}>{t("key.column.concurrency")}</label><input id={`${titleId}-concurrency`} name="max_concurrency" className="inp" type="number" min={1} max={1_000_000} defaultValue={item.max_concurrency ?? 1} required /></div>
          <div className="field"><label htmlFor={`${titleId}-rpm`}>{t("key.column.rpm")}</label><input id={`${titleId}-rpm`} name="messages_rpm" className="inp" type="number" min={1} max={1_000_000} defaultValue={item.messages_rpm ?? 1} required /></div>
          <div className="field"><label htmlFor={`${titleId}-spend`}>{t("key.column.spendLimit")}<span className="hint">{t("key.edit.spendHint")}</span></label><input id={`${titleId}-spend`} name="spend_limit_amount" className="inp" type="number" min={0} step="0.01" defaultValue={item.spend_limit_amount ?? ""} /></div>
          <fieldset className="choice-field field-wide"><legend>{t("action.key.permissions")}</legend><div className="choice-grid">{[["messages", "option.endpoint.messages"], ["models", "option.endpoint.models"]].map(([value, labelKey]) => <label key={value} className="choice-card"><input type="checkbox" name="endpoint_permissions" value={value} checked={endpointPermissions.includes(value)} onChange={(event) => setEndpointPermissions((current) => event.target.checked ? [...new Set([...current, value])] : current.filter((item) => item !== value))} /><span>{t(labelKey as MessageKey)}</span></label>)}</div></fieldset>
          <fieldset className="choice-field field-wide"><legend>{t("action.key.modelAllowlist")}<span className="hint">{t("action.key.modelAllowlistHint")}</span></legend>{models.isLoading ? <p className="muted">{t("common.loading")}</p> : <div className="choice-grid">{(models.data ?? []).filter((model) => model.lifecycle === "published").map((model) => { const id = String(model.id ?? ""); return <label key={id} className="choice-card"><input type="checkbox" name="model_allowlist" value={id} checked={selectedModels.includes(id)} onChange={(event) => setSelectedModels((current) => event.target.checked ? [...new Set([...current, id])] : current.filter((item) => item !== id))} /><span>{String(model.display_name ?? model.upstream_model_id ?? id)}</span></label>; })}</div>}</fieldset>
          <div className="field field-wide"><label htmlFor={`${titleId}-ips`}>{t("action.key.ipAllowlist")}<span className="hint">{t("action.key.ipAllowlistHint")}</span></label><textarea id={`${titleId}-ips`} name="ip_allowlist" className="inp mono" rows={4} value={ipAllowlist} onChange={(event) => setIpAllowlist(event.target.value)} /></div>
          <div className="field"><label htmlFor={`${titleId}-expires`}>{t("action.key.expires")}<span className="hint">{t("key.edit.expiresHint")}</span></label><input id={`${titleId}-expires`} name="expires_at" className="inp" type="datetime-local" defaultValue={localDateTimeValue(item.expires_at)} /></div>
        </>}{needsPassword && <div className="field field-wide"><label htmlFor={`${titleId}-password`}>{t("key.action.currentPassword")}</label><input id={`${titleId}-password`} name="current_password" className="inp" type="password" required autoComplete="current-password" autoFocus /></div>}{needsReason && <div className="field field-wide"><label htmlFor={`${titleId}-reason`}>{t("key.action.reason")}</label><textarea id={`${titleId}-reason`} name="reason" className="inp" maxLength={2048} rows={3} autoFocus={!needsPassword} /></div>}</div><div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose} disabled={mutation.isPending}>{t("common.cancel")}</button><button type="submit" className={`btn ${action === "revoke" ? "btn-danger" : "btn-primary"}`} disabled={mutation.isPending || (action === "edit" && canChangeGroup && groups.isLoading)}>{mutation.isPending ? t("common.submitting") : t(actionConfirmKey(action))}</button></div></form>}
  </section></div>, document.body);
}

const hiddenTechnicalKeys = new Set(["id", "platform_key_id", "config_id", "object_id", "actor_id", "created_by"]);

function LocalizedData({ value, locale }: { value: unknown; locale: Locale }): ReactNode {
  const { t } = useI18n();
  if (value === null || value === undefined) return <span>—</span>;
  if (Array.isArray(value)) return value.length === 0 ? <p className="muted">{t("key.details.empty")}</p> : <div className="key-data-list">{value.map((entry, index) => <article key={index}><LocalizedData value={entry} locale={locale} /></article>)}</div>;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).filter(([key]) => !hiddenTechnicalKeys.has(key) && !key.endsWith("_id"));
    return <dl className="key-data-grid">{entries.map(([key, entry]) => <div key={key}><dt>{dataLabel(key, locale)}</dt><dd><LocalizedData value={entry} locale={locale} /></dd></div>)}</dl>;
  }
  if (typeof value === "boolean") return locale === "zh-CN" ? value ? "是" : "否" : value ? "Yes" : "No";
  const text = String(value);
  const translated = dataValue(text, locale);
  if (/^\d{4}-\d{2}-\d{2}T/.test(text)) return new Date(text).toLocaleString(locale);
  return <span className={text.length > 36 ? "mono breakable" : ""}>{translated}</span>;
}

const zhDataLabels: Record<string, string> = {
  name: "名称", status: "状态", display_prefix: "密钥前缀", template_kind: "配置模板", contains_secret: "是否包含密钥",
  environment: "环境变量", active_config: "当前配置", version: "版本", messages_enabled: "消息接口", models_enabled: "模型接口",
  max_body_bytes: "最大请求体字节数", messages_rpm: "消息接口每分钟请求数", messages_burst: "消息接口突发数",
  models_rpm: "模型接口每分钟请求数", models_burst: "模型接口突发数", max_concurrency: "最大并发数",
  content_sha256: "内容校验摘要", messages_rate: "消息接口速率", models_rate: "模型接口速率", rpm: "每分钟请求数", burst: "突发数",
  model_allowlist: "模型白名单", ip_allowlist: "网络白名单", created_at: "创建时间",
  is_active: "是否生效", pointer_revision: "生效版本", event_day: "事件日期", daily_sequence: "当日序号", actor_type: "操作方类型",
  action: "操作", object_type: "对象类型", outcome: "结果", detail: "详情", occurred_at: "发生时间", canonical_redacted_event: "脱敏审计内容",
};

function dataLabel(value: string, locale: Locale): string {
  if (locale === "zh-CN") return zhDataLabels[value] ?? "扩展信息";
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

const zhDataValues: Record<string, string> = { active: "活跃", disabled: "已禁用", expired: "已过期", revoked: "已吊销", claude_code_environment: "客户端环境配置", success: "成功", platform_admin: "平台管理员", key_owner: "密钥所有者" };

function dataValue(value: string, locale: Locale): string {
  if (locale === "zh-CN") return zhDataValues[value] ?? value;
  return value.replaceAll("_", " ");
}
