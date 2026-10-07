import { FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, apiEnvelope, type Principal } from "./api";
import { formatAmount, formatCount, formatCountdown, formatDateTime, formatRelative } from "./format";
import { Meter, useCountdown } from "./meter";
import { useI18n, type MessageKey, type Locale } from "./i18n";
import { AccountStatsModal } from "./account-stats";
import { useOpenAiAccountActions, type OpenAiAccount } from "./openai-account-panel";
import { AddAccountDialog } from "./add-account-dialog";
import { useResourceRowActions } from "./resource-actions";
import { RowActionsCell } from "./row-actions";
import { TablePager, usePagination } from "./pagination";
import { useToast } from "./feedback";
import { SelectField } from "./select-field";

function Icon({ name }: { name: string }) {
  return <svg className="icon sm" aria-hidden="true"><use href={`#i-${name}`} /></svg>;
}

interface QuotaWindow { utilization: number; resets_at: string | null; observed_at: string | null }
interface CredentialRow extends Record<string, unknown> {
  id: string; group_id: string; account_uuid: string | null; purpose: string; auth_kind: string;
  lifecycle_state: string; auth_state: string; scheduling_state: string; quota_state: string;
  transport_state: string; management_class: string; cooldown_until: string | null;
  last_error_code: string | null; last_error_message: string | null; last_error_at: string | null;
  egress_mode: string | null; subscription_plan: string | null;
  quota_windows: Record<string, QuotaWindow>;
  scheduling_config: { concurrency: number | null; messages_rpm: number | null; priority: number | null; weight: number | null };
  revision: number; updated_at: string;
}
interface Group { id: string; name: string; provider?: string; status_code?: string }
interface TodayRow { credential_id: string; request_count: number; input_tokens: number | null; output_tokens: number | null; estimated_amount: string | null }

type StateBucket = "normal" | "cooldown" | "blocked" | "auth" | "disabled" | "pending";

interface AccountCard {
  key: string; provider: "anthropic" | "openai"; id: string; name: string; groupId: string;
  badge: string; tone: "teal" | "amber" | "coral" | "gray";
  stateKey: MessageKey; bucket: StateBucket;
  cooldownUntil: string | null; lastError: string | null;
  plan: string | null; windows: { fiveHour: QuotaWindow | null; sevenDay: QuotaWindow | null };
  openaiLimited: boolean | null; today: TodayRow | null;
  priority: number | null; concurrency: number | null; egress: string | null;
  updatedAt: string | null; revision: number; enabled: boolean | null; refreshable: boolean;
  raw: Record<string, unknown>;
}

const asOpenAi = (raw: Record<string, unknown>): OpenAiAccount => raw as unknown as OpenAiAccount;

function anthropicCard(row: CredentialRow, today: Map<string, TodayRow>): AccountCard {
  const error = row.last_error_code ? `${row.last_error_code}${row.last_error_message ? ` · ${row.last_error_message}` : ""}` : null;
  let tone: AccountCard["tone"] = "teal";
  let bucket: StateBucket = "normal";
  let stateKey: MessageKey = "accounts.state.normal";
  if (row.lifecycle_state === "archived") { tone = "gray"; bucket = "disabled"; stateKey = "accounts.state.archived"; }
  else if (row.lifecycle_state !== "active") { tone = "gray"; bucket = "disabled"; stateKey = "accounts.state.disabled"; }
  else if (row.scheduling_state === "blocked") { tone = "coral"; bucket = "blocked"; stateKey = "accounts.state.blocked"; }
  else if (row.scheduling_state === "cooldown") { tone = "coral"; bucket = "cooldown"; stateKey = "accounts.state.cooldown"; }
  else if (row.auth_state !== "healthy") { tone = "amber"; bucket = row.auth_state === "expiring" ? "normal" : "auth"; stateKey = row.auth_state === "expiring" ? "accounts.state.expiring" : "accounts.state.auth"; }
  if (bucket === "blocked" || bucket === "auth") tone = error ? "coral" : tone;
  return {
    key: `anthropic:${row.id}`, provider: "anthropic", id: row.id, name: row.subscription_plan ?? row.account_uuid?.slice(0, 8) ?? row.id.slice(0, 8),
    groupId: row.group_id, badge: row.auth_kind, tone, stateKey, bucket,
    cooldownUntil: row.cooldown_until, lastError: error,
    plan: row.subscription_plan, windows: { fiveHour: row.quota_windows?.five_hour ?? null, sevenDay: row.quota_windows?.seven_day ?? null },
    openaiLimited: null, today: today.get(row.id) ?? null,
    priority: row.scheduling_config?.priority ?? null, concurrency: row.scheduling_config?.concurrency ?? null,
    egress: row.egress_mode, updatedAt: row.updated_at, revision: row.revision, enabled: null, refreshable: true, raw: row,
  };
}

function openaiCard(row: OpenAiAccount, today: Map<string, TodayRow>): AccountCard {
  const error = row.last_error_code ? `${row.last_error_code}${row.last_error_message ? ` · ${row.last_error_message}` : ""}` : null;
  const limited = (row.quota as { rate_limit?: { allowed?: boolean } } | null | undefined)?.rate_limit?.allowed === false ? true : null;
  let tone: AccountCard["tone"] = "teal";
  let bucket: StateBucket = "normal";
  let stateKey: MessageKey = "accounts.state.normal";
  if (!row.enabled) { tone = "gray"; bucket = "disabled"; stateKey = "accounts.state.disabled"; }
  else if (row.auth_state === "pending_verify") { tone = "gray"; bucket = "pending"; stateKey = "openai.pending"; }
  else if (row.auth_state === "needs_reauth" || row.auth_state === "manual_update") { tone = "amber"; bucket = "auth"; stateKey = row.auth_state === "needs_reauth" ? "openai.reauth" : "openai.manual"; }
  else if (error) { tone = "coral"; bucket = "auth"; stateKey = "accounts.state.error"; }
  if (bucket === "normal") tone = "teal";
  return {
    key: `openai:${row.id}`, provider: "openai", id: row.id, name: row.name,
    groupId: row.group_id, badge: row.auth_kind === "oauth" ? "chatgpt_oauth" : "api_key", tone, stateKey, bucket,
    cooldownUntil: row.cooldown_until ?? null, lastError: error,
    plan: row.plan ?? null, windows: { fiveHour: null, sevenDay: null },
    openaiLimited: limited, today: today.get(row.id) ?? null,
    priority: row.priority ?? null, concurrency: row.max_concurrency ?? null, egress: row.proxy_id ? "proxy" : "direct",
    updatedAt: row.quota_observed_at ?? null, revision: row.revision, enabled: row.enabled, refreshable: row.refreshable === true,
    raw: row as unknown as Record<string, unknown>,
  };
}

export function AccountsPage({ principal }: { principal: Principal }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const cache = useQueryClient();
  const [platform, setPlatform] = useState<"all" | "anthropic" | "openai">("all");
  const [bucket, setBucket] = useState<"all" | StateBucket>("all");
  const [groupFilter, setGroupFilter] = useState("");
  const [search, setSearch] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(0);
  const [view, setView] = useState<"cards" | "table">("cards");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [stats, setStats] = useState<{ provider: "anthropic" | "openai"; id: string; name: string } | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [addInitial, setAddInitial] = useState<"pick" | "openai">("pick");
  const openaiActions = useOpenAiAccountActions();
  const { rowActions, rowDialogs } = useResourceRowActions("/credentials", principal);
  const intervalMs = autoRefresh > 0 ? autoRefresh * 1000 : false;
  const credentials = useQuery({ queryKey: ["/admin/v1/credentials"], queryFn: () => api<CredentialRow[]>("/admin/v1/credentials"), retry: false, refetchInterval: intervalMs });
  const openaiAccounts = useQuery({ queryKey: ["/admin/v1/openai/accounts"], queryFn: () => apiEnvelope<OpenAiAccount[]>("/admin/v1/openai/accounts"), retry: false, refetchInterval: intervalMs });
  const today = useQuery({ queryKey: ["/admin/v1/usage/today-by-credential"], queryFn: () => api<TodayRow[]>("/admin/v1/usage/today-by-credential"), retry: false, refetchInterval: intervalMs });
  const groups = useQuery({ queryKey: ["/admin/v1/groups"], queryFn: () => api<Group[]>("/admin/v1/groups"), retry: false });
  const todayMap = useMemo(() => new Map((today.data ?? []).map((row) => [row.credential_id, row])), [today.data]);
  const groupName = useMemo(() => new Map((groups.data ?? []).map((group) => [group.id, group.name])), [groups.data]);
  const cards = useMemo(() => {
    const list: AccountCard[] = [];
    if (platform !== "openai") for (const row of credentials.data ?? []) list.push(anthropicCard(row, todayMap));
    if (platform !== "anthropic") for (const row of openaiAccounts.data?.data ?? []) list.push(openaiCard(row, todayMap));
    const needle = search.trim().toLocaleLowerCase(locale);
    return list.filter((card) => (bucket === "all" || card.bucket === bucket)
      && (!groupFilter || card.groupId === groupFilter)
      && (!needle || `${card.name} ${card.id}`.toLocaleLowerCase(locale).includes(needle)));
  }, [credentials.data, openaiAccounts.data, todayMap, platform, bucket, groupFilter, search, locale]);
  const pager = usePagination(cards);
  const busy = useMutation({
    mutationFn: async (action: "cooldown" | "refresh" | "disable" | "enable") => {
      const reason = t("accounts.bulk.reason");
      let ok = 0;
      let failed = 0;
      for (const card of cards.filter((item) => selected.has(item.key))) {
        try {
          if (card.provider === "anthropic") {
            const base = `/admin/v1/credentials/${encodeURIComponent(card.id)}`;
            if (action === "cooldown") await api(base + ":clear-cooldown", { method: "POST", headers: { "If-Match": `"rev-${card.revision}"` }, body: JSON.stringify({ reason }) });
            else if (action === "refresh") await api(base + ":refresh-token", { method: "POST", headers: { "If-Match": `"rev-${card.revision}"` }, body: JSON.stringify({ reason }) });
            else if (action === "disable") await api(base + ":disable", { method: "POST", headers: { "If-Match": `"rev-${card.revision}"` }, body: JSON.stringify({ reason }) });
            else await api(base + ":reactivate", { method: "POST", headers: { "If-Match": `"rev-${card.revision}"` }, body: JSON.stringify({ reason }) });
          } else {
            const row = asOpenAi(card.raw);
            if (action === "refresh") await api(`/admin/v1/openai/accounts/${encodeURIComponent(card.id)}:refresh`, { method: "POST", headers: { "If-Match": `"rev-${row.revision}"` }, body: "{}" });
            else await api(`/admin/v1/openai/accounts/${encodeURIComponent(card.id)}`, { method: "PATCH", headers: { "If-Match": `"rev-${row.revision}"` }, body: JSON.stringify({ name: row.name, enabled: action === "enable", max_concurrency: row.max_concurrency, priority: row.priority, websocket_enabled: row.websocket_enabled, models: row.models }) });
          }
          ok += 1;
        } catch { failed += 1; }
      }
      return { ok, failed };
    },
    onSuccess: ({ ok, failed }) => {
      toast.success(t("accounts.bulk.done", { ok, failed }));
      setSelected(new Set());
      void cache.invalidateQueries({ queryKey: ["/admin/v1/credentials"] });
      void cache.invalidateQueries({ queryKey: ["/admin/v1/openai/accounts"] });
    },
    onError: () => toast.error(t("common.operationFailed")),
  });
  const probe = useMutation({
    mutationFn: (card: AccountCard) => api(`/admin/v1/credentials/${encodeURIComponent(card.id)}:probe-usage`, { method: "POST", headers: { "If-Match": `"rev-${card.revision}"` }, body: "{}" }),
    onSuccess: () => { toast.success(t("accounts.probe.done")); void cache.invalidateQueries({ queryKey: ["/admin/v1/credentials"] }); },
    onError: () => toast.error(t("accounts.probe.failed")),
  });
  function toggleSelect(key: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }
  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
  }
  const filters = <form className="filter-rail" onSubmit={applyFilters}>
    <div className="field"><label htmlFor="account-search">{t("accounts.filter.search")}</label><input id="account-search" className="inp" value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("accounts.filter.searchPlaceholder")} /></div>
    <div className="field"><label htmlFor="account-platform">{t("accounts.filter.platform")}</label><SelectField id="account-platform" value={platform} onChange={(value) => setPlatform(value as "all" | "anthropic" | "openai")} options={[{ value: "all", label: t("accounts.filter.all") }, { value: "anthropic", label: "Anthropic" }, { value: "openai", label: "OpenAI" }]} /></div>
    <div className="field"><label htmlFor="account-state">{t("accounts.filter.state")}</label><SelectField id="account-state" value={bucket} onChange={(value) => setBucket(value as "all" | StateBucket)} options={([["all", "accounts.filter.all"], ["normal", "accounts.state.normal"], ["cooldown", "accounts.state.cooldown"], ["blocked", "accounts.state.blocked"], ["auth", "accounts.filter.auth"], ["pending", "accounts.filter.pending"], ["disabled", "accounts.state.disabled"]] as const).map(([value, key]) => ({ value, label: t(key) }))} /></div>
    <div className="field"><label htmlFor="account-group">{t("accounts.filter.group")}</label><SelectField id="account-group" value={groupFilter} onChange={setGroupFilter} options={[{ value: "", label: t("accounts.filter.all") }, ...(groups.data ?? []).map((group) => ({ value: group.id, label: group.name }))]} /></div>
    <div className="field"><label htmlFor="account-refresh">{t("accounts.filter.refresh")}</label><SelectField id="account-refresh" value={String(autoRefresh)} onChange={(value) => setAutoRefresh(Number(value))} options={[{ value: "0", label: t("accounts.filter.off") }, { value: "10", label: t("accounts.filter.seconds", { value: 10 }) }, { value: "30", label: t("accounts.filter.seconds", { value: 30 }) }, { value: "60", label: t("accounts.filter.seconds", { value: 60 }) }]} /></div>
    <button type="submit" className="btn btn-ghost">{t("request.apply")}</button>
  </form>;
  const bulkBar = selected.size > 0 && <div className="account-bulk" role="toolbar" aria-label={t("accounts.bulk.label")}>
    <span className="mono">{t("accounts.bulk.selected", { count: selected.size })}</span>
    <button type="button" className="btn btn-outline btn-sm" disabled={busy.isPending} onClick={() => busy.mutate("cooldown")}>{t("accounts.bulk.clearCooldown")}</button>
    <button type="button" className="btn btn-outline btn-sm" disabled={busy.isPending} onClick={() => busy.mutate("refresh")}>{t("accounts.bulk.refresh")}</button>
    <button type="button" className="btn btn-outline btn-sm" disabled={busy.isPending} onClick={() => busy.mutate("enable")}>{t("accounts.bulk.enable")}</button>
    <button type="button" className="btn btn-danger btn-sm" disabled={busy.isPending} onClick={() => busy.mutate("disable")}>{t("accounts.bulk.disable")}</button>
    <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set())}>{t("common.cancel")}</button>
  </div>;
  return <div className="page-stack">
    <header className="page-heading">
      <div><p className="eyebrow mono">{t("accounts.eyebrow")}</p><h1>{t("nav.accounts")}</h1><p>{t("accounts.description")}</p></div>
      <span className="tag t-gray mono">{t("accounts.count", { count: cards.length })}</span>
    </header>
    {(credentials.isError ?? openaiAccounts.isError ?? today.isError) && <div className="alert alert-warn" role="alert"><Icon name="alert" /><div><div className="at">{t("error.loadTitle")}</div></div></div>}
    <div className="segmented local" role="group" aria-label={t("accounts.view")}>
      <button type="button" className={view === "cards" ? "active" : ""} onClick={() => setView("cards")}>{t("accounts.viewCards")}</button>
      <button type="button" className={view === "table" ? "active" : ""} onClick={() => setView("table")}>{t("accounts.viewTable")}</button>
    </div>
    {filters}
    {bulkBar}
    <section className="card table-card" aria-busy={credentials.isLoading}>
      <div className="cardbar">
        <div className="cbl"><h2>{t("nav.accounts")}</h2><span className="tag t-gray">{t("accounts.autoNote")}</span></div>
        <div className="cbr">
          <button type="button" className="btn btn-primary btn-sm" onClick={() => { setAddInitial("pick"); setAddOpen(true); }}><Icon name="plus" />{t("accounts.action.add")}</button>
          <button className={`ibtn outline${credentials.isFetching || openaiAccounts.isFetching ? " loading" : ""}`} type="button" aria-label={t("table.refresh")} onClick={() => { void credentials.refetch(); void openaiAccounts.refetch(); void today.refetch(); }}><Icon name="refresh" /></button>
        </div>
      </div>
      {credentials.isLoading || openaiAccounts.isLoading ? <div className="loading-lines"><span className="skel title" /><span className="skel line" /><span className="skel line" /></div>
        : cards.length === 0 ? <div className="empty"><div className="empty-orbit"><Icon name="inbox" /></div><h3>{t("accounts.emptyTitle")}</h3><p>{t("accounts.emptyBody")}</p></div>
          : view === "cards"
            ? <><div className="account-grid">{pager.pageRows.map((card) => <AccountCardView key={card.key} card={card} groupName={groupName.get(card.groupId)} locale={locale} t={t}
              selected={selected.has(card.key)} onSelect={() => toggleSelect(card.key)}
              rowActions={card.provider === "anthropic" ? rowActions : undefined}
              onStats={() => setStats({ provider: card.provider, id: card.id, name: card.name })}
              onProbe={() => probe.mutate(card)} probeBusy={probe.isPending}
              openai={{ editing: openaiActions.editing?.id === card.id, onEdit: () => openaiActions.setEditing(asOpenAi(card.raw)), onReplace: () => { openaiActions.setReplace(asOpenAi(card.raw)); openaiActions.setKind(asOpenAi(card.raw).auth_kind); setAddInitial("openai"); setAddOpen(true); }, onToggle: () => openaiActions.accountAction.mutate({ account: asOpenAi(card.raw), test: false }), onRefresh: () => openaiActions.refresh.mutate(asOpenAi(card.raw)), onTest: () => openaiActions.accountAction.mutate({ account: asOpenAi(card.raw), test: true }), busy: openaiActions.accountAction.isPending || openaiActions.refresh.isPending }} />)}</div>
              <TablePager page={pager.page} pageCount={pager.pageCount} total={pager.total} onPage={pager.setPage} /></>
            : <AccountTable cards={pager.pageRows} groupName={groupName} locale={locale} t={t} onStats={(card) => setStats({ provider: card.provider, id: card.id, name: card.name })} />}
    </section>
    {rowDialogs}
    {stats && <AccountStatsModal provider={stats.provider} id={stats.id} name={stats.name} onClose={() => setStats(null)} />}
    <AddAccountDialog open={addOpen} initialPlatform={addInitial} onClose={() => setAddOpen(false)} groups={groups.data} openai={openaiActions} />
  </div>;
}

function CardStatus({ card, locale, t }: { card: AccountCard; locale: Locale; t: (key: MessageKey, vars?: Record<string, string | number>) => string }) {
  const countdown = useCountdown(card.cooldownUntil);
  return <div className="account-status">
    <span className={`tag t-${card.tone === "gray" ? "gray" : card.tone} dotled`}>{t(card.stateKey)}</span>
    {countdown.active && <span className="tag t-coral mono">{t("accounts.state.countdown", { value: formatCountdown(countdown.secondsLeft, locale) })}</span>}
    {card.openaiLimited && <span className="tag t-amber">{t("accounts.state.limited")}</span>}
    {card.lastError && <span className="account-error" data-tip={card.lastError}><Icon name="warning" />{card.lastError.slice(0, 42)}{card.lastError.length > 42 ? "…" : ""}</span>}
  </div>;
}

function CardMeters({ card, t }: { card: AccountCard; t: (key: MessageKey) => string }) {
  if (card.provider === "anthropic") {
    const five = card.windows.fiveHour;
    const seven = card.windows.sevenDay;
    if (!five && !seven) return null;
    return <div className="account-meters">
      {five && <Meter label={t("accounts.window.fiveHour")} value={five.utilization} note={five.resets_at ? `${t("accounts.window.resets")} ${formatDateTime(five.resets_at, "zh-CN")}` : undefined} />}
      {seven && <Meter label={t("accounts.window.sevenDay")} value={seven.utilization} note={seven.resets_at ? `${t("accounts.window.resets")} ${formatDateTime(seven.resets_at, "zh-CN")}` : undefined} />}
    </div>;
  }
  return null;
}

function AccountCardView({ card, groupName, locale, t, selected, onSelect, rowActions, onStats, onProbe, probeBusy, openai }: {
  card: AccountCard; groupName: string | undefined; locale: Locale; t: (key: MessageKey, vars?: Record<string, string | number>) => string;
  selected: boolean; onSelect(): void; rowActions: ReturnType<typeof useResourceRowActions>["rowActions"] | undefined;
  onStats(): void; onProbe(): void; probeBusy: boolean;
  openai: { editing: boolean; onEdit(): void; onReplace(): void; onToggle(): void; onRefresh(): void; onTest(): void; busy: boolean };
}) {
  return <article className={`account-card tone-${card.tone}${openai.editing ? " editing" : ""}`}>
    <header className="account-card-head">
      <label className="check-row account-select"><input type="checkbox" checked={selected} onChange={onSelect} aria-label={t("accounts.select")} /></label>
      <div className="account-title">
        <b>{card.name}</b>
        <small className="mono">{card.badge} · {groupName ?? card.groupId.slice(0, 8)}</small>
      </div>
      <span className={`tag t-${card.tone === "gray" ? "gray" : card.tone} dotled`}>{t(card.stateKey)}</span>
    </header>
    <CardStatus card={card} locale={locale} t={t} />
    <CardMeters card={card} t={t} />
    <dl className="account-meta">
      <div><dt>{t("accounts.today.requests")}</dt><dd>{formatCount(card.today?.request_count, locale)}</dd></div>
      <div><dt>{t("accounts.today.tokens")}</dt><dd>{card.today == null ? "—" : formatCount((card.today.input_tokens ?? 0) + (card.today.output_tokens ?? 0), locale)}</dd></div>
      <div><dt>{t("accounts.today.amount")}</dt><dd>{formatAmount(card.today?.estimated_amount)}</dd></div>
      <div><dt>{t("accounts.meta.capacity")}</dt><dd className="mono">{card.concurrency ?? "—"} · P{card.priority ?? "—"}</dd></div>
      <div><dt>{t("accounts.meta.egress")}</dt><dd className="mono">{card.egress ?? "—"}</dd></div>
      <div><dt>{t("accounts.meta.updated")}</dt><dd>{formatRelative(card.updatedAt, locale)}</dd></div>
    </dl>
    <footer className="account-card-foot">
      <button type="button" className="btn btn-outline btn-sm" onClick={onStats}>{t("accounts.action.stats")}</button>
      {card.provider === "anthropic" && <button type="button" className="btn btn-outline btn-sm" disabled={probeBusy} onClick={onProbe}>{t("accounts.action.probe")}</button>}
      {card.provider === "openai" && <>
        <button type="button" className="btn btn-outline btn-sm" onClick={openai.onEdit}>{t("openai.edit")}</button>
        <button type="button" className="btn btn-outline btn-sm" onClick={openai.onReplace}>{t("openai.replace")}</button>
        {card.refreshable && <button type="button" className="btn btn-outline btn-sm" disabled={openai.busy} onClick={openai.onRefresh}>{t("openai.refresh")}</button>}
        <button type="button" className="btn btn-outline btn-sm" disabled={openai.busy} onClick={openai.onTest}>{t("openai.test")}</button>
        <button type="button" className="btn btn-outline btn-sm" disabled={openai.busy || (!card.enabled && !(asOpenAi(card.raw)).verified_at)} onClick={openai.onToggle}>{t(card.enabled ? "openai.disable" : "openai.enable")}</button>
      </>}
      {rowActions && rowActions.length > 0 && <RowActionsCell row={card.raw} actions={rowActions} />}
    </footer>
  </article>;
}

function AccountTable({ cards, groupName, locale, t, onStats }: { cards: AccountCard[]; groupName: Map<string, string>; locale: Locale; t: (key: MessageKey, vars?: Record<string, string | number>) => string; onStats(card: AccountCard): void }) {
  return <div className="tbl-wrap"><table className="tbl accounts-table">
    <caption className="sr-only">{t("nav.accounts")}</caption>
    <thead><tr>
      <th scope="col">{t("action.group.name")}</th><th scope="col">{t("accounts.filter.platform")}</th>
      <th scope="col">{t("accounts.filter.state")}</th><th scope="col">{t("accounts.window.fiveHour")}</th>
      <th scope="col">{t("accounts.window.sevenDay")}</th><th scope="col">{t("accounts.today.requests")}</th>
      <th scope="col">{t("accounts.meta.capacity")}</th><th scope="col">{t("accounts.meta.updated")}</th>
      <th scope="col">{t("table.actions")}</th>
    </tr></thead>
    <tbody>{cards.map((card) => <tr key={card.key}>
      <td><b>{card.name}</b><small className="mono"> · {groupName.get(card.groupId) ?? card.groupId.slice(0, 8)}</small></td>
      <td className="mono">{card.provider}</td>
      <td><CardStatus card={card} locale={locale} t={t} /></td>
      <td>{card.windows.fiveHour ? <Meter label={t("accounts.window.fiveHour")} value={card.windows.fiveHour.utilization} /> : "—"}</td>
      <td>{card.windows.sevenDay ? <Meter label={t("accounts.window.sevenDay")} value={card.windows.sevenDay.utilization} /> : "—"}</td>
      <td>{formatCount(card.today?.request_count, locale)}</td>
      <td className="mono">{card.concurrency ?? "—"} · P{card.priority ?? "—"}</td>
      <td>{formatRelative(card.updatedAt, locale)}</td>
      <td><button type="button" className="btn btn-outline btn-sm" onClick={() => onStats(card)}>{t("accounts.action.stats")}</button></td>
    </tr>)}</tbody>
  </table></div>;
}
