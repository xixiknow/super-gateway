import { ReactNode, useMemo, useState } from "react";
import { Locale, useI18n } from "./i18n";
import { RowActionDef, RowActionsCell } from "./row-actions";
import { TablePager, usePagination } from "./pagination";
import { SelectField } from "./select-field";
import { useCompactLayout } from "./use-compact-layout";

interface UserRecord extends Record<string, unknown> {
  id: string;
  username: string;
  display_name: string | null;
  email: string | null;
  role: "platform_admin" | "key_owner";
  status: "active" | "mfa_pending" | "disabled" | "locked" | "archived";
  last_used_at: string | null;
  max_concurrency: number;
  rpm: number;
  balance_amount: string | null;
  lifetime_spend_amount: string;
  revision: number;
}

function isUserRecord(value: unknown): value is UserRecord {
  if (!value || typeof value !== "object") return false;
  const row = value as Record<string, unknown>;
  return typeof row.id === "string" && typeof row.username === "string" && typeof row.role === "string"
    && typeof row.status === "string" && typeof row.max_concurrency === "number" && typeof row.rpm === "number";
}

function formatDate(value: string | null, locale: Locale, empty: string): string {
  return value ? new Date(value).toLocaleString(locale) : empty;
}

function formatMoney(value: string | null, locale: Locale, unlimited: string): string {
  if (value === null) return unlimited;
  const amount = Number(value);
  return Number.isFinite(amount)
    ? new Intl.NumberFormat(locale, { style: "currency", currency: "USD", maximumFractionDigits: 2 }).format(amount)
    : value;
}

export function UsersTable({
  loading, items, title, onRefresh, rowActions, refreshing = false, toolbar,
}: {
  loading: boolean;
  items?: unknown[];
  title: string;
  onRefresh(): void;
  rowActions?: RowActionDef<Record<string, unknown>>[];
  refreshing?: boolean;
  toolbar?: ReactNode;
}) {
  const { locale, t } = useI18n();
  const compact = useCompactLayout();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [role, setRole] = useState("");
  const records = (items ?? []).filter(isUserRecord);
  const filtered = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase(locale);
    return records.filter((row) => {
      const matchesQuery = !needle || [row.username, row.display_name, row.email]
        .some((value) => value?.toLocaleLowerCase(locale).includes(needle));
      return matchesQuery && (!status || row.status === status) && (!role || row.role === role);
    });
  }, [locale, query, records, role, status]);
  const pager = usePagination(filtered);
  return <section className="card table-card users-table-card" aria-busy={loading}>
    <div className="cardbar users-cardbar">
      <div className="cbl"><h2>{title}</h2><span className="tag t-gray">{t("table.stableSort")}</span></div>
      <div className="cbr">{toolbar}<button className={`ibtn outline${refreshing ? " loading" : ""}`} type="button" aria-label={t("table.refresh")} disabled={refreshing} onClick={onRefresh}><svg className="icon" aria-hidden="true"><use href="#i-refresh" /></svg></button></div>
    </div>
    <div className="table-filters" role="search" aria-label={t("user.filters.title")}>
      <label><span>{t("user.filters.search")}</span><input className="inp" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("user.filters.searchPlaceholder")} /></label>
      <label><span>{t("user.filters.status")}</span><SelectField value={status} onChange={setStatus} options={[{ value: "", label: t("user.filters.all") }, { value: "active", label: t("user.status.active") }, { value: "mfa_pending", label: t("user.status.mfa_pending") }, { value: "disabled", label: t("user.status.disabled") }, { value: "locked", label: t("user.status.locked") }, { value: "archived", label: t("user.status.archived") }]} /></label>
      <label><span>{t("user.filters.role")}</span><SelectField value={role} onChange={setRole} options={[{ value: "", label: t("user.filters.all") }, { value: "platform_admin", label: t("user.role.platform_admin") }, { value: "key_owner", label: t("user.role.key_owner") }]} /></label>
      {(query || status || role) && <button type="button" className="btn btn-ghost filter-reset" onClick={() => { setQuery(""); setStatus(""); setRole(""); }}>{t("user.filters.reset")}</button>}
    </div>
    {loading ? <div className="loading-lines"><span className="skel title" /><span className="skel line" /><span className="skel line" /></div>
      : filtered.length === 0 ? <div className="empty"><div className="empty-orbit"><svg className="icon" aria-hidden="true"><use href="#i-inbox" /></svg></div><h3>{t("table.emptyTitle")}</h3><p>{t("table.emptyBody")}</p></div>
        : <>{compact ? <div className="tbl-cards">{pager.pageRows.map((row) => <article className="tbl-card" key={row.id}><header className="tbl-card-head"><div><strong>{row.display_name || row.username}</strong><small>{row.username}{row.email ? ` · ${row.email}` : ""}</small></div><span className={`user-status ${row.status}`}><i />{t(`user.status.${row.status}`)}</span></header><dl className="tbl-card-grid"><div><dt>{t("user.column.role")}</dt><dd>{t(`user.role.${row.role}`)}</dd></div><div><dt>{t("user.column.lastUsed")}</dt><dd>{formatDate(row.last_used_at, locale, t("user.neverUsed"))}</dd></div><div><dt>{t("user.column.concurrency")}</dt><dd>{row.max_concurrency.toLocaleString(locale)}</dd></div><div><dt>{t("user.column.rpm")}</dt><dd>{row.rpm.toLocaleString(locale)}</dd></div><div className="card-field-wide"><dt>{t("user.column.balance")}</dt><dd>{formatMoney(row.balance_amount, locale, t("user.balance.unlimited"))}<small>{t("user.balance.spent", { amount: formatMoney(row.lifetime_spend_amount, locale, "—") })}</small></dd></div></dl>{rowActions && <footer className="tbl-card-foot"><RowActionsCell row={row} actions={rowActions} /></footer>}</article>)}</div>
          : <div className="tbl-wrap"><table className="tbl users-table"><caption className="sr-only">{t("table.caption", { title, count: filtered.length })}</caption><thead><tr><th scope="col">{t("user.column.user")}</th><th scope="col">{t("user.column.status")}</th><th scope="col">{t("user.column.lastUsed")}</th><th scope="col">{t("user.column.concurrency")}</th><th scope="col">{t("user.column.balance")}</th><th scope="col">{t("user.column.role")}</th><th scope="col">{t("user.column.rpm")}</th><th scope="col" className="row-actions-heading">{t("table.actions")}</th></tr></thead><tbody>{pager.pageRows.map((row) => <tr key={row.id}><td><strong>{row.display_name || row.username}</strong><small>{row.username}{row.email ? ` · ${row.email}` : ""}</small></td><td><span className={`user-status ${row.status}`}><i />{t(`user.status.${row.status}`)}</span></td><td>{formatDate(row.last_used_at, locale, t("user.neverUsed"))}</td><td>{row.max_concurrency.toLocaleString(locale)}</td><td>{formatMoney(row.balance_amount, locale, t("user.balance.unlimited"))}<small>{t("user.balance.spent", { amount: formatMoney(row.lifetime_spend_amount, locale, "—") })}</small></td><td>{t(`user.role.${row.role}`)}</td><td>{row.rpm.toLocaleString(locale)}</td><td>{rowActions && <RowActionsCell row={row} actions={rowActions} />}</td></tr>)}</tbody></table></div>}<TablePager page={pager.page} pageCount={pager.pageCount} total={pager.total} onPage={pager.setPage} /></>}
  </section>;
}
