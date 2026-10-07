import { ReactNode } from "react";
import { ApiError } from "./api";
import { Icon } from "./detail-kit";
import { columnLabel, displayCell } from "./display";
import { Locale, useI18n } from "./i18n";
import { TablePager, usePagination } from "./pagination";
import { RowActionDef, RowActionsCell } from "./row-actions";
import { useCompactLayout } from "./use-compact-layout";

/* ============================================================
   通用资源表格与错误态:App 各页面与 CredentialsPage 共用
   ============================================================ */

export function ResourceTable({ loading, items, title, rowActions, columnKeys, renderCell, onRefresh, refreshing = false, toolbar, tableClassName = "" }: { tableClassName?: string; loading: boolean; items?: unknown[]; title: string; rowActions?: RowActionDef<Record<string, unknown>>[]; columnKeys?: string[]; renderCell?: (column: string, record: Record<string, unknown>) => ReactNode; onRefresh?: () => void; refreshing?: boolean; toolbar?: ReactNode }) {
  const { locale, t } = useI18n();
  const compact = useCompactLayout();
  const records = (items ?? []).filter((item): item is Record<string, unknown> => typeof item === "object" && item !== null);
  const columns = (columnKeys && columnKeys.length > 0) ? columnKeys.filter((key) => records.some((record) => key in record)) : Array.from(new Set(records.flatMap((record) => Object.keys(record)))).slice(0, 6);
  const pager = usePagination(records);
  const cardCells = (record: Record<string, unknown>) => columns.map((column) => ({ column, content: renderCell ? renderCell(column, record) : displayCell(record[column], locale) }));
  return <section className="card table-card" aria-busy={loading}><div className="cardbar"><div className="cbl"><h2>{title}</h2><span className="tag t-gray">{t("table.stableSort")}</span></div><div className="cbr">{toolbar}{onRefresh && <button className={`ibtn outline${refreshing ? " loading" : ""}`} type="button" aria-label={t("table.refresh")} disabled={refreshing} onClick={onRefresh}><Icon name="refresh" /></button>}</div></div>{loading ? <div className="loading-lines"><span className="skel title" /><span className="skel line" /><span className="skel line" /></div> : records.length === 0 ? <div className="empty"><div className="empty-orbit"><Icon name="inbox" /></div><h3>{t("table.emptyTitle")}</h3><p>{t("table.emptyBody")}</p></div> : <>{compact ? <div className="tbl-cards">{pager.pageRows.map((record, index) => { const cells = cardCells(record); const [first, ...rest] = cells; const statusCell = rest.find((cell) => cell.column === "status"); const gridCells = statusCell ? rest.filter((cell) => cell !== statusCell) : rest; return <article className="tbl-card" key={String(record.id ?? index)}><header className="tbl-card-head"><div className="tbl-card-title">{first?.content}</div>{statusCell && <div className="tbl-card-status">{statusCell.content}</div>}</header>{gridCells.length > 0 && <dl className="tbl-card-grid">{gridCells.map(({ column, content }) => <div key={column}><dt>{columnLabel(column, locale)}</dt><dd className="mono">{content}</dd></div>)}</dl>}{rowActions && rowActions.length > 0 && <footer className="tbl-card-foot"><RowActionsCell row={record} actions={rowActions} /></footer>}</article>; })}</div>
  : <div className="tbl-wrap"><table className={`tbl ${tableClassName}`}><caption className="sr-only">{t("table.caption", { title, count: records.length })}</caption><thead><tr>{columns.map((column) => <th key={column} scope="col">{columnLabel(column, locale)}</th>)}{rowActions && rowActions.length > 0 && <th scope="col" className="row-actions-heading">{t("table.actions")}</th>}</tr></thead><tbody>{pager.pageRows.map((record, index) => <tr key={String(record.id ?? index)}>{columns.map((column) => <td key={column} className="mono">{renderCell ? renderCell(column, record) : displayCell(record[column], locale)}</td>)}{rowActions && rowActions.length > 0 && <td><RowActionsCell row={record} actions={rowActions} /></td>}</tr>)}</tbody></table></div>}<TablePager page={pager.page} pageCount={pager.pageCount} total={pager.total} onPage={pager.setPage} /></>}</section>;
}

export function ErrorState({ error }: { error: Error }) {
  const { t } = useI18n();
  const status = error instanceof ApiError ? error.status : 0;
  const message = error instanceof ApiError && error.message === "request_failed" ? t("common.requestFailed") : error.message;
  return <div className="alert alert-warn" role="alert"><Icon name="alert" /><div><div className="at">{t("error.loadTitle")}</div><div className="ad">{status ? t("common.http", { status, message }) : message}</div></div></div>;
}
