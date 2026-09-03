import { ReactNode } from "react";
import { useI18n } from "./i18n";
import { columnLabel, displayCell } from "./display";
import { rowActionError } from "./row-actions";
import { TablePager, usePagination } from "./pagination";

/* ============================================================
   详情对话框共用套件:图标 / 键值网格 / 加载与错误态 / 子资源表格
   ============================================================ */

export type Row = Record<string, unknown>;

export function Icon({ name }: { name: string }) {
  return <svg className="icon sm" aria-hidden="true"><use href={`#i-${name}`} /></svg>;
}

export function scalarEntries(record: Row): [string, unknown][] {
  return Object.entries(record).filter(([, value]) => value === null || typeof value !== "object");
}

export function DataGrid({ record, keys }: { record: Row; keys?: string[] }) {
  const { locale } = useI18n();
  const entries = keys
    ? keys.filter((key) => key in record).map((key): [string, unknown] => [key, record[key]])
    : scalarEntries(record);
  return (
    <dl className="key-data-grid">
      {entries.map(([key, value]) => (
        <div key={key}><dt>{columnLabel(key, locale)}</dt><dd className="mono breakable">{displayCell(value, locale)}</dd></div>
      ))}
    </dl>
  );
}

export function PaneStatus({ loading, error, children }: { loading: boolean; error: Error | null; children: ReactNode }) {
  const { locale, t } = useI18n();
  if (loading) return <div className="loading-lines"><span className="skel line" /><span className="skel line" /></div>;
  if (error) return <div className="alert alert-warn" role="alert"><Icon name="alert" /><div><div className="at">{t("error.loadTitle")}</div><div className="ad">{rowActionError(error, locale)}</div></div></div>;
  return <>{children}</>;
}

/** 子资源通用表格:固定列 + 分页 + 可选行尾动作 */
export function SubTable({ rows, columns, empty, rowTail }: { rows: Row[]; columns: string[]; empty: string; rowTail?: (row: Row) => ReactNode }) {
  const { locale, t } = useI18n();
  const pager = usePagination(rows);
  if (rows.length === 0) return <p className="muted">{empty}</p>;
  return (
    <>
      <div className="tbl-wrap">
        <table className="tbl">
          <thead><tr>{columns.map((column) => <th key={column} scope="col">{columnLabel(column, locale)}</th>)}{rowTail && <th scope="col" className="row-actions-heading">{t("table.actions")}</th>}</tr></thead>
          <tbody>
            {pager.pageRows.map((row, index) => (
              <tr key={String(row.id ?? index)}>
                {columns.map((column) => <td key={column} className="mono">{displayCell(row[column], locale)}</td>)}
                {rowTail && <td>{rowTail(row)}</td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <TablePager page={pager.page} pageCount={pager.pageCount} total={pager.total} onPage={pager.setPage} />
    </>
  );
}

/** 从行数据推导展示列:按偏好顺序取实际存在的标量键,不足则补充其余键 */
export function deriveColumns(rows: Row[], preferred: string[], max = 7): string[] {
  const present = new Set(rows.flatMap((row) => scalarEntries(row).map(([key]) => key)));
  const ordered = preferred.filter((key) => present.has(key));
  for (const key of present) {
    if (ordered.length >= max) break;
    if (!ordered.includes(key)) ordered.push(key);
  }
  return ordered.slice(0, max);
}
