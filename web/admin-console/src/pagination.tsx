import { useState } from "react";
import { useI18n } from "./i18n";

/* ============================================================
   客户端分页:后端列表端点当前固定 LIMIT 100 且 has_more 恒为 false,
   在服务端游标分页真正落地前,统一在前端做每页 20 条的切片分页。
   ============================================================ */

export interface Pagination<T> {
  pageRows: T[];
  page: number;
  pageCount: number;
  total: number;
  setPage(page: number): void;
}

export function usePagination<T>(rows: T[], pageSize = 20): Pagination<T> {
  const [rawPage, setPage] = useState(0);
  const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
  const page = Math.min(rawPage, pageCount - 1);
  return { pageRows: rows.slice(page * pageSize, (page + 1) * pageSize), page, pageCount, total: rows.length, setPage };
}

export function TablePager({ page, pageCount, total, onPage }: { page: number; pageCount: number; total: number; onPage(page: number): void }) {
  const { t } = useI18n();
  if (total === 0) return null;
  return (
    <div className="table-pager">
      <span>{t("table.pageInfo", { page: page + 1, pages: pageCount, count: total })}</span>
      <div className="pager">
        <button type="button" className="pg" aria-label={t("table.prevPage")} disabled={page === 0} onClick={() => onPage(page - 1)}>‹</button>
        <button type="button" className="pg" aria-label={t("table.nextPage")} disabled={page >= pageCount - 1} onClick={() => onPage(page + 1)}>›</button>
      </div>
    </div>
  );
}
