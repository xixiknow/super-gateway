import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { createPortal } from "react-dom";
import { api } from "./api";
import { formatAmount, formatCount, formatDateTime } from "./format";
import { useI18n } from "./i18n";

export interface UsageSummary {
  request_count: number;
  input_tokens: number | null;
  output_tokens: number | null;
  estimated_amount: string | null;
  currency: string;
  completeness: string;
}

export interface UsageBucket {
  bucket_day: string;
  request_count: number;
  input_tokens: number | null;
  output_tokens: number | null;
  estimated_amount: string | null;
}

export interface UsageModelRow {
  model: string;
  request_count: number;
  input_tokens: number | null;
  output_tokens: number | null;
  estimated_amount: string | null;
}

export interface AccountUsage {
  credential_id: string;
  days: number;
  summary: UsageSummary;
  daily: UsageBucket[];
  models: UsageModelRow[];
}

/** Per-account usage modal: summary metrics, daily bar chart, per-model breakdown. */
export function AccountStatsModal({ provider, id, name, onClose }: { provider: "anthropic" | "openai"; id: string; name: string; onClose(): void }) {
  const { locale, t } = useI18n();
  const endpoint = provider === "anthropic"
    ? `/admin/v1/credentials/${encodeURIComponent(id)}/usage?days=30`
    : `/admin/v1/openai/accounts/${encodeURIComponent(id)}/usage?days=30`;
  const usage = useQuery({ queryKey: [endpoint], queryFn: () => api<AccountUsage>(endpoint), retry: false });
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  const data = usage.data;
  const summary = data?.summary;
  const daily = [...(data?.daily ?? [])].reverse();
  const max = Math.max(1, ...daily.map((bucket) => bucket.request_count));
  return createPortal(
    <div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section className="modal account-stats-modal" role="dialog" aria-modal="true" aria-labelledby="account-stats-title">
        <div className="modal-head">
          <div>
            <p className="eyebrow mono">{t("accounts.statsEyebrow")}</p>
            <h3 id="account-stats-title">{name}</h3>
          </div>
          <button type="button" className="ibtn outline" aria-label={t("common.close")} onClick={onClose}>×</button>
        </div>
        <div className="modal-body">
          {usage.isLoading ? <div className="loading-lines"><span className="skel title" /><span className="skel line" /><span className="skel line" /></div>
            : usage.isError ? <p role="alert" className="muted">{t("common.operationFailed")}</p>
              : summary && <>
                <dl className="account-stats-grid">
                  <div><dt>{t("accounts.stats.requests")}</dt><dd>{formatCount(summary.request_count, locale)}</dd></div>
                  <div><dt>{t("accounts.stats.inputTokens")}</dt><dd>{formatCount(summary.input_tokens, locale)}</dd></div>
                  <div><dt>{t("accounts.stats.outputTokens")}</dt><dd>{formatCount(summary.output_tokens, locale)}</dd></div>
                  <div><dt>{t("accounts.stats.amount")}</dt><dd>{formatAmount(summary.estimated_amount)}</dd></div>
                </dl>
                <div className="segmented local detail-tabs" aria-hidden="true"><button type="button" className="active">{t("accounts.stats.daily", { days: data?.days ?? 30 })}</button></div>
                {daily.length > 0 ? <svg className="usage-chart" viewBox={`0 0 ${Math.max(240, daily.length * 24)} 160`} role="img" aria-label={t("accounts.stats.chart")}>
                  {daily.map((bucket, index) => {
                    const barHeight = Math.max(2, Math.round((120 * bucket.request_count) / max));
                    return <rect key={bucket.bucket_day} x={index * 24 + 3} y={140 - barHeight} width={18} height={barHeight} rx={2} className="usage-bar">
                      <title>{`${bucket.bucket_day} · ${bucket.request_count.toLocaleString(locale)}`}</title>
                    </rect>;
                  })}
                  <text x={3} y={156}>{daily[0]?.bucket_day}</text>
                  <text x={daily.length * 24 - 3} y={156} textAnchor="end">{daily[daily.length - 1]?.bucket_day}</text>
                </svg> : <p className="muted">{t("accounts.stats.empty")}</p>}
                <h4>{t("accounts.stats.models")}</h4>
                {data.models.length === 0 ? <p className="muted">{t("accounts.stats.empty")}</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr>
                  <th scope="col">{t("accounts.stats.model")}</th><th scope="col">{t("accounts.stats.requests")}</th>
                  <th scope="col">{t("accounts.stats.inputTokens")}</th><th scope="col">{t("accounts.stats.outputTokens")}</th>
                  <th scope="col">{t("accounts.stats.amount")}</th>
                </tr></thead><tbody>{data.models.map((row) => <tr key={row.model}>
                  <td className="mono">{row.model}</td><td>{formatCount(row.request_count, locale)}</td>
                  <td>{formatCount(row.input_tokens, locale)}</td><td>{formatCount(row.output_tokens, locale)}</td>
                  <td>{formatAmount(row.estimated_amount)}</td>
                </tr>)}</tbody></table></div>}
                <p className="muted">{t("accounts.stats.note")} · {t("accounts.stats.lastBucket", { value: formatDateTime(daily[daily.length - 1]?.bucket_day, locale) })}</p>
              </>}
        </div>
        <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>{t("common.close")}</button></div>
      </section>
    </div>,
    document.body,
  );
}
