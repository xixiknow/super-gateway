import { useState } from "react";
import { useToast } from "./feedback";
import { useI18n } from "./i18n";

const beijingTime = new Intl.DateTimeFormat("en-GB", {
  timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
});

export function formatRequestTime(value: unknown): string {
  if (value == null || value === "") return "—";
  // PostgreSQL text timestamps may use a space and an hour-only UTC offset.
  const normalized = typeof value === "string" ? value.replace(" ", "T").replace(/([+-]\d{2})$/, "$1:00") : value;
  if (typeof normalized !== "string" && typeof normalized !== "number") return "—";
  // Never interpret a timezone-less server value using the browser's local zone.
  if (typeof normalized === "string" && !/(Z|[+-]\d{2}:?\d{2})$/i.test(normalized)) return "—";
  const date = new Date(normalized);
  if (!Number.isFinite(date.getTime())) return "—";
  const parts = Object.fromEntries(beijingTime.formatToParts(date).map(({ type, value: part }) => [type, part]));
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
}

export function formatRequestDuration(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "—";
  return value < 1000 ? `${Math.round(value)} ms` : `${(value / 1000).toFixed(2)} s`;
}

export function requestClient(record: Record<string, unknown>, locale: string): string {
  const name = typeof record.client_name === "string" && record.client_name
    ? record.client_name : record.client_class === "claude_code_cli" ? "Claude Code" : locale === "zh-CN" ? "未知客户端" : "Unknown client";
  return `${name} ${typeof record.client_version === "string" && record.client_version ? record.client_version : "—"}`;
}

export function RequestMetrics({ record }: { record: Record<string, unknown> }) {
  const { t } = useI18n();
  const first = record.request_type === "streaming" || record.request_type === "websocket";
  const rate = typeof record.tps === "number" && Number.isFinite(record.tps) && record.tps >= 0 ? `${record.tps.toFixed(1)} token/s` : "—";
  return <dl className="request-metrics-grid" title={t(record.request_type === "sync" ? "request.timing.syncHint" : "request.timing.streamHint")}>
    {first && <div><dt>{t("request.timing.first")}</dt><dd>{formatRequestDuration(record.first_content_ms)}</dd></div>}
    <div><dt>{t("request.timing.total")}</dt><dd>{formatRequestDuration(record.duration_ms)}</dd></div>
    <div><dt>TPS</dt><dd>{rate}{record.tps_estimated === true && <small> · {t("request.timing.estimated")}</small>}</dd></div>
  </dl>;
}

export function CopyRequestContent({ text, label }: { text: string | null; label: string }) {
  const { t } = useI18n();
  const toast = useToast();
  async function copy() {
    if (text === null) return;
    try {
      await navigator.clipboard.writeText(text);
      toast.success(t("request.copySuccess"));
    } catch {
      toast.error(t("request.copyFailed"));
    }
  }
  return <button type="button" className="btn btn-ghost" disabled={text === null} aria-label={t("request.copyLabel", { label })} onClick={() => void copy()}>{t("request.copy")}</button>;
}

export interface HeaderSnapshot {
  entries: { name: string; value: string; redacted: boolean }[];
  captured_at_ms: number;
  transport: "http" | "websocket_handshake";
  reused: boolean;
  attempt_ordinal: number | null;
  truncated: boolean;
}

export interface RequestCapture extends Record<string, unknown> {
  original_headers?: HeaderSnapshot | null;
  final_upstream_headers?: HeaderSnapshot | null;
  upstream_response_headers?: HeaderSnapshot | null;
}

export function RequestHeaders({ capture, loading, failed }: { capture?: RequestCapture; loading: boolean; failed: boolean }) {
  const { t } = useI18n();
  const [tab, setTab] = useState<"original_headers" | "final_upstream_headers" | "upstream_response_headers">("original_headers");
  const snapshot = capture?.[tab];
  const text = snapshot ? snapshot.entries.map(({ name, value }) => `${name}: ${value}`).join("\n") : null;
  return <section className="request-body-panel request-headers-panel">
    <div className="section-head"><div><p className="eyebrow mono">REQUEST / HEADERS</p><h4>{t("request.headers.title")}</h4></div><CopyRequestContent text={text} label={t(`request.headers.${tab}`)} /></div>
    <div className="segmented local request-body-tabs">
      {(["original_headers", "final_upstream_headers", "upstream_response_headers"] as const).map((key) => <button type="button" key={key} className={tab === key ? "active" : ""} onClick={() => setTab(key)}>{t(`request.headers.${key}`)}</button>)}
    </div>
    {loading ? <p className="muted">{t("common.loading")}</p> : failed ? <p className="muted">{t("common.requestFailed")}</p> : !snapshot ? <p className="muted">{t("request.headers.missing")}</p> : <>
      <div className="request-header-meta"><span>{formatRequestTime(snapshot.captured_at_ms)} · {t("request.beijingTime")}</span>
        <span>{snapshot.transport === "websocket_handshake" ? t("request.headers.handshake") : "HTTP"}</span>
        {snapshot.reused && <span className="tag t-gray">{t("request.headers.reused")}</span>}
        {snapshot.attempt_ordinal != null && <span>{t("request.headers.attempt", { count: snapshot.attempt_ordinal })}</span>}
        {snapshot.truncated && <span className="tag t-amber">{t("request.headers.truncated")}</span>}
      </div>
      <p className="muted">{t("request.headers.redacted")}</p>
      <pre className="request-body-content">{text || t("request.headers.empty")}</pre>
    </>}
  </section>;
}
