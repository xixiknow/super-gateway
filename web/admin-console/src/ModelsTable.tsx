import { ReactNode, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { CapabilityWorkbench } from "./CapabilityWorkbench";
import { Drawer } from "./drawer";
import { useI18n } from "./i18n";
import { RowActionDef, RowActionsCell } from "./row-actions";
import { TablePager, usePagination } from "./pagination";

type RecordRow = Record<string, unknown>;

interface ModelsTableProps {
  loading: boolean;
  items?: unknown[];
  title: string;
  rowActions?: RowActionDef<RecordRow>[];
  onRefresh(): void;
  refreshing?: boolean;
  toolbar?: ReactNode;
}

const sourceLabels = {
  "zh-CN": {
    anthropic_public_docs: "Anthropic 公开目录",
    anthropic_models_api: "凭据验证",
    builtin_snapshot: "内置目录快照",
    unknown: "未知",
  },
  "en-US": {
    anthropic_public_docs: "Anthropic public catalog",
    anthropic_models_api: "Credential verified",
    builtin_snapshot: "Built-in catalog snapshot",
    unknown: "Unknown",
  },
} as const;

const lifecycleLabels = {
  "zh-CN": { discovered: "已发现", reviewing: "审核中", published: "已发布", deprecated: "已弃用", disabled: "已禁用", active: "活跃", candidate: "候选", retired: "已退役" },
  "en-US": { discovered: "Discovered", reviewing: "Reviewing", published: "Published", deprecated: "Deprecated", disabled: "Disabled", active: "Active", candidate: "Candidate", retired: "Retired" },
} as const;

function text(row: RecordRow, key: string): string {
  const value = row[key];
  return value === null || value === undefined ? "" : String(value);
}

function number(row: RecordRow, key: string): number | null {
  const value = row[key];
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;
}

function object(value: unknown): RecordRow | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as RecordRow : null;
}

function tokenCount(value: number | null, locale: string): string {
  if (value === null) return "—";
  if (value % 1_000_000 === 0) return `${value / 1_000_000}M`;
  if (value % 1_000 === 0) return `${value / 1_000}K`;
  return new Intl.NumberFormat(locale).format(value);
}

function displayDate(value: string, locale: string): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString(locale, { year: "numeric", month: "2-digit", day: "2-digit" });
}

function stateLabel(value: string, locale: "zh-CN" | "en-US"): string {
  const labels = lifecycleLabels[locale] as Record<string, string>;
  return labels[value] ?? value.replaceAll("_", " ");
}

function capabilityValue(key: string, value: unknown, locale: "zh-CN" | "en-US"): string {
  if (value === null || value === undefined || value === "") return "—";
  if (key === "catalog_status" && value === "current") return locale === "zh-CN" ? "当前型号" : "Current";
  if (key === "catalog_status" && value === "legacy_available") return locale === "zh-CN" ? "仍可用旧型号" : "Legacy, still available";
  if (value === "not_supported") return locale === "zh-CN" ? "不支持" : "Not supported";
  if (key === "profile_completeness" && value === "complete") return locale === "zh-CN" ? "完整" : "Complete";
  if (key === "profile_completeness" && value === "partial") return locale === "zh-CN" ? "部分" : "Partial";
  if (Array.isArray(value)) return value.length > 0 ? value.join(" · ") : "—";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

export function ModelsTable({ loading, items, title, rowActions, onRefresh, refreshing = false, toolbar }: ModelsTableProps) {
  const { locale, t } = useI18n();
  const records = (items ?? []).filter((item): item is RecordRow => typeof item === "object" && item !== null);
  const pager = usePagination(records);
  const [selectedRow, setSelectedRow] = useState<RecordRow | null>(null);
  const drawerTrigger = useRef<HTMLButtonElement | null>(null);
  const capabilityVersions = useQuery({
    queryKey: ["/admin/v1/capability-versions"],
    queryFn: () => api<unknown[]>("/admin/v1/capability-versions"),
    enabled: records.length > 0,
    retry: false,
  });
  const versions = (capabilityVersions.data ?? []).filter((item): item is RecordRow => typeof item === "object" && item !== null);
  const hasActions = Boolean(rowActions?.length);
  const selectedVersions = selectedRow
    ? versions.filter((version) => text(version, "model_id") === text(selectedRow, "id")).sort((left, right) => Number(right.capability_version ?? 0) - Number(left.capability_version ?? 0))
    : [];
  function closeDrawer() {
    setSelectedRow(null);
    requestAnimationFrame(() => drawerTrigger.current?.focus());
  }

  return <section className="card table-card models-table-card" aria-busy={loading}>
    <div className="cardbar"><div className="cbl"><h2>{title}</h2><span className="tag t-gray">{t("table.stableSort")}</span></div><div className="cbr">{toolbar}<button className={`ibtn outline${refreshing ? " loading" : ""}`} type="button" aria-label={t("table.refresh")} disabled={refreshing} onClick={onRefresh}><svg className="icon sm" aria-hidden="true"><use href="#i-refresh" /></svg></button></div></div>
    {loading
      ? <div className="loading-lines"><span className="skel title" /><span className="skel line" /><span className="skel line" /></div>
      : records.length === 0
        ? <div className="empty"><div className="empty-orbit"><svg className="icon sm" aria-hidden="true"><use href="#i-inbox" /></svg></div><h3>{t("table.emptyTitle")}</h3><p>{t("table.emptyBody")}</p></div>
        : <><div className="tbl-wrap"><table className="tbl models-table"><caption className="sr-only">{t("table.caption", { title, count: records.length })}</caption><thead><tr>
          <th scope="col">{t("models.column.model")}</th><th scope="col">{t("models.column.source")}</th><th scope="col">{t("models.column.publicCapability")}</th><th scope="col">{t("models.column.lifecycle")}</th><th scope="col">{t("models.column.gatewayCapability")}</th><th scope="col">{t("models.column.releasedAt")}</th><th scope="col" className="capability-toggle-heading">{t("models.capability.open")}</th>{hasActions && <th scope="col" className="row-actions-heading">{t("table.actions")}</th>}
        </tr></thead><tbody>{pager.pageRows.map((row, index) => {
          const id = text(row, "id") || String(index);
          const input = number(row, "max_input_tokens");
          const output = number(row, "max_output_tokens");
          const source = text(row, "source") || "unknown";
          const lifecycle = text(row, "lifecycle");
          const activeVersion = row.capability_version;
          const activeState = text(row, "capability_state");
          return <tr key={id}>
              <td><div className="model-identity"><strong>{text(row, "display_name") || "—"}</strong><code>{text(row, "upstream_model_id") || "—"}</code></div></td>
              <td><span className={`model-source source-${source}`}>{(sourceLabels[locale] as Record<string, string>)[source] ?? source}</span></td>
              <td><div className="capability-inline"><b>{tokenCount(input, locale)}</b><span>{t("models.capability.context")}</span><i aria-hidden="true" /><b>{tokenCount(output, locale)}</b><span>{t("models.capability.output")}</span></div></td>
              <td><span className={`model-lifecycle state-${lifecycle}`}>{stateLabel(lifecycle, locale)}</span></td>
              <td>{activeVersion === null || activeVersion === undefined ? <span className="muted">—</span> : <span className="gateway-version"><b>v{String(activeVersion)}</b><small>{stateLabel(activeState, locale)}</small></span>}</td>
              <td><time className="model-seen" dateTime={text(row, "released_at")}>{displayDate(text(row, "released_at"), locale)}</time></td>
              <td className="capability-toggle-cell"><button type="button" className="capability-toggle" aria-haspopup="dialog" aria-label={`${t("models.capability.open")} · ${text(row, "display_name")}`} onClick={(event) => { drawerTrigger.current = event.currentTarget; setSelectedRow(row); }}>→</button></td>
              {hasActions && <td><RowActionsCell row={row} actions={rowActions ?? []} /></td>}
            </tr>;
        })}</tbody></table></div><TablePager page={pager.page} pageCount={pager.pageCount} total={pager.total} onPage={(page) => { setSelectedRow(null); pager.setPage(page); }} /></>}
    {selectedRow && <CapabilityDrawer row={selectedRow} versions={selectedVersions} versionsLoading={capabilityVersions.isLoading} versionsError={capabilityVersions.isError} onClose={closeDrawer} />}
  </section>;
}

function CapabilityDrawer({ row, versions, versionsLoading, versionsError, onClose }: { row: RecordRow; versions: RecordRow[]; versionsLoading: boolean; versionsError: boolean; onClose(): void }) {
  return <Drawer className="capability-drawer" eyebrow="MODEL CAPABILITY" title={text(row, "display_name")} subtitle={text(row, "upstream_model_id")} onRequestClose={onClose}>
    <ModelCapabilityPanel id={`model-capability-${text(row, "id")}`} row={row} versions={versions} versionsLoading={versionsLoading} versionsError={versionsError} />
  </Drawer>;
}

function ModelCapabilityPanel({ id, row, versions, versionsLoading, versionsError }: { id: string; row: RecordRow; versions: RecordRow[]; versionsLoading: boolean; versionsError: boolean }) {
  const { locale, t } = useI18n();
  const provider = object(row.provider_capabilities);
  const labels: Record<string, string> = {
    catalog_status: t("models.capability.catalogStatus"),
    thinking: t("models.capability.thinking"),
    default_effort: t("models.capability.defaultEffort"),
    thinking_modes: t("models.capability.thinkingModes"),
    effort_levels: t("models.capability.effortLevels"),
    sampling_profile: t("models.capability.samplingProfile"),
    profile_completeness: t("models.capability.profileCompleteness"),
    profile_version: t("models.capability.profileVersion"),
  };
  return <div className="model-capability-panel" id={id}>
    <section className="provider-capability-block"><header><div><p className="eyebrow mono">PROVIDER</p><h3>{t("models.capability.provider")}</h3></div><p>{t("models.capability.providerHint")}</p></header><dl className="capability-metrics"><div><dt>{t("models.capability.context")}</dt><dd>{tokenCount(number(row, "max_input_tokens"), locale)} <small>tokens</small></dd></div><div><dt>{t("models.capability.output")}</dt><dd>{tokenCount(number(row, "max_output_tokens"), locale)} <small>tokens</small></dd></div>{provider && Object.entries(provider).map(([key, value]) => <div key={key}><dt>{labels[key] ?? key.replaceAll("_", " ")}</dt><dd>{capabilityValue(key, value, locale)}</dd></div>)}</dl></section>
    <section className="gateway-capability-block"><header><div><p className="eyebrow mono">GATEWAY</p><h3>{t("models.capability.gateway")}</h3></div><p>{t("models.capability.gatewayHint")}</p></header><CapabilityWorkbench modelId={text(row, "id")} modelRevision={Number(row.revision ?? 1)} maxOutputTokens={number(row, "max_output_tokens")} versions={versions} loading={versionsLoading} error={versionsError} /></section>
  </div>;
}
