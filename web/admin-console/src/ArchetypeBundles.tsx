import { FormEvent, useEffect, useId, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createPortal } from "react-dom";
import { ApiError, api } from "./api";
import { useToast } from "./feedback";
import { TablePager, usePagination } from "./pagination";
import { MessageKey, useI18n } from "./i18n";
import { SelectField } from "./select-field";

type View = "archetypes" | "bundles";

interface ArchetypeRecord {
  id: string;
  name: string;
  os_family: string;
  architecture: string;
  os_build?: string | null;
  lifecycle: string;
  version_id?: string | null;
  version?: number | null;
  version_lifecycle?: string | null;
  runtime?: string | null;
  runtime_version?: string | null;
  client_version?: string | null;
  profile_schema_version?: number | null;
  capture_cohort?: string | null;
  evidence_state?: string | null;
  max_credentials?: number | null;
  allocation_weight?: number | null;
  allocation_cohort?: string | null;
  revision: number;
}

interface BundleRecord {
  id: string;
  artifact_version: number;
  engine_abi_version: string;
  lifecycle: string;
  source_archetype_version_id?: string | null;
  capture_cohort?: string | null;
  protocol?: string | null;
  backend_id?: string | null;
  evidence_gate: string;
  runtime_state: string;
  engine_activation_generation: number;
  binding_state?: string | null;
  archetype_name?: string | null;
  archetype_version?: number | null;
  created_at: string;
  activated_at?: string | null;
  revision: number;
}

type CreationDialog =
  | { kind: "archetype"; base?: ArchetypeRecord }
  | { kind: "bundle" }
  | null;

type LifecycleDialog =
  | { kind: "archetype"; action: "verify" | "activate" | "retire"; row: ArchetypeRecord }
  | { kind: "bundle"; action: "verify" | "activate" | "rollback"; row: BundleRecord }
  | null;

interface BundleFileSummary {
  file: File;
  envelope: Record<string, unknown>;
  artifactVersion: string;
  sourceVersion: string;
  protocol: string;
}

function Icon({ name }: { name: string }) {
  return <svg className="icon sm" aria-hidden="true"><use href={`#i-${name}`} /></svg>;
}

function text(data: FormData, name: string): string {
  return String(data.get(name) ?? "").trim();
}

function positiveInteger(data: FormData, name: string): number {
  return Number.parseInt(text(data, name), 10);
}

function stringList(value: string): string[] {
  return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
}

function readTextFile(file: File): Promise<string> {
  if (typeof file.text === "function") return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("file_read_failed"));
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.readAsText(file);
  });
}

function describeError(error: unknown, fallback: string): string {
  if (error instanceof ApiError) return error.status ? `HTTP ${error.status} · ${error.message || fallback}` : error.message;
  return error instanceof Error ? error.message : fallback;
}

function lifecycleLabel(value: string | null | undefined, t: (key: MessageKey) => string): string {
  const normalized = value === "canary" ? "verified" : value;
  const labels: Record<string, MessageKey> = {
    draft: "bundle.status.draft",
    verified: "bundle.status.verified",
    active: "bundle.status.active",
    retired: "bundle.status.retired",
    complete: "bundle.status.complete",
    passed: "bundle.status.passed",
    pending: "bundle.status.pending",
    loadable: "bundle.status.loadable",
    candidate: "bundle.status.candidate",
  };
  return normalized ? (labels[normalized] ? t(labels[normalized]) : normalized) : "—";
}

function statusTone(value: string | null | undefined): string {
  const normalized = value === "canary" ? "verified" : value;
  if (["active", "complete", "passed", "loadable", "verified"].includes(normalized ?? "")) return "ready";
  if (["draft", "pending", "candidate"].includes(normalized ?? "")) return "waiting";
  return "muted";
}

function StatusPill({ value }: { value: string | null | undefined }) {
  const { t } = useI18n();
  return <span className={`lifecycle-pill ${statusTone(value)}`}><i />{lifecycleLabel(value, t)}</span>;
}

function WorkflowGuide() {
  const { t } = useI18n();
  const steps = [
    ["01", "bundle.workflow.archetype", "bundle.workflow.archetypeBody"],
    ["02", "bundle.workflow.evidence", "bundle.workflow.evidenceBody"],
    ["03", "bundle.workflow.bundle", "bundle.workflow.bundleBody"],
    ["04", "bundle.workflow.release", "bundle.workflow.releaseBody"],
  ] as const;
  return <section className="bundle-workflow card" aria-labelledby="bundle-workflow-title">
    <div className="bundle-workflow-intro"><p className="eyebrow mono">{t("bundle.eyebrow.workflow")}</p><h2 id="bundle-workflow-title">{t("bundle.workflow.title")}</h2><p>{t("bundle.workflow.description")}</p></div>
    <ol>{steps.map(([number, title, body]) => <li key={number}><span>{number}</span><div><b>{t(title)}</b><small>{t(body)}</small></div></li>)}</ol>
  </section>;
}

function OsCoverageOverview({ archetypes, bundles }: { archetypes: ArchetypeRecord[]; bundles: BundleRecord[] }) {
  const { t } = useI18n();
  const operatingSystems = ["windows", "macos", "linux"] as const;
  return <section className="card os-coverage" aria-labelledby="os-coverage-title">
    <div className="cardbar"><div className="cbl"><h2 id="os-coverage-title">{t("bundle.coverage.title")}</h2><span className="tag t-gray">{t("bundle.coverage.subtitle")}</span></div></div>
    <div className="os-coverage-grid">{operatingSystems.map((os) => {
      const activeArchetypes = archetypes.filter((row) => row.os_family === os && (row.lifecycle === "active" || row.version_lifecycle === "active"));
      const archetypeIds = new Set(activeArchetypes.flatMap((row) => [row.id, row.version_id].filter((value): value is string => Boolean(value))));
      const activeBundles = bundles.filter((row) => {
        const sourceId = row.source_archetype_version_id;
        return row.lifecycle === "active" && typeof sourceId === "string" && archetypeIds.has(sourceId);
      });
      const ready = activeArchetypes.length > 0 && activeBundles.length > 0;
      return <article key={os} className={`os-coverage-item ${ready ? "ready" : "missing"}`}>
        <div className="os-coverage-head"><strong>{t(`bundle.coverage.${os}` as MessageKey)}</strong><span className={`lifecycle-pill ${ready ? "ready" : "waiting"}`}><i />{ready ? t("bundle.coverage.ready") : t("bundle.coverage.missing")}</span></div>
        <p>{activeArchetypes.length > 0 ? t("bundle.coverage.archetypeBound") : t("bundle.coverage.archetypeMissing")}</p>
        <p>{activeBundles.length > 0 ? t("bundle.coverage.bundleBound") : t("bundle.coverage.bundleMissing")}</p>
        {!ready && <p><a href="/alerts">{t("bundle.coverage.openAlerts")}</a></p>}
      </article>;
    })}</div>
  </section>;
}

function ArchetypeTable({ result, onCreate, onCreateVersion, onAction }: {
  result: ReturnType<typeof useQuery<ArchetypeRecord[]>>;
  onCreate(): void;
  onCreateVersion(row: ArchetypeRecord): void;
  onAction(action: "verify" | "activate" | "retire", row: ArchetypeRecord): void;
}) {
  const { t } = useI18n();
  const rows = result.data ?? [];
  const pager = usePagination(rows);
  return <section className="card table-card lifecycle-table-card" aria-busy={result.isLoading}>
    <div className="cardbar"><div className="cbl"><h2>{t("bundle.archetypes.title")}</h2><span className="tag t-gray">{t("bundle.count", { count: rows.length })}</span></div><div className="cbr"><button className="ibtn outline" type="button" data-tip={t("bundle.action.createArchetype")} aria-label={t("bundle.action.createArchetype")} onClick={onCreate}><Icon name="plus" /></button><button className={`ibtn outline${result.isFetching ? " loading" : ""}`} type="button" aria-label={t("table.refresh")} disabled={result.isFetching} onClick={() => void result.refetch()}><Icon name="refresh" /></button></div></div>
    {result.isLoading ? <LoadingState /> : rows.length === 0 ? <EmptyState title={t("bundle.archetypes.empty")} body={t("bundle.archetypes.emptyBody")} /> : <><div className="tbl-wrap"><table className="tbl lifecycle-table"><thead><tr><th>{t("bundle.column.archetype")}</th><th>{t("bundle.column.environment")}</th><th>{t("bundle.column.client")}</th><th>{t("bundle.column.evidence")}</th><th>{t("bundle.column.capacity")}</th><th>{t("bundle.column.lifecycle")}</th><th className="row-actions-heading">{t("table.actions")}</th></tr></thead><tbody>{pager.pageRows.map((row) => {
      const state = row.version_lifecycle ?? row.lifecycle;
      const next = state === "draft" ? "verify" : state === "verified" ? "activate" : state === "active" ? "retire" : null;
      return <tr key={row.id}>
        <td><strong>{row.name}</strong><small>{t("bundle.version", { version: row.version ?? "—" })}</small></td>
        <td><strong>{t(`bundle.os.${row.os_family}` as MessageKey)} · {row.architecture}</strong><small>{row.os_build || "—"}</small></td>
        <td><strong>Claude Code {row.client_version || "—"}</strong><small>{row.runtime || "—"} {row.runtime_version || ""}</small></td>
        <td><StatusPill value={row.evidence_state} /><small>{row.capture_cohort || t("bundle.notBound")}</small></td>
        <td><strong>{t("bundle.capacity.credentials", { count: row.max_credentials ?? 0 })}</strong></td>
        <td><StatusPill value={state} /></td>
        <td><div className="lifecycle-actions"><button className="btn btn-outline btn-sm" type="button" onClick={() => onCreateVersion(row)}>{t("bundle.action.newVersion")}</button>{next && <button className={`btn btn-sm ${next === "retire" ? "btn-ghost danger-text" : "btn-outline"}`} type="button" onClick={() => onAction(next, row)}>{t(`bundle.action.${next}` as MessageKey)}</button>}</div></td>
      </tr>;
    })}</tbody></table></div><TablePager page={pager.page} pageCount={pager.pageCount} total={pager.total} onPage={pager.setPage} /></>}
  </section>;
}

function BundleTable({ result, onCreate, onAction }: {
  result: ReturnType<typeof useQuery<BundleRecord[]>>;
  onCreate(): void;
  onAction(action: "verify" | "activate" | "rollback", row: BundleRecord): void;
}) {
  const { locale, t } = useI18n();
  const rows = result.data ?? [];
  const pager = usePagination(rows);
  return <section className="card table-card lifecycle-table-card" aria-busy={result.isLoading}>
    <div className="cardbar"><div className="cbl"><h2>{t("bundle.bundles.title")}</h2><span className="tag t-gray">{t("bundle.count", { count: rows.length })}</span></div><div className="cbr"><button className="ibtn outline" type="button" data-tip={t("bundle.action.upload")} aria-label={t("bundle.action.upload")} onClick={onCreate}><Icon name="upload" /></button><button className={`ibtn outline${result.isFetching ? " loading" : ""}`} type="button" aria-label={t("table.refresh")} disabled={result.isFetching} onClick={() => void result.refetch()}><Icon name="refresh" /></button></div></div>
    {result.isLoading ? <LoadingState /> : rows.length === 0 ? <EmptyState title={t("bundle.bundles.empty")} body={t("bundle.bundles.emptyBody")} /> : <><div className="tbl-wrap"><table className="tbl lifecycle-table bundle-table"><thead><tr><th>{t("bundle.column.bundle")}</th><th>{t("bundle.column.source")}</th><th>{t("bundle.column.protocol")}</th><th>{t("bundle.column.gates")}</th><th>{t("bundle.column.lifecycle")}</th><th>{t("bundle.column.activated")}</th><th className="row-actions-heading">{t("table.actions")}</th></tr></thead><tbody>{pager.pageRows.map((row) => {
      const next = row.lifecycle === "draft" ? "verify" : row.lifecycle === "verified" ? "activate" : row.lifecycle === "retired" ? "rollback" : null;
      return <tr key={row.id}>
        <td><strong>{t("bundle.artifactVersion", { version: row.artifact_version })}</strong><small>ABI {row.engine_abi_version}</small></td>
        <td><strong>{row.archetype_name || t("bundle.unknownArchetype")}</strong><small>{t("bundle.version", { version: row.archetype_version ?? "—" })} · {row.capture_cohort || "—"}</small></td>
        <td><strong>{(row.protocol || "—").toUpperCase()}</strong><small>{row.backend_id || "—"}</small></td>
        <td><div className="gate-pair"><StatusPill value={row.evidence_gate} /><StatusPill value={row.runtime_state} /></div></td>
        <td><StatusPill value={row.lifecycle} /></td>
        <td><strong>{row.activated_at ? new Date(row.activated_at).toLocaleString(locale) : "—"}</strong><small>{row.engine_activation_generation > 0 ? t("bundle.generation", { generation: row.engine_activation_generation }) : t("bundle.notActivated")}</small></td>
        <td><div className="lifecycle-actions">{next ? <button className="btn btn-outline btn-sm" type="button" onClick={() => onAction(next, row)}>{t(`bundle.action.${next}` as MessageKey)}</button> : <span className="muted">—</span>}</div></td>
      </tr>;
    })}</tbody></table></div><TablePager page={pager.page} pageCount={pager.pageCount} total={pager.total} onPage={pager.setPage} /></>}
  </section>;
}

function LoadingState() {
  return <div className="loading-lines"><span className="skel title" /><span className="skel line" /><span className="skel line" /></div>;
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return <div className="empty"><div className="empty-orbit"><Icon name="inbox" /></div><h3>{title}</h3><p>{body}</p></div>;
}

function ArchetypeForm({ base, pending, error, onCancel, onSubmit }: {
  base?: ArchetypeRecord;
  pending: boolean;
  error?: string;
  onCancel(): void;
  onSubmit(data: FormData): void;
}) {
  const { t } = useI18n();
  const titleId = useId();
  return <div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget && !pending) onCancel(); }}><section className="modal resource-action-modal archetype-modal" role="dialog" aria-modal="true" aria-labelledby={titleId}>
    <div className="modal-head"><div><p className="eyebrow mono">{t("bundle.eyebrow.profile")}</p><h3 id={titleId}>{base ? t("bundle.archetype.newVersionTitle") : t("bundle.archetype.createTitle")}</h3><p className="muted resource-action-description">{t("bundle.archetype.formDescription")}</p></div><button className="ibtn outline" type="button" aria-label={t("common.close")} onClick={onCancel} disabled={pending}>×</button></div>
    <form onSubmit={(event) => { event.preventDefault(); onSubmit(new FormData(event.currentTarget)); }}>
      <div className="modal-body archetype-form-grid">{error && <div className="alert alert-err form-wide" role="alert"><div><div className="at">{t("action.submitFailed")}</div><div className="ad">{error}</div></div></div>}
        <div className="form-section-label form-wide"><span>01</span><div><b>{t("bundle.archetype.environmentSection")}</b><small>{t("bundle.archetype.environmentSectionBody")}</small></div></div>
        <div className="field"><label htmlFor={`${titleId}-name`}>{t("bundle.field.name")}</label><input className="inp" id={`${titleId}-name`} name="name" defaultValue={base?.name ?? ""} maxLength={128} readOnly={Boolean(base)} required autoFocus /></div>
        <div className="field"><label htmlFor={`${titleId}-os`}>{t("bundle.field.os")}</label><SelectField id={`${titleId}-os`} name="os_family" defaultValue={base?.os_family ?? "windows"} disabled={Boolean(base)} options={[{ value: "windows", label: t("bundle.os.windows") }, { value: "macos", label: t("bundle.os.macos") }, { value: "linux", label: t("bundle.os.linux") }]} />{base && <input type="hidden" name="os_family" value={base.os_family} />}</div>
        <div className="field"><label htmlFor={`${titleId}-arch`}>{t("bundle.field.architecture")}</label><SelectField id={`${titleId}-arch`} name="architecture" defaultValue={base?.architecture ?? "x86_64"} disabled={Boolean(base)} options={[{ value: "x86_64", label: "x86_64" }, { value: "aarch64", label: "ARM64" }]} />{base && <input type="hidden" name="architecture" value={base.architecture} />}</div>
        <div className="field"><label htmlFor={`${titleId}-build`}>{t("bundle.field.osBuild")}</label><input className="inp" id={`${titleId}-build`} name="os_build" defaultValue={base?.os_build ?? ""} placeholder={t("bundle.placeholder.osBuild")} maxLength={256} required /></div>
        <div className="form-section-label form-wide"><span>02</span><div><b>{t("bundle.archetype.clientSection")}</b><small>{t("bundle.archetype.clientSectionBody")}</small></div></div>
        <div className="field"><label htmlFor={`${titleId}-client-version`}>{t("bundle.field.clientVersion")}</label><input className="inp" id={`${titleId}-client-version`} name="client_version" defaultValue={base?.client_version ?? ""} placeholder="1.0.0" maxLength={256} required /></div>
        <div className="field"><label htmlFor={`${titleId}-runtime`}>{t("bundle.field.runtime")}</label><input className="inp" id={`${titleId}-runtime`} name="runtime" defaultValue={base?.runtime ?? "node"} maxLength={256} required /></div>
        <div className="field"><label htmlFor={`${titleId}-runtime-version`}>{t("bundle.field.runtimeVersion")}</label><input className="inp" id={`${titleId}-runtime-version`} name="runtime_version" defaultValue={base?.runtime_version ?? "24"} maxLength={256} required /></div>
        <div className="field"><label htmlFor={`${titleId}-cohort`}>{t("bundle.field.captureCohort")}</label><input className="inp" id={`${titleId}-cohort`} name="capture_cohort" defaultValue={base?.capture_cohort ?? "local"} maxLength={256} required /></div>
        <div className="form-section-label form-wide"><span>03</span><div><b>{t("bundle.archetype.capacitySection")}</b><small>{t("bundle.archetype.capacitySectionBody")}</small></div></div>
        <div className="field"><label htmlFor={`${titleId}-credentials`}>{t("bundle.field.maxCredentials")}</label><input className="inp" id={`${titleId}-credentials`} name="max_credentials" type="number" min="1" defaultValue={base?.max_credentials ?? 10} required /></div>
        <div className="field"><label htmlFor={`${titleId}-weight`}>{t("bundle.field.allocationWeight")}</label><input className="inp" id={`${titleId}-weight`} name="allocation_weight" type="number" min="1" defaultValue={base?.allocation_weight ?? 1} required /></div>
        <div className="field"><label htmlFor={`${titleId}-allocation-cohort`}>{t("bundle.field.allocationCohort")}</label><input className="inp" id={`${titleId}-allocation-cohort`} name="allocation_cohort" defaultValue={base?.allocation_cohort ?? "default"} maxLength={256} required /></div>
        <details className="advanced-settings form-wide"><summary>{t("common.advanced")}</summary><p>{t("bundle.archetype.advancedHint")}</p><div className="archetype-form-grid">
          <div className="field"><label htmlFor={`${titleId}-schema`}>{t("bundle.field.profileSchema")}</label><input className="inp" id={`${titleId}-schema`} name="profile_schema_version" type="number" min="1" defaultValue={base?.profile_schema_version ?? 1} required /></div>
          <div className="field"><label htmlFor={`${titleId}-evidence`}>{t("bundle.field.evidenceSet")}</label><input className="inp mono" id={`${titleId}-evidence`} name="evidence_set_id" placeholder={t("bundle.placeholder.evidenceSet")} /></div>
          <div className="field form-wide"><label htmlFor={`${titleId}-refs`}>{t("bundle.field.sourceRefs")}<span className="hint">{t("bundle.field.sourceRefsHint")}</span></label><textarea className="inp" id={`${titleId}-refs`} name="source_refs" rows={3} /></div>
        </div></details>
        <div className="field form-wide"><label htmlFor={`${titleId}-reason`}>{t("bundle.field.reason")}</label><input className="inp" id={`${titleId}-reason`} name="reason" maxLength={2048} /></div>
      </div>
      <div className="modal-foot"><button className="btn btn-ghost" type="button" onClick={onCancel} disabled={pending}>{t("common.cancel")}</button><button className="btn btn-primary" type="submit" disabled={pending}>{pending ? t("common.submitting") : base ? t("bundle.action.createVersion") : t("bundle.action.createArchetype")}</button></div>
    </form>
  </section></div>;
}

function BundleUploadForm({ pending, error, summary, onFile, onCancel, onSubmit }: {
  pending: boolean;
  error?: string;
  summary: BundleFileSummary | null;
  onFile(file?: File): void;
  onCancel(): void;
  onSubmit(data: FormData): void;
}) {
  const { t } = useI18n();
  const titleId = useId();
  return <div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget && !pending) onCancel(); }}><section className="modal resource-action-modal bundle-upload-modal" role="dialog" aria-modal="true" aria-labelledby={titleId}>
    <div className="modal-head"><div><p className="eyebrow mono">{t("bundle.eyebrow.signedArtifact")}</p><h3 id={titleId}>{t("bundle.upload.title")}</h3><p className="muted resource-action-description">{t("bundle.upload.description")}</p></div><button className="ibtn outline" type="button" aria-label={t("common.close")} onClick={onCancel} disabled={pending}>×</button></div>
    <form onSubmit={(event) => { event.preventDefault(); onSubmit(new FormData(event.currentTarget)); }}><div className="modal-body resource-action-grid">{error && <div className="alert alert-err action-error" role="alert"><div><div className="at">{t("action.submitFailed")}</div><div className="ad">{error}</div></div></div>}
      <div className="policy-note field-wide"><Icon name="shield" /><span>{t("bundle.upload.policy")}</span></div>
      <div className="field field-wide"><label htmlFor={`${titleId}-file`}>{t("bundle.field.signedFile")}</label><label className={`bundle-dropzone ${summary ? "has-file" : ""}`} htmlFor={`${titleId}-file`}><Icon name={summary ? "check" : "upload"} /><b>{summary ? summary.file.name : t("bundle.upload.choose")}</b><small>{summary ? t("bundle.upload.fileSize", { size: (summary.file.size / 1024).toFixed(1) }) : t("bundle.upload.fileHint")}</small></label><input className="sr-only" id={`${titleId}-file`} name="signed_file" type="file" accept="application/json,.json" onChange={(event) => onFile(event.currentTarget.files?.[0])} /></div>
      {summary && <dl className="bundle-file-summary field-wide"><div><dt>{t("bundle.field.artifactVersion")}</dt><dd>{summary.artifactVersion}</dd></div><div><dt>{t("bundle.field.sourceVersion")}</dt><dd>{summary.sourceVersion}</dd></div><div><dt>{t("bundle.field.protocol")}</dt><dd>{summary.protocol}</dd></div></dl>}
      <div className="field"><label htmlFor={`${titleId}-name`}>{t("bundle.field.uploadName")}</label><input className="inp" id={`${titleId}-name`} name="name" maxLength={128} required /></div>
      <div className="field"><label htmlFor={`${titleId}-reason`}>{t("bundle.field.reason")}</label><input className="inp" id={`${titleId}-reason`} name="reason" maxLength={2048} /></div>
      <div className="field field-wide"><label htmlFor={`${titleId}-refs`}>{t("bundle.field.sourceRefs")}<span className="hint">{t("bundle.field.sourceRefsHint")}</span></label><textarea className="inp" id={`${titleId}-refs`} name="source_refs" rows={3} /></div>
    </div><div className="modal-foot"><button className="btn btn-ghost" type="button" onClick={onCancel} disabled={pending}>{t("common.cancel")}</button><button className="btn btn-primary" type="submit" disabled={pending || !summary}><Icon name="upload" />{pending ? t("common.submitting") : t("bundle.action.upload")}</button></div></form>
  </section></div>;
}

function LifecycleForm({ dialog, pending, error, onCancel, onSubmit }: {
  dialog: NonNullable<LifecycleDialog>;
  pending: boolean;
  error?: string;
  onCancel(): void;
  onSubmit(data: FormData): void;
}) {
  const { t } = useI18n();
  const titleId = useId();
  const subject = dialog.kind === "archetype" ? dialog.row.name : t("bundle.artifactVersion", { version: dialog.row.artifact_version });
  return <div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget && !pending) onCancel(); }}><section className="modal lifecycle-modal" role="dialog" aria-modal="true" aria-labelledby={titleId}>
    <div className="modal-head"><div><p className="eyebrow mono">{t("bundle.eyebrow.lifecycle")}</p><h3 id={titleId}>{t(`bundle.action.${dialog.action}` as MessageKey)}</h3><p className="muted resource-action-description">{t("bundle.lifecycle.subject", { name: subject })}</p></div><button className="ibtn outline" type="button" aria-label={t("common.close")} onClick={onCancel} disabled={pending}>×</button></div>
    <form onSubmit={(event) => { event.preventDefault(); onSubmit(new FormData(event.currentTarget)); }}><div className="modal-body">{error && <div className="alert alert-err" role="alert"><div><div className="at">{t("action.submitFailed")}</div><div className="ad">{error}</div></div></div>}<div className="policy-note"><Icon name="check" /><span>{t(`bundle.lifecycle.${dialog.action}Hint` as MessageKey)}</span></div><div className="field"><label htmlFor={`${titleId}-reason`}>{t("bundle.field.reason")}</label><input className="inp" id={`${titleId}-reason`} name="reason" maxLength={2048} autoFocus /></div></div><div className="modal-foot"><button className="btn btn-ghost" type="button" onClick={onCancel} disabled={pending}>{t("common.cancel")}</button><button className="btn btn-primary" type="submit" disabled={pending}>{pending ? t("common.submitting") : t("common.confirm")}</button></div></form>
  </section></div>;
}

export function ArchetypeBundlePage() {
  const { t } = useI18n();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [view, setView] = useState<View>("archetypes");
  const [creation, setCreation] = useState<CreationDialog>(null);
  const [lifecycle, setLifecycle] = useState<LifecycleDialog>(null);
  const [bundleFile, setBundleFile] = useState<BundleFileSummary | null>(null);
  const [fileError, setFileError] = useState("");
  const archetypes = useQuery<ArchetypeRecord[]>({ queryKey: ["/admin/v1/environment-archetypes"], queryFn: () => api("/admin/v1/environment-archetypes"), retry: false });
  const bundles = useQuery<BundleRecord[]>({ queryKey: ["/admin/v1/transport-bundles"], queryFn: () => api("/admin/v1/transport-bundles"), retry: false });
  const createArchetype = useMutation({
    mutationFn: (data: FormData) => api("/admin/v1/environment-archetypes", { method: "POST", body: JSON.stringify({
      name: text(data, "name"), schema_version: 1, archetype_id: creation?.kind === "archetype" ? creation.base?.id ?? null : null,
      payload: { os_family: text(data, "os_family"), architecture: text(data, "architecture"), os_build: text(data, "os_build"), client_family: "claude_code_cli", runtime: text(data, "runtime"), runtime_version: text(data, "runtime_version"), client_version: text(data, "client_version"), profile_schema_version: positiveInteger(data, "profile_schema_version"), capture_cohort: text(data, "capture_cohort"), protocol_profile: {}, evidence_set_id: text(data, "evidence_set_id") || null, capacity: { max_credentials: positiveInteger(data, "max_credentials"), allocation_weight: positiveInteger(data, "allocation_weight"), allocation_cohort: text(data, "allocation_cohort") } },
      source_refs: stringList(text(data, "source_refs")), reason: text(data, "reason"),
    }) }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ["/admin/v1/environment-archetypes"] }); toast.success(t("bundle.toast.archetypeCreated")); setCreation(null); },
  });
  const uploadBundle = useMutation({
    mutationFn: (data: FormData) => {
      if (!bundleFile) throw new Error(t("bundle.error.fileRequired"));
      return api("/admin/v1/transport-bundles", { method: "POST", body: JSON.stringify({ name: text(data, "name"), schema_version: 1, signed_envelope: bundleFile.envelope, source_refs: stringList(text(data, "source_refs")), reason: text(data, "reason") }) });
    },
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ["/admin/v1/transport-bundles"] }); toast.success(t("bundle.toast.bundleUploaded")); setCreation(null); setBundleFile(null); },
  });
  const transition = useMutation({
    mutationFn: ({ dialog, data }: { dialog: NonNullable<LifecycleDialog>; data: FormData }) => {
      const revision = dialog.row.revision;
      const body: Record<string, unknown> = { reason: text(data, "reason"), expected_revision: revision };
      const base = dialog.kind === "archetype" ? "/admin/v1/environment-archetypes" : "/admin/v1/transport-bundles";
      return api(`${base}/${encodeURIComponent(dialog.row.id)}:${dialog.action}`, { method: "POST", headers: { "If-Match": `\"rev-${revision}\"` }, body: JSON.stringify(body) });
    },
    onSuccess: (_, variables) => { const endpoint = variables.dialog.kind === "archetype" ? "/admin/v1/environment-archetypes" : "/admin/v1/transport-bundles"; void queryClient.invalidateQueries({ queryKey: [endpoint] }); toast.success(t("bundle.toast.transitioned")); setLifecycle(null); },
    onError: (error) => toast.error(describeError(error, t("common.operationFailed"))),
  });
  useEffect(() => {
    if (!creation && !lifecycle) return;
    const close = (event: KeyboardEvent) => { if (event.key === "Escape" && !createArchetype.isPending && !uploadBundle.isPending && !transition.isPending) { setCreation(null); setLifecycle(null); } };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [creation, lifecycle, createArchetype.isPending, uploadBundle.isPending, transition.isPending]);

  async function selectBundleFile(file?: File) {
    setBundleFile(null); setFileError("");
    if (!file) return;
    if (file.size > 8 * 1024 * 1024) { setFileError(t("bundle.error.fileTooLarge")); return; }
    try {
      const value: unknown = JSON.parse(await readTextFile(file));
      if (!value || typeof value !== "object" || !("payload" in value) || !("signature" in value)) throw new Error();
      const envelope = value as Record<string, unknown>;
      const payload = envelope.payload && typeof envelope.payload === "object" ? envelope.payload as Record<string, unknown> : {};
      const application = payload.application && typeof payload.application === "object" ? payload.application as Record<string, unknown> : {};
      setBundleFile({ file, envelope, artifactVersion: String(payload.artifact_version ?? "—"), sourceVersion: String(payload.source_archetype_version_id ?? "—"), protocol: String(application.protocol ?? application.type ?? "—").toUpperCase() });
    } catch { setFileError(t("bundle.error.invalidFile")); }
  }

  function verifyArchetype(row: ArchetypeRecord) {
    transition.mutate({ dialog: { kind: "archetype", action: "verify", row }, data: new FormData() });
  }

  function verifyBundle(row: BundleRecord) {
    transition.mutate({ dialog: { kind: "bundle", action: "verify", row }, data: new FormData() });
  }

  const loadError = view === "archetypes" ? archetypes.error : bundles.error;
  const archetypeRows = archetypes.data ?? [];
  const bundleRows = bundles.data ?? [];
  return <div className="page-stack bundle-page">
    <header className="page-heading"><div><p className="eyebrow mono">{t("bundle.eyebrow.page")}</p><h1>{t("nav.bundles")}</h1><p>{t("bundle.pageDescription")}</p></div></header>
    <OsCoverageOverview archetypes={archetypeRows} bundles={bundleRows} />
    <WorkflowGuide />
    <div className="bundle-viewbar"><div className="segmented local" role="tablist" aria-label={t("bundle.viewLabel")}><button type="button" role="tab" aria-selected={view === "archetypes"} className={view === "archetypes" ? "active" : ""} onClick={() => setView("archetypes")}>{t("bundle.archetypes.title")}</button><button type="button" role="tab" aria-selected={view === "bundles"} className={view === "bundles" ? "active" : ""} onClick={() => setView("bundles")}>{t("bundle.bundles.title")}</button></div><p><Icon name="info" />{view === "archetypes" ? t("bundle.archetypes.help") : t("bundle.bundles.help")}</p></div>
    {loadError && <div className="alert alert-warn" role="alert"><Icon name="alert" /><div><div className="at">{t("error.loadTitle")}</div><div className="ad">{describeError(loadError, t("common.requestFailed"))}</div></div></div>}
    {view === "archetypes"
      ? <ArchetypeTable result={archetypes} onCreate={() => { setFileError(""); setBundleFile(null); setCreation({ kind: "archetype" }); }} onCreateVersion={(row) => setCreation({ kind: "archetype", base: row })} onAction={(action, row) => action === "verify" ? verifyArchetype(row) : setLifecycle({ kind: "archetype", action, row })} />
      : <BundleTable result={bundles} onCreate={() => { setFileError(""); setBundleFile(null); setCreation({ kind: "bundle" }); }} onAction={(action, row) => action === "verify" ? verifyBundle(row) : setLifecycle({ kind: "bundle", action, row })} />}
    {creation?.kind === "archetype" && createPortal(<ArchetypeForm base={creation.base} pending={createArchetype.isPending} error={createArchetype.isError ? describeError(createArchetype.error, t("common.operationFailed")) : undefined} onCancel={() => { if (!createArchetype.isPending) { createArchetype.reset(); setCreation(null); } }} onSubmit={(data) => createArchetype.mutate(data)} />, document.body)}
    {creation?.kind === "bundle" && createPortal(<BundleUploadForm pending={uploadBundle.isPending} error={fileError || (uploadBundle.isError ? describeError(uploadBundle.error, t("common.operationFailed")) : undefined)} summary={bundleFile} onFile={(file) => void selectBundleFile(file)} onCancel={() => { if (!uploadBundle.isPending) { uploadBundle.reset(); setCreation(null); setBundleFile(null); setFileError(""); } }} onSubmit={(data) => uploadBundle.mutate(data)} />, document.body)}
    {lifecycle && createPortal(<LifecycleForm dialog={lifecycle} pending={transition.isPending} error={transition.isError ? describeError(transition.error, t("common.operationFailed")) : undefined} onCancel={() => { if (!transition.isPending) { transition.reset(); setLifecycle(null); } }} onSubmit={(data) => transition.mutate({ dialog: lifecycle, data })} />, document.body)}
  </div>;
}
