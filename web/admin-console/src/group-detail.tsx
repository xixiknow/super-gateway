import { FormEvent, ReactNode, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useConfirm, useToast } from "./feedback";
import { MessageKey, useI18n } from "./i18n";
import { rowActionError } from "./row-actions";
import { SelectField } from "./select-field";
import { DataGrid, Icon, PaneStatus, Row, SubTable, deriveColumns } from "./detail-kit";

/* ============================================================
   分组详情对话框:概览 / 组内凭据 / 调度与限流 / 请求治理 /
   能力与出口 / 配置版本六页签。
   配置调整基于当前生效配置创建不可变版本,保存后直接生效。
   ============================================================ */

type Tab = "overview" | "credentials" | "scheduling" | "governance" | "egress" | "versions";
type ConfigTab = "scheduling" | "governance" | "egress";
type VersionAction = "validate" | "simulate" | "activate";

/** 配置版本投影是嵌套结构(limits/credential_defaults/queue/timeouts/governance/model_scope) */
function section(record: Row, key: string): Row {
  const value = record[key];
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Row) : {};
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function numberOrDefault(value: unknown, fallback: number): string {
  return String(asNumber(value) ?? fallback);
}

function clientClasses(record: Row): string[] {
  const value = record.accepted_client_classes;
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function modelIds(record: Row): string[] {
  const value = section(record, "model_scope").model_ids;
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function stringOf(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

/** System 替换内容在投影里是 JSON 字符串或块数组,编辑与展示统一转文本 */
function systemContentText(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return JSON.stringify(value, null, 2);
  return "";
}

/** 与后端一致的高风险判定:System 切到 replace / strip_all */
function isHighRiskChange(target: Row, active: Row): boolean {
  const targetMode = stringOf(section(target, "governance").system_prompt_mode);
  const activeMode = stringOf(section(active, "governance").system_prompt_mode);
  return targetMode !== undefined && targetMode !== activeMode
    && (targetMode === "replace" || targetMode === "strip_all");
}

const versionActionMeta: Record<VersionAction, { labelKey: MessageKey; icon: string; when(lifecycle: string, isActive: boolean): boolean }> = {
  "validate": { labelKey: "group.version.validate", icon: "check", when: (lifecycle) => lifecycle === "draft" },
  "simulate": { labelKey: "group.version.simulate", icon: "activity", when: () => true },
  // 新建的 draft 版本可直接激活，校验是可选前置。
  "activate": { labelKey: "group.version.activate", icon: "play", when: (lifecycle, isActive) => !isActive && ["draft", "validated"].includes(lifecycle) },
};

function versionNumber(row: Row): number | undefined {
  const value = row.version ?? row.config_version;
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function VersionsPane({ endpoint, versions, onChanged, onNewDraft }: { endpoint: string; versions: Row[]; onChanged(): Promise<void>; onNewDraft?(): void }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const confirm = useConfirm();
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [targetVersion, setTargetVersion] = useState("");
  const [rollbackReason, setRollbackReason] = useState("");
  const [diffVersion, setDiffVersion] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const pointerRevision = versions
    .map((row) => (typeof row.pointer_revision === "number" ? row.pointer_revision : undefined))
    .find((value) => value !== undefined);
  const activeConfig = versions.find((row) => row.is_active === true);
  const diffTarget = diffVersion === null ? undefined : versions.find((row) => versionNumber(row) === diffVersion);

  async function runAction(row: Row, action: VersionAction) {
    const version = versionNumber(row);
    if (version === undefined) return;
    // 校验/模拟使用版本号；激活使用活动指针 revision。
    const ifMatch = action === "activate" ? pointerRevision : version;
    if (ifMatch === undefined) return;
    let reason = "";
    if (action === "activate") {
      const highRisk = activeConfig !== undefined && isHighRiskChange(row, activeConfig);
      const result = await confirm({
        titleKey: versionActionMeta[action].labelKey,
        bodyKey: highRisk ? "group.version.highRiskBody" : "group.version.confirmBody",
        withReason: true,
        danger: true,
      });
      if (!result.ok) return;
      reason = result.reason;
    }
    setBusy(true);
    try {
      await api(`${endpoint}/config-versions/${version}:${action}`, {
        method: "POST",
        headers: { "If-Match": `"rev-${ifMatch}"` },
        body: JSON.stringify({ reason, expected_revision: ifMatch }),
      });
      toast.success(t("action.success"));
      await onChanged();
    } catch (error) {
      toast.error(rowActionError(error, locale));
    } finally {
      setBusy(false);
    }
  }

  async function submitRollback(event: FormEvent) {
    event.preventDefault();
    if (pointerRevision === undefined) return;
    const confirmation = await confirm({
      titleKey: "group.version.rollback",
      bodyKey: "group.version.confirmBody",
      danger: true,
    });
    if (!confirmation.ok) return;
    setBusy(true);
    try {
      await api(`${endpoint}:rollback-config`, {
        method: "POST",
        headers: { "If-Match": `"rev-${pointerRevision}"` },
        body: JSON.stringify({
          target_version: Number(targetVersion),
          reason: rollbackReason || confirmation.reason,
          expected_revision: pointerRevision,
        }),
      });
      toast.success(t("action.success"));
      setRollbackOpen(false);
      setTargetVersion("");
      setRollbackReason("");
      await onChanged();
    } catch (error) {
      toast.error(rowActionError(error, locale));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="group-versions-pane">
      <div className="version-chain-bar">
        <p className="muted">{t("group.version.chainHint")}</p>
        <div className="version-chain-actions">
          {onNewDraft && <button type="button" className="btn btn-primary" disabled={busy} onClick={onNewDraft}><Icon name="plus" />{t("group.config.newVersion")}</button>}
          <button type="button" className="btn btn-ghost" disabled={busy || pointerRevision === undefined} onClick={() => setRollbackOpen((open) => !open)}><Icon name="arrow-left" />{t("group.version.rollback")}</button>
        </div>
      </div>
      {rollbackOpen && (
        <form className="version-rollback-form" onSubmit={(event) => void submitRollback(event)}>
          <div className="field"><label htmlFor="rollback-version">{t("group.version.targetVersion")}</label><input id="rollback-version" className="inp" type="number" min={1} required value={targetVersion} onChange={(event) => setTargetVersion(event.target.value)} /></div>
          <div className="field"><label htmlFor="rollback-reason">{t("credential.form.reason")}</label><input id="rollback-reason" className="inp" maxLength={2048} value={rollbackReason} onChange={(event) => setRollbackReason(event.target.value)} /></div>
          <button type="submit" className="btn btn-primary" disabled={busy}>{t("credential.form.submit")}</button>
        </form>
      )}
      {diffTarget && activeConfig && <DiffPanel target={diffTarget} active={activeConfig} onClose={() => setDiffVersion(null)} />}
      <SubTable
        rows={versions}
        columns={deriveColumns(versions, ["version", "lifecycle", "is_active", "validated_at", "published_at", "created_at"], 6)}
        empty={t("group.versions.none")}
        rowTail={(row) => {
          const lifecycle = typeof row.lifecycle === "string" ? row.lifecycle : "";
          const isActive = row.is_active === true;
          const available = (Object.keys(versionActionMeta) as VersionAction[]).filter((action) => versionActionMeta[action].when(lifecycle, isActive));
          const version = versionNumber(row);
          return (
            <div className="row-actions">
              {!isActive && activeConfig !== undefined && (
                <button type="button" className="ibtn outline sm" data-tip={t("group.diff.action")} aria-label={t("group.diff.action")} disabled={busy} onClick={() => setDiffVersion((current) => (current === version ? null : version ?? null))}>
                  <Icon name="list" />
                </button>
              )}
              {available.map((action) => (
                <button key={action} type="button" className="ibtn outline sm" data-tip={t(versionActionMeta[action].labelKey)} aria-label={t(versionActionMeta[action].labelKey)} disabled={busy} onClick={() => void runAction(row, action)}>
                  <Icon name={versionActionMeta[action].icon} />
                </button>
              ))}
            </div>
          );
        }}
      />
    </div>
  );
}

type Translate = (key: MessageKey, vars?: Record<string, string | number>) => string;

/** 配置字段的统一文案化:页签只读展示与版本对比共用同一套格式,保证口径一致 */
function configEntries(config: Row, tab: ConfigTab | "all", t: Translate, locale: string): [string, string][] {
  const limits = section(config, "limits");
  const defaults = section(config, "credential_defaults");
  const queue = section(config, "queue");
  const timeouts = section(config, "timeouts");
  const governance = section(config, "governance");
  const modelScope = section(config, "model_scope");
  const unlimited = t("group.config.unlimited");
  const bool = (value: unknown) => (value === true ? t("common.yes") : t("common.no"));
  const count = (value: unknown, fallback: string) => asNumber(value)?.toLocaleString(locale) ?? fallback;
  const enumText = (prefix: string, value: unknown) => (typeof value === "string" && value ? t(`${prefix}.${value}` as MessageKey) : "—");
  const scheduling: [string, string][] = [
    [t("group.config.groupConcurrency"), count(limits.concurrency, unlimited)],
    [t("group.config.messagesRpm"), count(limits.messages_rpm, unlimited)],
    [t("group.config.messagesBurst"), count(limits.messages_burst, unlimited)],
    [t("group.config.credentialConcurrency"), count(defaults.concurrency, "—")],
    [t("group.config.credentialRpm"), count(defaults.messages_rpm, "—")],
    [t("group.config.queueCapacity"), asNumber(queue.capacity)?.toLocaleString(locale) ?? t("group.config.queueAuto")],
    [t("group.config.preUpstreamTimeout"), count(queue.pre_upstream_timeout_ms, "—")],
    [t("group.config.connectTimeout"), count(timeouts.upstream_connect_ms, "—")],
    [t("group.config.nonStreamTimeout"), count(timeouts.upstream_non_stream_total_ms, "—")],
    [t("group.config.streamIdleTimeout"), count(timeouts.upstream_stream_idle_ms, "—")],
  ];
  const governanceEntries: [string, string][] = [
    [t("group.config.acceptedClients"), clientClasses(config).map((item) => t(`group.config.client.${item}` as MessageKey)).join("、") || "—"],
    [t("group.config.systemPromptMode"), enumText("group.config.system", governance.system_prompt_mode)],
    ...(governance.system_prompt_mode === "replace"
      ? [[t("group.config.systemPromptRef"), stringOf(governance.system_prompt_ref) ?? "—"] as [string, string]]
      : []),
    [t("group.config.consoleFallback"), bool(governance.console_business_fallback_enabled)],
  ];
  const egress: [string, string][] = [
    [t("group.config.egressMode"), enumText("group.config.egress", config.egress_mode)],
    [t("group.config.fullyManaged"), bool(config.fully_managed_required)],
    [t("group.config.modelScope"), enumText("group.config.scope", modelScope.scope)],
    ...(modelScope.scope === "allowlist"
      ? [[t("group.config.allowlistCount"), String(modelIds(config).length)] as [string, string]]
      : []),
  ];
  if (tab === "scheduling") return scheduling;
  if (tab === "governance") return governanceEntries;
  if (tab === "egress") return egress;
  return [...scheduling, ...governanceEntries, ...egress];
}

/** 三个配置页签的只读展示:按投影的嵌套结构渲染,值带中文标签与语义化空值 */
function ConfigPane({ config, tab, onAdjust }: { config: Row; tab: ConfigTab; onAdjust(): void }) {
  const { locale, t } = useI18n();
  const entries = configEntries(config, tab, t, locale);
  const when = (value: unknown) => (typeof value === "string" && value ? new Date(value).toLocaleString(locale) : "—");
  const meta: [string, ReactNode][] = tab === "governance"
    ? [[t("group.config.validatedAt"), when(config.validated_at)], [t("group.config.publishedAt"), when(config.published_at)]]
    : [];
  return (
    <div className="group-config-pane">
      <div className="version-chain-bar">
        <p className="muted">{t("group.config.activeTitle")}{" · v"}{String(versionNumber(config) ?? "—")}</p>
        <button type="button" className="btn btn-ghost" onClick={onAdjust}><Icon name="edit" />{t("group.config.adjust")}</button>
      </div>
      <dl className="key-data-grid">
        {[...entries, ...meta].map(([label, value]) => <div key={label}><dt>{label}</dt><dd className="mono breakable">{value}</dd></div>)}
      </dl>
    </div>
  );
}

/** 版本对比:目标版本与当前生效版本逐字段对照,仅高亮有差异的行 */
function DiffPanel({ target, active, onClose }: { target: Row; active: Row; onClose(): void }) {
  const { locale, t } = useI18n();
  const targetEntries = configEntries(target, "all", t, locale);
  const activeValues = new Map(configEntries(active, "all", t, locale));
  const rows = targetEntries.map(([label, value]) => ({ label, from: activeValues.get(label) ?? "—", to: value }));
  const changed = rows.filter((row) => row.from !== row.to);
  return (
    <section className="config-diff-panel" aria-label={t("group.diff.title")}>
      <div className="version-chain-bar">
        <p className="muted">
          {t("group.diff.title")}{" · v"}{String(versionNumber(active) ?? "—")}{" → v"}{String(versionNumber(target) ?? "—")}
          {isHighRiskChange(target, active) && <span className="tag t-coral config-diff-risk">{t("group.diff.highRisk")}</span>}
        </p>
        <button type="button" className="ibtn outline sm" aria-label={t("common.close")} onClick={onClose}>×</button>
      </div>
      {changed.length === 0
        ? <p className="muted">{t("group.diff.identical")}</p>
        : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead><tr><th scope="col">{t("group.diff.field")}</th><th scope="col">{t("group.diff.active")}</th><th scope="col">{t("group.diff.candidate")}</th></tr></thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.label} className={row.from !== row.to ? "config-diff-changed" : ""}>
                    <td>{row.label}</td>
                    <td className="mono">{row.from}</td>
                    <td className="mono">{row.from !== row.to ? <strong>{row.to}</strong> : row.to}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
    </section>
  );
}

interface ModelRecord { id?: unknown; display_name?: unknown; upstream_model_id?: unknown; lifecycle?: unknown }

/** 新建配置候选草稿:预填当前生效配置,提交 POST /groups/{id}/config-versions */
function ConfigDraftForm({ endpoint, active, onBack, onDone }: { endpoint: string; active: Row; onBack(): void; onDone(leave: boolean): Promise<void> }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const confirm = useConfirm();
  const intentRef = useRef<"activate" | "draft">("activate");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const limits = section(active, "limits");
  const defaults = section(active, "credential_defaults");
  const queue = section(active, "queue");
  const timeouts = section(active, "timeouts");
  const governance = section(active, "governance");
  const activeClients = clientClasses(active);
  const [systemMode, setSystemMode] = useState(stringOf(governance.system_prompt_mode) ?? "preserve");
  const [modelScope, setModelScope] = useState(stringOf(section(active, "model_scope").scope) ?? "all_published");
  const [selectedModels, setSelectedModels] = useState<string[]>(modelIds(active));
  // 已发布模型目录用于白名单选择;仅 allowlist 模式需要
  const models = useQuery({
    queryKey: ["/admin/v1/models"],
    queryFn: () => api<ModelRecord[]>("/admin/v1/models"),
    enabled: modelScope === "allowlist",
    retry: false,
  });
  const publishedModels = (models.data ?? []).filter((model) => model.lifecycle === "published");
  // 高风险模式会在激活时提示，并由审计记录变更。
  const activeMode = stringOf(governance.system_prompt_mode) ?? "preserve";
  const modeHighRisk = systemMode !== activeMode && (systemMode === "replace" || systemMode === "strip_all");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const accepted = data.getAll("accepted_client_classes").map(String);
    if (accepted.length === 0) {
      setFormError(t("group.config.clientsRequired"));
      return;
    }
    const optional = (name: string): number | null => {
      const value = String(data.get(name) ?? "").trim();
      return value === "" ? null : Number(value);
    };
    const integer = (name: string): number => Number(String(data.get(name) ?? "").trim());
    const rpm = optional("messages_rpm");
    const burst = optional("messages_burst");
    if ((rpm === null) !== (burst === null)) {
      setFormError(t("group.config.rpmPairHint"));
      return;
    }
    const promptRef = String(data.get("system_prompt_ref") ?? "").trim();
    const promptContent = String(data.get("system_prompt_content") ?? "").trim();
    // replace 模式只强制标识;内容留空表示派发时使用所选原型采集的静态模板
    if (systemMode === "replace" && !promptRef) {
      setFormError(t("group.config.replaceRequired"));
      return;
    }
    if (modelScope === "allowlist" && selectedModels.length === 0) {
      setFormError(t("group.config.allowlistRequired"));
      return;
    }
    const activate = intentRef.current === "activate";
    intentRef.current = "activate";
    if (modeHighRisk) {
      const result = await confirm({
        titleKey: activate ? "group.config.saveAndActivate" : "group.config.saveDraft",
        bodyKey: "group.version.highRiskBody",
        danger: true,
      });
      if (!result.ok) return;
    }
    setFormError(null);
    setSubmitting(true);
    try {
      const created = await api<Row>(`${endpoint}/config-versions`, {
        method: "POST",
        body: JSON.stringify({
          accepted_client_classes: accepted,
          fully_managed_required: data.get("fully_managed_required") !== null,
          egress_mode: String(data.get("egress_mode") ?? "auto"),
          default_os_family: String(data.get("default_os_family") ?? "").trim() || undefined,
          limits: { concurrency: optional("concurrency"), messages_rpm: rpm, messages_burst: burst },
          credential_defaults: { concurrency: integer("credential_concurrency"), messages_rpm: integer("credential_rpm") },
          queue: { pre_upstream_timeout_ms: integer("pre_upstream_timeout_ms") },
          timeouts: {
            upstream_connect_ms: integer("upstream_connect_ms"),
            upstream_non_stream_total_ms: integer("upstream_non_stream_total_ms"),
            upstream_stream_idle_ms: integer("upstream_stream_idle_ms"),
          },
          governance: {
            system_prompt_mode: systemMode,
            system_prompt_ref: systemMode === "replace" ? promptRef : null,
            system_prompt_content: systemMode === "replace" ? promptContent : null,
            console_business_fallback_enabled: data.get("console_business_fallback_enabled") !== null,
          },
          model_scope: { scope: modelScope, model_ids: modelScope === "allowlist" ? selectedModels : [] },
        }),
      });
      const version = versionNumber(created);
      if (version === undefined) {
        throw new Error(t("group.config.missingVersion"));
      }
      if (!activate) {
        toast.success(t("action.success"));
        await onDone(true);
        return;
      }
      const pointerRevision = asNumber(active.pointer_revision) ?? asNumber(created.pointer_revision);
      if (pointerRevision === undefined) {
        setFormError(t("group.config.draftCreatedActivateFailed", { version }));
        toast.error(t("group.config.draftCreatedActivateFailed", { version }));
        await onDone(false);
        return;
      }
      try {
        await api(`${endpoint}/config-versions/${version}:activate`, {
          method: "POST",
          headers: { "If-Match": `"rev-${pointerRevision}"` },
          body: JSON.stringify({ reason: "", expected_revision: pointerRevision }),
        });
        toast.success(t("action.success"));
        await onDone(true);
      } catch (error) {
        setFormError(t("group.config.draftCreatedActivateFailed", { version }));
        toast.error(rowActionError(error, locale));
        await onDone(false);
      }
    } catch (error) {
      setFormError(rowActionError(error, locale));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="credential-ops-form" onSubmit={(event) => void submit(event)}>
      <div className="ops-form-head">
        <button type="button" className="ibtn outline sm" aria-label={t("credential.form.back")} data-tip={t("credential.form.back")} onClick={onBack}><Icon name="arrow-left" /></button>
        <h4>{t("group.config.newVersion")}</h4>
      </div>
      <p className="muted">{t("group.config.formDescription")}</p>
      {formError && <div className="alert alert-err" role="alert"><Icon name="alert" /><div><div className="ad">{formError}</div></div></div>}

      <div className="config-draft-grid">
        <div className="form-section-label form-wide"><span>01</span><div><b>{t("group.config.section.clients")}</b></div></div>
        <div className="field form-wide">
          <fieldset className="choice-field">
            <legend>{t("group.config.acceptedClients")}</legend>
            <div className="choice-grid">
              {(["claude_code_cli", "non_claude_code_cli"] as const).map((value) => (
                <label key={value} className="choice-card">
                  <input type="checkbox" name="accepted_client_classes" value={value} defaultChecked={activeClients.length === 0 || activeClients.includes(value)} />
                  <span>{t(`group.config.client.${value}`)}</span>
                </label>
              ))}
            </div>
          </fieldset>
        </div>
        <div className="form-section-label form-wide"><span>02</span><div><b>{t("group.config.section.governance")}</b></div></div>
        <div className="field"><label htmlFor="cfg-system-mode">{t("group.config.systemPromptMode")}</label>
          <SelectField id="cfg-system-mode" value={systemMode} onChange={setSystemMode}
            options={[
              { value: "preserve", label: t("group.config.system.preserve") },
              { value: "strip_client", label: t("group.config.system.strip_client") },
              { value: "replace", label: t("group.config.system.replace") },
              { value: "strip_all", label: t("group.config.system.strip_all") },
            ]} />
          {modeHighRisk && <small className="field-error" role="alert">{t("group.config.systemHighRiskHint")}</small>}
        </div>
        {systemMode === "replace" && (
          <>
            <div className="field"><label htmlFor="cfg-system-ref">{t("group.config.systemPromptRef")}</label>
              <input id="cfg-system-ref" name="system_prompt_ref" className="inp mono" maxLength={256} defaultValue={stringOf(governance.system_prompt_ref) ?? ""} placeholder="platform-system-v1" /></div>
            <div className="field"><label htmlFor="cfg-system-content">{t("group.config.systemPromptContent")}<span className="hint">{t("group.config.systemPromptContentHint")}</span></label>
              <textarea id="cfg-system-content" name="system_prompt_content" className="inp mono" rows={4} maxLength={65_536} defaultValue={systemContentText(governance.system_prompt_content)} /></div>
          </>
        )}

        <div className="form-section-label form-wide"><span>03</span><div><b>{t("group.config.section.modelScope")}</b></div></div>
        <div className="field"><label htmlFor="cfg-model-scope">{t("group.config.modelScope")}</label>
          <SelectField id="cfg-model-scope" value={modelScope} onChange={setModelScope}
            options={[{ value: "all_published", label: t("group.config.scope.all_published") }, { value: "allowlist", label: t("group.config.scope.allowlist") }]} />
        </div>
        {modelScope === "allowlist" && (
          <div className="field form-wide">
            <fieldset className="choice-field">
              <legend>{t("group.config.allowlistModels")}<span className="hint">{t("group.config.allowlistHint")}</span></legend>
              {models.isLoading
                ? <p className="muted">{t("common.loading")}</p>
                : models.isError
                  ? <small className="field-error" role="alert">{t("action.optionLoadFailed")}</small>
                  : publishedModels.length === 0
                    ? <p className="muted">{t("group.config.noPublishedModels")}</p>
                    : (
                      <div className="choice-grid">
                        {publishedModels.map((model) => {
                          const id = String(model.id ?? "");
                          return (
                            <label key={id} className="choice-card">
                              <input
                                type="checkbox"
                                checked={selectedModels.includes(id)}
                                onChange={(event) => setSelectedModels((current) => (event.target.checked ? [...current, id] : current.filter((item) => item !== id)))}
                              />
                              <span>{String(model.display_name ?? model.upstream_model_id ?? id)}</span>
                            </label>
                          );
                        })}
                      </div>
                    )}
            </fieldset>
          </div>
        )}

        <div className="form-section-label form-wide"><span>04</span><div><b>{t("group.config.section.egress")}</b></div></div>
        <div className="field"><label htmlFor="cfg-egress">{t("group.config.egressMode")}</label>
          <SelectField id="cfg-egress" name="egress_mode" required defaultValue={typeof active.egress_mode === "string" ? active.egress_mode : "auto"}
            options={[{ value: "auto", label: t("group.config.egress.auto") }, { value: "direct_only", label: t("group.config.egress.direct_only") }, { value: "proxy_only", label: t("group.config.egress.proxy_only") }]} />
        </div>
        <div className="field"><span className="field-label">{t("group.config.fullyManaged")}</span>
          <label className="choice-card"><input type="checkbox" name="fully_managed_required" defaultChecked={active.fully_managed_required === true} /><span>{t("common.yes")}</span></label>
        </div>

        <div className="form-section-label form-wide"><span>05</span><div><b>{t("group.config.section.limits")}</b></div></div>
        <div className="field"><label htmlFor="cfg-concurrency">{t("group.config.groupConcurrency")}<span className="hint">{t("group.config.unlimitedHint")}</span></label>
          <input id="cfg-concurrency" name="concurrency" className="inp" type="number" min={1} defaultValue={asNumber(limits.concurrency) ?? ""} /></div>
        <div className="field"><label htmlFor="cfg-rpm">{t("group.config.messagesRpm")}<span className="hint">{t("group.config.unlimitedHint")}</span></label>
          <input id="cfg-rpm" name="messages_rpm" className="inp" type="number" min={1} defaultValue={asNumber(limits.messages_rpm) ?? ""} /></div>
        <div className="field"><label htmlFor="cfg-burst">{t("group.config.messagesBurst")}<span className="hint">{t("group.config.rpmPairHint")}</span></label>
          <input id="cfg-burst" name="messages_burst" className="inp" type="number" min={0} defaultValue={asNumber(limits.messages_burst) ?? ""} /></div>
        <div className="field"><label htmlFor="cfg-queue-capacity">{t("group.config.queueCapacity")}</label>
          <input id="cfg-queue-capacity" className="inp" value={asNumber(queue.capacity) ?? ""} placeholder={t("group.config.queueAuto")} readOnly aria-readonly="true" /></div>

        <details className="advanced-settings form-wide">
          <summary>{t("common.advanced")}</summary>
          <p>{t("common.advancedHint")}</p>
          <div className="config-draft-grid">
            <div className="field"><label htmlFor="cfg-cred-concurrency">{t("group.config.credentialConcurrency")}</label>
              <input id="cfg-cred-concurrency" name="credential_concurrency" className="inp" type="number" required min={1} defaultValue={numberOrDefault(defaults.concurrency, 5)} /></div>
            <div className="field"><label htmlFor="cfg-cred-rpm">{t("group.config.credentialRpm")}</label>
              <input id="cfg-cred-rpm" name="credential_rpm" className="inp" type="number" required min={1} defaultValue={numberOrDefault(defaults.messages_rpm, 60)} /></div>
            <div className="field"><label htmlFor="cfg-pre-upstream">{t("group.config.preUpstreamTimeout")}</label>
              <input id="cfg-pre-upstream" name="pre_upstream_timeout_ms" className="inp" type="number" required min={1000} max={600_000} defaultValue={numberOrDefault(queue.pre_upstream_timeout_ms, 30_000)} /></div>
            <div className="field"><label htmlFor="cfg-connect">{t("group.config.connectTimeout")}</label>
              <input id="cfg-connect" name="upstream_connect_ms" className="inp" type="number" required min={1000} max={30_000} defaultValue={numberOrDefault(timeouts.upstream_connect_ms, 10_000)} /></div>
            <div className="field"><label htmlFor="cfg-non-stream">{t("group.config.nonStreamTimeout")}</label>
              <input id="cfg-non-stream" name="upstream_non_stream_total_ms" className="inp" type="number" required min={5000} max={3_600_000} defaultValue={numberOrDefault(timeouts.upstream_non_stream_total_ms, 600_000)} /></div>
            <div className="field"><label htmlFor="cfg-stream-idle">{t("group.config.streamIdleTimeout")}</label>
              <input id="cfg-stream-idle" name="upstream_stream_idle_ms" className="inp" type="number" required min={5000} max={600_000} defaultValue={numberOrDefault(timeouts.upstream_stream_idle_ms, 120_000)} /></div>
            <div className="field"><span className="field-label">{t("group.config.consoleFallback")}</span>
              <label className="choice-card"><input type="checkbox" name="console_business_fallback_enabled" defaultChecked={governance.console_business_fallback_enabled === true} /><span>{t("common.yes")}</span></label>
            </div>
            <div className="field"><label htmlFor="cfg-default-os">{t("group.config.defaultOsFamily")}</label>
              <SelectField id="cfg-default-os" name="default_os_family" required defaultValue={stringOf(active.default_os_family) ?? "windows"}
                options={[{ value: "windows", label: t("group.config.os.windows") }, { value: "macos", label: t("group.config.os.macos") }, { value: "linux", label: t("group.config.os.linux") }]} />
            </div>
          </div>
        </details>
      </div>
      <div className="policy-note"><Icon name="info" /><span>{t("group.config.inheritNote")}</span></div>
      <div className="modal-foot">
        <button type="button" className="btn btn-ghost" onClick={onBack} disabled={submitting}>{t("credential.form.back")}</button>
        <button type="button" className="btn btn-ghost" disabled={submitting} onClick={(event) => { intentRef.current = "draft"; event.currentTarget.form?.requestSubmit(); }}>{t("group.config.saveDraft")}</button>
        <button type="submit" className="btn btn-primary" disabled={submitting}>{submitting ? t("common.submitting") : t("group.config.saveAndActivate")}</button>
      </div>
    </form>
  );
}

export function GroupDetailDialog({ row, onClose }: { row: Row; onClose(): void }) {
  const { t } = useI18n();
  const queryClient = useQueryClient();
  const id = String(row.id ?? "");
  const endpoint = `/admin/v1/groups/${encodeURIComponent(id)}`;
  const detail = useQuery({ queryKey: [endpoint], queryFn: () => api<Row>(endpoint), retry: false });
  const capacity = useQuery({ queryKey: [`${endpoint}/capacity`], queryFn: () => api<Row>(`${endpoint}/capacity`), retry: false });
  const credentials = useQuery({ queryKey: [`${endpoint}/credentials`], queryFn: () => api<Row[]>(`${endpoint}/credentials`), retry: false });
  const versions = useQuery({ queryKey: [`${endpoint}/config-versions`], queryFn: () => api<Row[]>(`${endpoint}/config-versions`), retry: false });
  const [tab, setTab] = useState<Tab>("scheduling");
  const [configDraft, setConfigDraft] = useState(true);
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  const record = detail.data ?? {};
  const versionRows = (versions.data ?? []).filter((item): item is Row => typeof item === "object" && item !== null);
  const credentialRows = (credentials.data ?? []).filter((item): item is Row => typeof item === "object" && item !== null);
  const activeConfig = versionRows.find((item) => item.is_active === true);
  // 容量投影中的 queue 是嵌套对象,拍平便于键值网格展示
  const capacityRecord: Row = (() => {
    const raw = capacity.data ?? {};
    const flattened: Row = {};
    for (const [key, value] of Object.entries(raw)) {
      if (key === "queue" && value && typeof value === "object") {
        const queue = value as Row;
        flattened.queue_used = queue.used;
        flattened.queue_capacity = queue.capacity;
      } else if (value === null || typeof value !== "object") {
        flattened[key] = value;
      }
    }
    return flattened;
  })();

  async function refreshVersions() {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: [`${endpoint}/config-versions`] }),
      queryClient.invalidateQueries({ queryKey: [endpoint] }),
      queryClient.invalidateQueries({ queryKey: [`${endpoint}/capacity`] }),
      queryClient.invalidateQueries({ queryKey: ["/admin/v1/groups"] }),
    ]);
  }

  const tabs: { key: Tab; label: MessageKey }[] = [
    { key: "overview", label: "group.tab.overview" },
    { key: "credentials", label: "group.tab.credentials" },
    { key: "scheduling", label: "group.tab.scheduling" },
    { key: "governance", label: "group.tab.governance" },
    { key: "egress", label: "group.tab.egress" },
    { key: "versions", label: "group.tab.versions" },
  ];

  return createPortal(
    <div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section className="modal group-detail-modal" role="dialog" aria-modal="true" aria-labelledby="group-detail-title">
        <div className="modal-head">
          <div>
            <p className="eyebrow mono">GROUP / OPS</p>
            <h3 id="group-detail-title">{t("group.detail.title")}</h3>
            <p className="muted mono breakable">{String(record.name ?? row.name ?? id)}</p>
          </div>
          <button type="button" className="ibtn outline" aria-label={t("common.close")} onClick={onClose}>×</button>
        </div>
        <div className="modal-body credential-detail-body">
          <PaneStatus loading={detail.isLoading} error={detail.error}>
            {configDraft && activeConfig ? (
              <ConfigDraftForm
                endpoint={endpoint}
                active={activeConfig}
                onBack={() => setConfigDraft(false)}
                onDone={async (leave) => {
                  await refreshVersions();
                  if (leave) {
                    setConfigDraft(false);
                    setTab("versions");
                  }
                }}
              />
            ) : (
              <>
                <div className="segmented local detail-tabs" role="group" aria-label={t("group.detail.title")}>
                  {tabs.map((item) => <button key={item.key} type="button" className={tab === item.key ? "active" : ""} aria-pressed={tab === item.key} onClick={() => setTab(item.key)}>{t(item.label)}</button>)}
                </div>
                <div className="detail-pane">
                  {tab === "overview" && (
                    <div className="group-overview">
                      <DataGrid record={record} />
                      <h4 className="detail-section-heading">{t("group.capacity.title")}</h4>
                      <PaneStatus loading={capacity.isLoading} error={capacity.error}>
                        <DataGrid record={capacityRecord} />
                      </PaneStatus>
                    </div>
                  )}
                  {tab === "credentials" && (
                    <PaneStatus loading={credentials.isLoading} error={credentials.error}>
                      <SubTable rows={credentialRows} columns={deriveColumns(credentialRows, ["account_uuid", "auth_kind", "lifecycle_state", "scheduling_state", "priority", "weight", "created_at"])} empty={t("group.credentials.none")} />
                    </PaneStatus>
                  )}
                  {(tab === "scheduling" || tab === "governance" || tab === "egress") && (
                    <PaneStatus loading={versions.isLoading} error={versions.error}>
                      {activeConfig
                        ? <ConfigPane config={activeConfig} tab={tab} onAdjust={() => setConfigDraft(true)} />
                        : <p className="muted">{t("group.config.none")}</p>}
                    </PaneStatus>
                  )}
                  {tab === "versions" && (
                    <PaneStatus loading={versions.isLoading} error={versions.error}>
                      <VersionsPane endpoint={endpoint} versions={versionRows} onChanged={refreshVersions} onNewDraft={activeConfig ? () => setConfigDraft(true) : undefined} />
                    </PaneStatus>
                  )}
                </div>
              </>
            )}
          </PaneStatus>
        </div>
      </section>
    </div>,
    document.body,
  );
}
