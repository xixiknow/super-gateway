import { FormEvent, useId, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "./api";
import { Drawer } from "./drawer";
import { useConfirm, useToast } from "./feedback";
import { useI18n } from "./i18n";
import { SelectField } from "./select-field";

type RecordRow = Record<string, unknown>;
type JsonScalar = string | number | boolean | null;
type ConditionOp = "always" | "present" | "equals" | "in" | "preserved";

interface RuleDraft {
  key: number;
  id: string;
  path: string;
  action: "required" | "allowed" | "forbidden";
  types: string[];
  enumText: string;
  minimum: string;
  maximum: string;
  exclusiveMaximumPath: string;
  requiredChildrenText: string;
  conditionOp: ConditionOp;
  conditionPath: string;
  conditionValuesText: string;
  conditionMode: "any_match" | "all_match";
  preservedCondition?: RecordRow;
}

interface CapabilityWorkbenchProps {
  modelId: string;
  modelRevision: number;
  maxOutputTokens: number | null;
  versions: RecordRow[];
  loading: boolean;
  error: boolean;
}

const jsonTypes = ["null", "boolean", "integer", "number", "string", "array", "object"] as const;
const ruleGroupOrder = ["base", "output", "thinking", "effort", "sampling", "other"] as const;
type RuleGroup = typeof ruleGroupOrder[number];
let nextRuleKey = 1;

function text(row: RecordRow, key: string): string {
  const value = row[key];
  return value === null || value === undefined ? "" : String(value);
}

function positiveRevision(value: unknown): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : 1;
}

function object(value: unknown): RecordRow | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as RecordRow : null;
}

function scalar(value: string): JsonScalar {
  const trimmed = value.trim();
  if (trimmed === "null") return null;
  if (trimmed === "true") return true;
  if (trimmed === "false") return false;
  if (trimmed !== "" && Number.isFinite(Number(trimmed))) return Number(trimmed);
  return trimmed;
}

function scalarLines(value: string): JsonScalar[] {
  return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean).map(scalar);
}

function stringLines(value: string): string[] {
  return [...new Set(value.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean))];
}

function numberOrNull(value: string): number | null {
  if (!value.trim()) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

function conditionFrom(value: unknown): Pick<RuleDraft, "conditionOp" | "conditionPath" | "conditionValuesText" | "conditionMode" | "preservedCondition"> {
  const condition = object(value) ?? { op: "always" };
  const op = text(condition, "op");
  const mode = text(condition, "mode") === "all_match" ? "all_match" : "any_match";
  if (op === "present") return { conditionOp: "present", conditionPath: text(condition, "path"), conditionValuesText: "", conditionMode: mode };
  if (op === "equals") return { conditionOp: "equals", conditionPath: text(condition, "path"), conditionValuesText: formatScalar(condition.value), conditionMode: mode };
  if (op === "in") return { conditionOp: "in", conditionPath: text(condition, "path"), conditionValuesText: Array.isArray(condition.values) ? condition.values.map(formatScalar).join("\n") : "", conditionMode: mode };
  if (op === "always" || !op) return { conditionOp: "always", conditionPath: "", conditionValuesText: "", conditionMode: "any_match" };
  return { conditionOp: "preserved", conditionPath: "", conditionValuesText: "", conditionMode: "any_match", preservedCondition: condition };
}

function formatScalar(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

function ruleFrom(value: unknown): RuleDraft {
  const rule = object(value) ?? {};
  return {
    key: nextRuleKey++,
    id: text(rule, "id"),
    path: text(rule, "path"),
    action: (["required", "allowed", "forbidden"] as const).includes(rule.action as never) ? rule.action as RuleDraft["action"] : "allowed",
    types: Array.isArray(rule.types) ? rule.types.filter((item): item is string => typeof item === "string" && (jsonTypes as readonly string[]).includes(item)) : [],
    enumText: Array.isArray(rule.enum_values) ? rule.enum_values.map(formatScalar).join("\n") : "",
    minimum: typeof rule.minimum === "number" ? String(rule.minimum) : "",
    maximum: typeof rule.maximum === "number" ? String(rule.maximum) : "",
    exclusiveMaximumPath: text(rule, "exclusive_maximum_path"),
    requiredChildrenText: Array.isArray(rule.required_children) ? rule.required_children.filter((item): item is string => typeof item === "string").join("\n") : "",
    ...conditionFrom(rule.when),
  };
}

function defaultRule(maxOutputTokens: number | null): RuleDraft {
  return ruleFrom({
    id: "provider-max-output-tokens",
    path: "body:/max_tokens",
    action: "required",
    types: ["integer"],
    enum_values: [],
    minimum: 1,
    maximum: maxOutputTokens,
    required_children: [],
    when: { op: "always" },
  });
}

function rulesFromVersion(version: RecordRow | undefined, maxOutputTokens: number | null): RuleDraft[] {
  const payload = object(version?.schema_payload);
  const rules = Array.isArray(payload?.rules) ? payload.rules.map(ruleFrom) : [];
  return rules.length ? rules : [defaultRule(maxOutputTokens)];
}

function conditionPayload(rule: RuleDraft): RecordRow {
  if (rule.conditionOp === "preserved") return rule.preservedCondition ?? { op: "always" };
  if (rule.conditionOp === "always") return { op: "always" };
  const base: RecordRow = { op: rule.conditionOp, path: rule.conditionPath.trim(), mode: rule.conditionMode };
  if (rule.conditionOp === "equals") base.value = scalarLines(rule.conditionValuesText)[0] ?? null;
  if (rule.conditionOp === "in") base.values = scalarLines(rule.conditionValuesText);
  return base;
}

function payloadRule(rule: RuleDraft): RecordRow {
  return {
    id: rule.id.trim(),
    path: rule.path.trim(),
    action: rule.action,
    types: rule.types,
    enum_values: scalarLines(rule.enumText),
    minimum: numberOrNull(rule.minimum),
    maximum: numberOrNull(rule.maximum),
    exclusive_maximum_path: rule.exclusiveMaximumPath.trim() || null,
    required_children: stringLines(rule.requiredChildrenText),
    when: conditionPayload(rule),
  };
}

function ruleGroup(value: Pick<RuleDraft, "id" | "path"> | RecordRow): RuleGroup {
  const id = text(value as RecordRow, "id").toLowerCase();
  const path = text(value as RecordRow, "path");
  if (id.includes("thinking") || path.startsWith("body:/thinking")) return "thinking";
  if (id.includes("effort") || path === "body:/output_config/effort") return "effort";
  if (id.includes("sampling") || ["body:/temperature", "body:/top_p", "body:/top_k"].includes(path)) return "sampling";
  if (id.includes("max-token") || path === "body:/max_tokens") return "output";
  if (id.startsWith("base-")) return "base";
  return "other";
}

function groupLabel(group: RuleGroup, t: ReturnType<typeof useI18n>["t"]): string {
  if (group === "base") return t("models.workbench.group.base");
  if (group === "output") return t("models.workbench.group.output");
  if (group === "thinking") return t("models.workbench.group.thinking");
  if (group === "effort") return t("models.workbench.group.effort");
  if (group === "sampling") return t("models.workbench.group.sampling");
  return t("models.workbench.group.other");
}

function versionRules(version: RecordRow): RecordRow[] {
  const payload = object(version.schema_payload);
  return Array.isArray(payload?.rules)
    ? payload.rules.filter((rule): rule is RecordRow => Boolean(object(rule)))
    : [];
}

function versionMetadata(version: RecordRow): RecordRow | null {
  return object(object(version.schema_payload)?.metadata);
}

function requestError(error: unknown, t: ReturnType<typeof useI18n>["t"]): string {
  if (error instanceof ApiError) return t("models.workbench.error.request", { status: error.status, message: error.message });
  return error instanceof Error ? error.message : t("common.operationFailed");
}

export function CapabilityWorkbench({ modelId, modelRevision, maxOutputTokens, versions, loading, error }: CapabilityWorkbenchProps) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const sorted = useMemo(() => [...versions].sort((left, right) => Number(right.capability_version ?? 0) - Number(left.capability_version ?? 0)), [versions]);
  const currentRevision = Math.max(modelRevision, ...sorted.map((version) => positiveRevision(version.model_revision)));
  const [editing, setEditing] = useState(false);
  const [sourceId, setSourceId] = useState<string | null>(null);
  const [rules, setRules] = useState<RuleDraft[]>(() => [defaultRule(maxOutputTokens)]);
  const [reason, setReason] = useState("");
  const [formError, setFormError] = useState("");
  const [validatedId, setValidatedId] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const editorFormId = useId();

  const createVersion = useMutation({
    mutationFn: (payload: RecordRow) => api<RecordRow>("/admin/v1/capability-versions", { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["/admin/v1/capability-versions"] });
      setEditing(false);
      setDirty(false);
      setReason("");
      setValidatedId(null);
      toast.success(t("models.workbench.created"));
    },
    onError: (failure) => setFormError(requestError(failure, t)),
  });
  const validateVersion = useMutation({
    mutationFn: (version: RecordRow) => api<RecordRow>(`/admin/v1/capability-versions/${encodeURIComponent(text(version, "id"))}:validate`, {
      method: "POST",
      headers: { "If-Match": `"rev-${currentRevision}"` },
      body: JSON.stringify({ expected_revision: currentRevision }),
    }),
    onSuccess: (_, version) => {
      setValidatedId(text(version, "id"));
      toast.success(t("models.workbench.valid"));
    },
    onError: (failure) => toast.error(requestError(failure, t)),
  });
  const activateVersion = useMutation({
    mutationFn: ({ version, actionReason }: { version: RecordRow; actionReason: string }) => api<RecordRow>(`/admin/v1/capability-versions/${encodeURIComponent(text(version, "id"))}:activate`, {
      method: "POST",
      headers: { "If-Match": `"rev-${currentRevision}"` },
      body: JSON.stringify({ reason: actionReason, expected_revision: currentRevision }),
    }),
    onSuccess: async () => {
      setValidatedId(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["/admin/v1/capability-versions"] }),
        queryClient.invalidateQueries({ queryKey: ["/admin/v1/models"] }),
      ]);
      toast.success(t("models.workbench.activated"));
    },
    onError: (failure) => toast.error(requestError(failure, t)),
  });

  function beginEdit(version?: RecordRow) {
    setSourceId(version ? text(version, "id") : null);
    setRules(rulesFromVersion(version, maxOutputTokens));
    setReason("");
    setFormError("");
    setDirty(false);
    createVersion.reset();
    setEditing(true);
  }

  function updateRule(key: number, patch: Partial<RuleDraft>) {
    setRules((current) => current.map((rule) => rule.key === key ? { ...rule, ...patch } : rule));
    setFormError("");
    setDirty(true);
  }

  /** ×、Esc、遮罩、取消四条关闭路径统一入口:有未保存改动时先确认 */
  async function requestCloseEditor() {
    if (dirty) {
      const result = await confirm({ titleKey: "models.workbench.discardTitle", bodyKey: "models.workbench.discardBody", confirmKey: "models.workbench.discardConfirm", danger: true });
      if (!result.ok) return;
    }
    setEditing(false);
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const compiled = rules.map(payloadRule);
    if (!reason.trim() || compiled.length === 0 || compiled.some((rule) => !rule.id || !rule.path || !object(rule.when)?.op || Number.isNaN(rule.minimum) || Number.isNaN(rule.maximum))) {
      setFormError(t("models.workbench.error.required"));
      return;
    }
    const invalidRange = compiled.findIndex((rule) => typeof rule.minimum === "number" && typeof rule.maximum === "number" && rule.minimum > rule.maximum);
    if (invalidRange >= 0) {
      setFormError(t("models.workbench.error.range", { index: invalidRange + 1 }));
      return;
    }
    createVersion.mutate({ model_id: modelId, schema_version: 1, rules: compiled, reason: reason.trim() });
  }

  async function activate(version: RecordRow) {
    const result = await confirm({
      titleKey: "models.workbench.activateTitle",
      bodyKey: "models.workbench.activateBody",
      bodyVars: { version: Number(version.capability_version ?? 0) },
      confirmKey: "models.workbench.activateConfirm",
      withReason: true,
    });
    if (result.ok) activateVersion.mutate({ version, actionReason: result.reason });
  }

  const sourceVersion = sorted.find((version) => text(version, "id") === sourceId);

  if (loading) return <div className="capability-placeholder"><span className="spin sm" aria-hidden="true" /></div>;
  if (error) return <p className="capability-empty">{t("models.capability.gatewayError")}</p>;

  return <div className="capability-workbench">
    <p className="capability-workbench-note">{t("models.workbench.versionHint")}</p>
    {sorted.length === 0 ? <div className="capability-empty"><p>{t("models.capability.gatewayEmpty")}</p><button type="button" className="btn btn-primary btn-sm" onClick={() => beginEdit()}>{t("models.workbench.create")}</button></div> : <div className="capability-version-list">
      {sorted.map((version) => {
        const lifecycle = text(version, "lifecycle");
        const origin = text(version, "origin") || "manual";
        const isValidated = validatedId === text(version, "id");
        const metadata = versionMetadata(version);
        const completeness = text(metadata ?? {}, "profile_completeness");
        const profileVersion = text(metadata ?? {}, "profile_version");
        const sourceUrls = Array.isArray(metadata?.source_urls) ? metadata.source_urls.filter((url): url is string => typeof url === "string") : [];
        const currentRules = versionRules(version);
        const versionRuleGroups = ruleGroupOrder.map((group) => ({
          group,
          count: currentRules.filter((rule) => ruleGroup(rule) === group).length,
        }));
        return <article className={`capability-version-card state-${lifecycle}`} key={text(version, "id")}>
          <div className="capability-version-main"><div><b>v{String(version.capability_version ?? "—")}</b><span className={`model-lifecycle state-${lifecycle}`}>{lifecycle === "active" ? (locale === "zh-CN" ? "活跃" : "Active") : lifecycle === "candidate" ? (locale === "zh-CN" ? "候选" : "Candidate") : (locale === "zh-CN" ? "已退役" : "Retired")}</span><span className={`capability-origin origin-${origin}`}>{origin === "system_discovery" ? t("models.workbench.system") : t("models.workbench.manual")}</span></div><time>{text(version, "created_at") ? new Date(text(version, "created_at")).toLocaleString(locale) : "—"}</time></div>
          <div className="capability-profile-meta"><span className={`profile-completeness is-${completeness || "legacy"}`}>{completeness === "complete" ? t("models.workbench.complete") : completeness === "partial" ? t("models.workbench.partial") : t("models.workbench.legacy")}</span>{profileVersion && <code>{t("models.workbench.matrix")} {profileVersion}</code>}<span>{t("models.workbench.ruleCount", { count: currentRules.length })}</span></div>
          <div className="capability-rule-summary">{versionRuleGroups.filter(({ count }) => count > 0).map(({ group, count }) => <span key={group}><b>{groupLabel(group, t)}</b><i>{count}</i></span>)}</div>
          {sourceUrls.length > 0 && <div className="capability-source-links"><span>{t("models.workbench.sources")}</span>{sourceUrls.map((url, index) => <a key={url} href={url} target="_blank" rel="noreferrer">{index + 1}</a>)}</div>}
          <div className="capability-version-actions">
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => beginEdit(version)}>{t("models.workbench.edit")}</button>
            {lifecycle === "candidate" && <button type="button" className="btn btn-outline btn-sm" disabled={validateVersion.isPending} onClick={() => validateVersion.mutate(version)}>{isValidated ? t("models.workbench.validated") : t("models.workbench.validate")}</button>}
            {lifecycle === "candidate" && <button type="button" className="btn btn-primary btn-sm" disabled={!isValidated || activateVersion.isPending} onClick={() => void activate(version)}>{t("models.workbench.activate")}</button>}
          </div>
        </article>;
      })}
    </div>}
    {sorted.length > 0 && !editing && <button type="button" className="btn btn-outline capability-create-button" onClick={() => beginEdit(sorted[0])}>{t("models.workbench.create")}</button>}
    {editing && <Drawer
      cascade
      className="capability-editor-drawer"
      eyebrow="GATEWAY CAPABILITY"
      title={t("models.workbench.editorTitle")}
      subtitle={sourceVersion ? t("models.workbench.sourceVersion", { version: Number(sourceVersion.capability_version ?? 0) }) : t("models.workbench.create")}
      onRequestClose={() => void requestCloseEditor()}
      foot={<>
        <button type="button" className="btn btn-ghost" onClick={() => void requestCloseEditor()}>{t("common.cancel")}</button>
        <button type="submit" form={editorFormId} className="btn btn-primary" disabled={createVersion.isPending}>{createVersion.isPending ? t("models.workbench.creating") : t("models.workbench.save")}</button>
      </>}
    >
      <form id={editorFormId} className="capability-rule-editor in-drawer" onSubmit={submit}>
        <p className="capability-editor-hint">{t("models.workbench.editorHint")}</p>
        <div className="field"><label htmlFor={`capability-reason-${modelId}`}>{t("models.workbench.reason")}</label><textarea id={`capability-reason-${modelId}`} className="inp" rows={2} maxLength={2048} value={reason} placeholder={t("models.workbench.reasonPlaceholder")} onChange={(event) => { setReason(event.target.value); setFormError(""); setDirty(true); }} /></div>
        <div className="capability-editor-rules">{ruleGroupOrder.map((group) => {
          const entries = rules.map((rule, index) => ({ rule, index })).filter(({ rule }) => ruleGroup(rule) === group);
          if (entries.length === 0) return null;
          return <section className={`capability-rule-group group-${group}`} key={group}><header><h5>{groupLabel(group, t)}</h5><span>{entries.length}</span></header><div>{entries.map(({ rule, index }) => <RuleEditor key={rule.key} rule={rule} index={index} onChange={(patch) => updateRule(rule.key, patch)} onRemove={() => { setRules((current) => current.filter((item) => item.key !== rule.key)); setDirty(true); }} />)}</div></section>;
        })}</div>
        <button type="button" className="btn btn-ghost capability-add-rule" onClick={() => { setRules((current) => [...current, ruleFrom({ id: `rule-${current.length + 1}`, action: "allowed", when: { op: "always" } })]); setDirty(true); }}>＋ {t("models.workbench.addRule")}</button>
        {formError && <p className="capability-form-error" role="alert">{formError}</p>}
      </form>
    </Drawer>}
  </div>;
}

function RuleEditor({ rule, index, onChange, onRemove }: { rule: RuleDraft; index: number; onChange(patch: Partial<RuleDraft>): void; onRemove(): void }) {
  const { t } = useI18n();
  const prefix = `capability-rule-${rule.key}`;
  return <fieldset className="capability-rule-card"><legend>{t("models.workbench.rule", { index: index + 1 })}</legend><button type="button" className="capability-remove-rule" onClick={onRemove}>{t("models.workbench.removeRule")}</button>
    <div className="capability-rule-grid"><div className="field"><label htmlFor={`${prefix}-id`}>{t("models.workbench.ruleId")}</label><input id={`${prefix}-id`} className="inp mono" value={rule.id} maxLength={128} onChange={(event) => onChange({ id: event.target.value })} /></div><div className="field field-wide"><label htmlFor={`${prefix}-path`}>{t("models.workbench.path")}</label><input id={`${prefix}-path`} className="inp mono" value={rule.path} maxLength={1024} placeholder="body:/max_tokens" onChange={(event) => onChange({ path: event.target.value })} /><small>{t("models.workbench.pathHint")}</small></div><div className="field"><label htmlFor={`${prefix}-action`}>{t("models.workbench.action")}</label><SelectField id={`${prefix}-action`} value={rule.action} onChange={(next) => onChange({ action: next as RuleDraft["action"] })} options={[{ value: "required", label: t("models.workbench.required") }, { value: "allowed", label: t("models.workbench.allowed") }, { value: "forbidden", label: t("models.workbench.forbidden") }]} /></div></div>
    <div className="field"><label>{t("models.workbench.types")}</label><div className="capability-type-grid">{jsonTypes.map((type) => <label key={type}><input type="checkbox" checked={rule.types.includes(type)} onChange={(event) => onChange({ types: event.target.checked ? [...rule.types, type] : rule.types.filter((item) => item !== type) })} /><span>{type}</span></label>)}</div></div>
    <div className="capability-rule-grid numeric"><div className="field"><label htmlFor={`${prefix}-minimum`}>{t("models.workbench.minimum")}</label><input id={`${prefix}-minimum`} type="number" className="inp mono" value={rule.minimum} onChange={(event) => onChange({ minimum: event.target.value })} /></div><div className="field"><label htmlFor={`${prefix}-maximum`}>{t("models.workbench.maximum")}</label><input id={`${prefix}-maximum`} type="number" className="inp mono" value={rule.maximum} onChange={(event) => onChange({ maximum: event.target.value })} /></div><div className="field"><label htmlFor={`${prefix}-exclusive-maximum`}>{t("models.workbench.exclusiveMaximumPath")}</label><input id={`${prefix}-exclusive-maximum`} className="inp mono" value={rule.exclusiveMaximumPath} placeholder="body:/max_tokens" onChange={(event) => onChange({ exclusiveMaximumPath: event.target.value })} /><small>{t("models.workbench.exclusiveMaximumHint")}</small></div><div className="field"><label htmlFor={`${prefix}-enum`}>{t("models.workbench.enumValues")}</label><textarea id={`${prefix}-enum`} className="inp mono" rows={2} value={rule.enumText} onChange={(event) => onChange({ enumText: event.target.value })} /><small>{t("models.workbench.enumHint")}</small></div><div className="field"><label htmlFor={`${prefix}-children`}>{t("models.workbench.requiredChildren")}</label><textarea id={`${prefix}-children`} className="inp mono" rows={2} value={rule.requiredChildrenText} onChange={(event) => onChange({ requiredChildrenText: event.target.value })} /><small>{t("models.workbench.childrenHint")}</small></div></div>
    <div className="capability-condition"><div className="field"><label htmlFor={`${prefix}-condition`}>{t("models.workbench.condition")}</label><SelectField id={`${prefix}-condition`} value={rule.conditionOp} onChange={(next) => onChange({ conditionOp: next as ConditionOp })} options={[{ value: "always", label: t("models.workbench.conditionAlways") }, { value: "present", label: t("models.workbench.conditionPresent") }, { value: "equals", label: t("models.workbench.conditionEquals") }, { value: "in", label: t("models.workbench.conditionIn") }, ...(rule.conditionOp === "preserved" ? [{ value: "preserved", label: t("models.workbench.conditionPreserved") }] : [])]} /></div>{!(["always", "preserved"] as ConditionOp[]).includes(rule.conditionOp) && <><div className="field"><label htmlFor={`${prefix}-condition-path`}>{t("models.workbench.conditionPath")}</label><input id={`${prefix}-condition-path`} className="inp mono" value={rule.conditionPath} onChange={(event) => onChange({ conditionPath: event.target.value })} /></div><div className="field"><label htmlFor={`${prefix}-condition-mode`}>{t("models.workbench.matchMode")}</label><SelectField id={`${prefix}-condition-mode`} value={rule.conditionMode} onChange={(next) => onChange({ conditionMode: next as RuleDraft["conditionMode"] })} options={[{ value: "any_match", label: t("models.workbench.anyMatch") }, { value: "all_match", label: t("models.workbench.allMatch") }]} /></div>{(["equals", "in"] as ConditionOp[]).includes(rule.conditionOp) && <div className="field"><label htmlFor={`${prefix}-condition-values`}>{t("models.workbench.conditionValues")}</label><textarea id={`${prefix}-condition-values`} className="inp mono" rows={2} value={rule.conditionValuesText} onChange={(event) => onChange({ conditionValuesText: event.target.value })} /></div>}</>}</div>
  </fieldset>;
}
