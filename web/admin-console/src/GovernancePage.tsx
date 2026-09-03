import { FormEvent, ReactNode, useState } from "react";
import { createPortal } from "react-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useConfirm, useToast } from "./feedback";
import { MessageKey, useI18n } from "./i18n";
import { rowActionError } from "./row-actions";
import { SelectField } from "./select-field";
import { Icon, PaneStatus, Row, SubTable } from "./detail-kit";

/* ============================================================
   规则与治理(规划 §22 / 模块 08):管理不可变政策工件
   - 规则集:结构化规则编辑 + 校验/模拟/Shadow/激活
   - 价格:模型单价版本
   ============================================================ */

type View = "rulesets" | "prices";

const RULESETS = "/admin/v1/rulesets";
const PRICES = "/admin/v1/price-versions";
const MODELS = "/admin/v1/models";
const GROUPS = "/admin/v1/groups";

function record(value: unknown): Row {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Row) : {};
}

function items(value: unknown): Row[] {
  return Array.isArray(value) ? value.filter((item): item is Row => typeof item === "object" && item !== null) : [];
}

/** 工件 payload 信封:{name, rules|payload, source_refs};类型化工件的业务体在 payload 内 */
function artifactEnvelope(row: Row): Row {
  return record(row.payload);
}

function artifactName(row: Row): string {
  const name = artifactEnvelope(row).name;
  return typeof name === "string" && name ? name : String(row.id ?? "");
}

function shortId(value: unknown): string {
  const text = String(value ?? "");
  return text.length > 12 ? `${text.slice(0, 8)}…${text.slice(-4)}` : text;
}

const LIFECYCLE_LABELS: Record<string, [string, string]> = {
  draft: ["草稿", "Draft"], validating: ["校验中", "Validating"], eligible: ["待发布", "Eligible"],
  shadow: ["Shadow", "Shadow"], canary: ["Canary", "Canary"], active: ["生效中", "Active"],
  retired: ["已退役", "Retired"], quarantined: ["已隔离", "Quarantined"],
};

function lifecycleLabel(value: unknown, zh: boolean): string {
  const raw = String(value ?? "");
  const pair = LIFECYCLE_LABELS[raw];
  return pair ? pair[zh ? 0 : 1] : raw;
}

function parseJsonOrString(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) return "";
  try {
    return JSON.parse(trimmed);
  } catch {
    return trimmed;
  }
}

interface ModelRecord { id?: unknown; display_name?: unknown; upstream_model_id?: unknown; lifecycle?: unknown }
interface GroupRecord { id?: unknown; name?: unknown; status?: unknown }

/** 生命周期动作统一执行器:If-Match 用工件版本乐观锁,高风险动作附审批单 */
function useArtifactActions(endpoint: string) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);

  async function run(row: Row, suffix: string, options?: { titleKey?: MessageKey; danger?: boolean }) {
    const version = typeof row.version === "number" ? row.version : undefined;
    const id = String(row.id ?? "");
    if (version === undefined || !id) return;
    const result = await confirm({
      titleKey: options?.titleKey ?? "group.version.confirmBody",
      bodyKey: "group.version.confirmBody",
      withReason: true,
      danger: options?.danger,
    });
    if (!result.ok) return;
    setBusy(true);
    try {
      await api(`${endpoint}/${encodeURIComponent(id)}:${suffix}`, {
        method: "POST",
        headers: { "If-Match": `"rev-${version}"` },
        body: JSON.stringify({ reason: result.reason, expected_revision: version }),
      });
      toast.success(t("action.success"));
      await queryClient.invalidateQueries({ queryKey: [endpoint] });
    } catch (error) {
      toast.error(rowActionError(error, locale));
    } finally {
      setBusy(false);
    }
  }

  return { busy, run };
}

function ActionButton({ tip, icon, disabled, onClick }: { tip: string; icon: string; disabled: boolean; onClick(): void }) {
  return (
    <button type="button" className="ibtn outline sm" data-tip={tip} aria-label={tip} disabled={disabled} onClick={onClick}>
      <Icon name={icon} />
    </button>
  );
}

function GovernanceCard({ title, onCreate, createLabel, refreshing, onRefresh, children }: {
  title: string; onCreate(): void; createLabel: string; refreshing: boolean; onRefresh(): void; children: ReactNode;
}) {
  const { t } = useI18n();
  return (
    <section className="card table-card" aria-busy={refreshing}>
      <div className="cardbar">
        <div className="cbl"><h2>{title}</h2></div>
        <div className="cbr">
          <button type="button" className="btn btn-primary" onClick={onCreate}><Icon name="plus" />{createLabel}</button>
          <button type="button" className={`ibtn outline${refreshing ? " loading" : ""}`} aria-label={t("table.refresh")} disabled={refreshing} onClick={onRefresh}><Icon name="refresh" /></button>
        </div>
      </div>
      <div className="governance-pane-body">{children}</div>
    </section>
  );
}

function GovernanceDialog({ titleKey, subtitle, wide, onClose, children }: {
  titleKey: MessageKey; subtitle?: string; wide?: boolean; onClose(): void; children: ReactNode;
}) {
  const { t } = useI18n();
  return createPortal(
    <div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section className={`modal resource-action-modal${wide ? " governance-wide-modal" : ""}`} role="dialog" aria-modal="true" aria-label={t(titleKey)}>
        <div className="modal-head">
          <div><p className="eyebrow mono">GOVERNANCE / POLICY</p><h3>{t(titleKey)}</h3>{subtitle && <p className="muted">{subtitle}</p>}</div>
          <button type="button" className="ibtn outline" aria-label={t("common.close")} onClick={onClose}>×</button>
        </div>
        {children}
      </section>
    </div>,
    document.body,
  );
}

/* ============================================================
   规则集:结构化编辑器(阶段/动作/路径/条件/风险)
   ============================================================ */

interface RuleDraft {
  key: number;
  id: string;
  phase: string;
  action: string;
  path: string;
  value: string;
  minimum: string;
  maximum: string;
  conditionOp: string;
  conditionPath: string;
  conditionValues: string;
  conditionMode: string;
  reason: string;
  risk: string;
}

let ruleKeySequence = 1;

function emptyRule(): RuleDraft {
  ruleKeySequence += 1;
  return {
    key: ruleKeySequence, id: `rule-${ruleKeySequence}`, phase: "default", action: "set_default",
    path: "body:/max_tokens", value: "", minimum: "", maximum: "",
    conditionOp: "always", conditionPath: "", conditionValues: "", conditionMode: "any_match",
    reason: "", risk: "low",
  };
}

function buildRulePayload(rule: RuleDraft): Row {
  const action: Row = { action: rule.action, path: rule.path.trim() };
  if (rule.action === "set_default" || rule.action === "set") action.value = parseJsonOrString(rule.value);
  if (rule.action === "clamp_number") {
    if (rule.minimum.trim() !== "") action.minimum = Number(rule.minimum);
    if (rule.maximum.trim() !== "") action.maximum = Number(rule.maximum);
  }
  const when: Row = { op: rule.conditionOp };
  if (rule.conditionOp !== "always") {
    when.path = rule.conditionPath.trim();
    when.mode = rule.conditionMode;
    if (rule.conditionOp === "equals") when.value = parseJsonOrString(rule.conditionValues);
    if (rule.conditionOp === "in") {
      when.values = rule.conditionValues.split(/[\n,]/).map((part) => part.trim()).filter(Boolean).map(parseJsonOrString);
    }
  }
  return { id: rule.id.trim(), phase: rule.phase, action, when, reason: rule.reason.trim(), risk: rule.risk };
}

function RuleCard({ rule, index, onChange, onRemove }: { rule: RuleDraft; index: number; onChange(patch: Partial<RuleDraft>): void; onRemove(): void }) {
  const { t } = useI18n();
  const prefix = `gov-rule-${rule.key}`;
  const needsValue = rule.action === "set_default" || rule.action === "set";
  return (
    <fieldset className="capability-rule-card">
      <legend>{t("gov.rule.legend", { index: index + 1 })}</legend>
      <button type="button" className="capability-remove-rule" onClick={onRemove}>{t("gov.rule.remove")}</button>
      <div className="config-draft-grid">
        <div className="field"><label htmlFor={`${prefix}-id`}>{t("gov.rule.id")}</label>
          <input id={`${prefix}-id`} className="inp mono" required maxLength={128} value={rule.id} onChange={(event) => onChange({ id: event.target.value })} /></div>
        <div className="field"><label htmlFor={`${prefix}-phase`}>{t("gov.rule.phase")}</label>
          <SelectField id={`${prefix}-phase`} value={rule.phase} onChange={(next) => onChange({ phase: next })}
            options={["structure_repair", "default", "range", "system", "tools", "thinking_cache", "beta_metadata"].map((value) => ({ value, label: t(`gov.phase.${value}` as MessageKey) }))} />
        </div>
        <div className="field"><label htmlFor={`${prefix}-action`}>{t("gov.rule.action")}</label>
          <SelectField id={`${prefix}-action`} value={rule.action} onChange={(next) => onChange({ action: next })}
            options={["set_default", "set", "remove", "clamp_number"].map((value) => ({ value, label: t(`gov.ruleAction.${value}` as MessageKey) }))} />
        </div>
        <div className="field"><label htmlFor={`${prefix}-path`}>{t("gov.rule.path")}<span className="hint">{t("gov.rule.pathHint")}</span></label>
          <input id={`${prefix}-path`} className="inp mono" required maxLength={1024} placeholder="body:/max_tokens" value={rule.path} onChange={(event) => onChange({ path: event.target.value })} /></div>
        {needsValue && (
          <div className="field"><label htmlFor={`${prefix}-value`}>{t("gov.rule.value")}</label>
            <input id={`${prefix}-value`} className="inp mono" required placeholder="4096" value={rule.value} onChange={(event) => onChange({ value: event.target.value })} /></div>
        )}
        {rule.action === "clamp_number" && (
          <>
            <div className="field"><label htmlFor={`${prefix}-minimum`}>{t("models.workbench.minimum")}</label>
              <input id={`${prefix}-minimum`} className="inp mono" type="number" value={rule.minimum} onChange={(event) => onChange({ minimum: event.target.value })} /></div>
            <div className="field"><label htmlFor={`${prefix}-maximum`}>{t("models.workbench.maximum")}</label>
              <input id={`${prefix}-maximum`} className="inp mono" type="number" value={rule.maximum} onChange={(event) => onChange({ maximum: event.target.value })} /></div>
          </>
        )}
        <div className="field"><label htmlFor={`${prefix}-condition`}>{t("models.workbench.condition")}</label>
          <SelectField id={`${prefix}-condition`} value={rule.conditionOp} onChange={(next) => onChange({ conditionOp: next })}
            options={[
              { value: "always", label: t("models.workbench.conditionAlways") },
              { value: "present", label: t("models.workbench.conditionPresent") },
              { value: "equals", label: t("models.workbench.conditionEquals") },
              { value: "in", label: t("models.workbench.conditionIn") },
            ]} />
        </div>
        {rule.conditionOp !== "always" && (
          <>
            <div className="field"><label htmlFor={`${prefix}-condition-path`}>{t("models.workbench.conditionPath")}</label>
              <input id={`${prefix}-condition-path`} className="inp mono" required placeholder="body:/model" value={rule.conditionPath} onChange={(event) => onChange({ conditionPath: event.target.value })} /></div>
            <div className="field"><label htmlFor={`${prefix}-condition-mode`}>{t("models.workbench.matchMode")}</label>
              <SelectField id={`${prefix}-condition-mode`} value={rule.conditionMode} onChange={(next) => onChange({ conditionMode: next })}
                options={[{ value: "any_match", label: t("models.workbench.anyMatch") }, { value: "all_match", label: t("models.workbench.allMatch") }]} />
            </div>
            {(rule.conditionOp === "equals" || rule.conditionOp === "in") && (
              <div className="field"><label htmlFor={`${prefix}-condition-values`}>{rule.conditionOp === "equals" ? t("gov.rule.conditionValue") : t("models.workbench.conditionValues")}</label>
                <input id={`${prefix}-condition-values`} className="inp mono" required value={rule.conditionValues} onChange={(event) => onChange({ conditionValues: event.target.value })} /></div>
            )}
          </>
        )}
        <div className="field"><label htmlFor={`${prefix}-reason`}>{t("gov.rule.reason")}</label>
          <input id={`${prefix}-reason`} className="inp" required maxLength={2048} value={rule.reason} onChange={(event) => onChange({ reason: event.target.value })} /></div>
        <div className="field"><label htmlFor={`${prefix}-risk`}>{t("gov.rule.risk")}</label>
          <SelectField id={`${prefix}-risk`} value={rule.risk} onChange={(next) => onChange({ risk: next })}
            options={[{ value: "low", label: t("gov.risk.low") }, { value: "medium", label: t("gov.risk.medium") }, { value: "high", label: t("gov.risk.high") }]} />
        </div>
      </div>
    </fieldset>
  );
}

function RulesetCreateDialog({ onClose, onCreated }: { onClose(): void; onCreated(): Promise<void> }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const [scopeType, setScopeType] = useState("group");
  const [scopeId, setScopeId] = useState("");
  const [rules, setRules] = useState<RuleDraft[]>([emptyRule()]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const groups = useQuery({ queryKey: [GROUPS], queryFn: () => api<GroupRecord[]>(GROUPS), enabled: scopeType === "group", retry: false });
  const activeGroups = (groups.data ?? []).filter((group) => group.status === "active");

  function updateRule(key: number, patch: Partial<RuleDraft>) {
    setRules((current) => current.map((rule) => (rule.key === key ? { ...rule, ...patch } : rule)));
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (rules.length === 0) {
      setError(t("gov.ruleset.rulesRequired"));
      return;
    }
    const data = new FormData(event.currentTarget);
    setError(null);
    setSubmitting(true);
    try {
      await api(RULESETS, {
        method: "POST",
        body: JSON.stringify({
          name: String(data.get("name") ?? "").trim(),
          schema_version: 1,
          scope_type: scopeType,
          scope_id: scopeId.trim(),
          rules: rules.map(buildRulePayload),
          source_refs: String(data.get("source_refs") ?? "").split(",").map((item) => item.trim()).filter(Boolean),
          reason: String(data.get("reason") ?? "").trim(),
        }),
      });
      toast.success(t("action.success"));
      await onCreated();
      onClose();
    } catch (cause) {
      setError(rowActionError(cause, locale));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <GovernanceDialog titleKey="gov.ruleset.createTitle" wide onClose={onClose}>
      <form onSubmit={(event) => void submit(event)}>
        <div className="modal-body">
          <p className="muted">{t("gov.ruleset.createDescription")}</p>
          {error && <div className="alert alert-err" role="alert"><Icon name="alert" /><div><div className="ad">{error}</div></div></div>}
          <div className="config-draft-grid">
            <div className="field"><label htmlFor="gov-rs-name">{t("action.name")}</label>
              <input id="gov-rs-name" name="name" className="inp" required maxLength={128} /></div>
            <div className="field"><label htmlFor="gov-rs-scope-type">{t("action.ruleset.scopeType")}</label>
              <SelectField id="gov-rs-scope-type" value={scopeType} onChange={(next) => { setScopeType(next); setScopeId(""); }}
                options={[{ value: "group", label: t("option.group") }, { value: "platform_key", label: t("option.platformKey") }]} />
            </div>
            {scopeType === "group" ? (
              <div className="field"><label htmlFor="gov-rs-scope-group">{t("gov.ruleset.scopeGroup")}</label>
                <SelectField id="gov-rs-scope-group" required value={scopeId} onChange={setScopeId}
                  disabled={groups.isLoading || activeGroups.length === 0}
                  placeholder={groups.isLoading ? t("common.loading") : activeGroups.length === 0 ? t("common.noneAvailable") : t("common.select")}
                  options={activeGroups.map((group) => ({ value: String(group.id), label: String(group.name ?? group.id) }))} />
              </div>
            ) : (
              <div className="field"><label htmlFor="gov-rs-scope-id">{t("action.ruleset.scopeId")}</label>
                <input id="gov-rs-scope-id" className="inp mono" required placeholder="00000000-0000-0000-0000-000000000000" value={scopeId} onChange={(event) => setScopeId(event.target.value)} /></div>
            )}
            <div className="field"><label htmlFor="gov-rs-source">{t("action.sourceRefs")}<span className="hint">{t("action.sourceRefsHint")}</span></label>
              <input id="gov-rs-source" name="source_refs" className="inp mono" /></div>
            <div className="field form-wide"><label htmlFor="gov-rs-reason">{t("action.reason.create")}</label>
              <input id="gov-rs-reason" name="reason" className="inp" maxLength={2048} /></div>
          </div>
          {rules.map((rule, index) => (
            <RuleCard key={rule.key} rule={rule} index={index} onChange={(patch) => updateRule(rule.key, patch)}
              onRemove={() => setRules((current) => current.filter((item) => item.key !== rule.key))} />
          ))}
          <button type="button" className="btn btn-ghost capability-add-rule" onClick={() => setRules((current) => [...current, emptyRule()])}>＋ {t("gov.rule.add")}</button>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn btn-ghost" onClick={onClose} disabled={submitting}>{t("common.cancel")}</button>
          <button type="submit" className="btn btn-primary" disabled={submitting}>{submitting ? t("common.submitting") : t("gov.ruleset.submit")}</button>
        </div>
      </form>
    </GovernanceDialog>
  );
}

function RulesetSimulateDialog({ row, endpoint, onClose }: { row: Row; endpoint: string; onClose(): void }) {
  const { locale, t } = useI18n();
  const [request, setRequest] = useState("{\n  \"model\": \"claude-sonnet-4-5\",\n  \"max_tokens\": 0,\n  \"messages\": [{ \"role\": \"user\", \"content\": \"hello\" }]\n}");
  const [clientClass, setClientClass] = useState("claude_code_cli");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Row | null>(null);

  async function run() {
    let parsed: unknown;
    try {
      parsed = JSON.parse(request);
    } catch {
      setError(t("gov.simulate.invalidJson"));
      return;
    }
    setError(null);
    setRunning(true);
    try {
      const version = typeof row.version === "number" ? row.version : 1;
      const response = await api<Row>(`${endpoint}/${encodeURIComponent(String(row.id))}:simulate`, {
        method: "POST",
        headers: { "If-Match": `"rev-${version}"` },
        body: JSON.stringify({ request: parsed, client_class: clientClass }),
      });
      setResult(response);
    } catch (cause) {
      setError(rowActionError(cause, locale));
    } finally {
      setRunning(false);
    }
  }

  const changes = items(result?.change_set);
  return (
    <GovernanceDialog titleKey="gov.simulate.title" subtitle={artifactName(row)} wide onClose={onClose}>
      <div className="modal-body">
        <div className="config-draft-grid">
          <div className="field"><label htmlFor="gov-sim-client">{t("gov.simulate.clientClass")}</label>
            <SelectField id="gov-sim-client" value={clientClass} onChange={setClientClass}
              options={[{ value: "claude_code_cli", label: t("group.config.client.claude_code_cli") }, { value: "non_claude_code_cli", label: t("group.config.client.non_claude_code_cli") }]} />
          </div>
          <div className="field form-wide"><label htmlFor="gov-sim-request">{t("gov.simulate.request")}</label>
            <textarea id="gov-sim-request" className="inp mono" rows={8} value={request} onChange={(event) => setRequest(event.target.value)} /></div>
        </div>
        {error && <div className="alert alert-err" role="alert"><Icon name="alert" /><div><div className="ad">{error}</div></div></div>}
        {result && (
          <div className="gov-simulate-result">
            <p className="muted mono breakable">{t("gov.simulate.digest")}: {String(result.adjusted_request_digest ?? "—")}</p>
            {changes.length === 0
              ? <p className="muted">{t("gov.simulate.noChanges")}</p>
              : <SubTable rows={changes.map((change, index) => ({ id: index, rule_id: change.rule_id, path: change.path, reason: change.reason, risk: change.risk }))}
                columns={["rule_id", "path", "reason", "risk"]} empty="" />}
          </div>
        )}
      </div>
      <div className="modal-foot">
        <button type="button" className="btn btn-ghost" onClick={onClose} disabled={running}>{t("common.close")}</button>
        <button type="button" className="btn btn-primary" disabled={running} onClick={() => void run()}>{running ? t("common.submitting") : t("gov.simulate.run")}</button>
      </div>
    </GovernanceDialog>
  );
}

function RulesetsPane() {
  const { locale, t } = useI18n();
  const list = useQuery({ queryKey: [RULESETS], queryFn: () => api<Row[]>(RULESETS), retry: false });
  const actions = useArtifactActions(RULESETS);
  const [createOpen, setCreateOpen] = useState(false);
  const [simulateRow, setSimulateRow] = useState<Row | null>(null);
  const queryClient = useQueryClient();
  const rows = items(list.data).map((row) => ({
    ...row,
    name: artifactName(row),
    scope: `${String(row.scope_type ?? "")} · ${shortId(row.scope_id)}`,
    rule_count: items(artifactEnvelope(row).rules).length,
    lifecycle: lifecycleLabel(row.lifecycle, locale === "zh-CN"),
    lifecycle_code: String(row.lifecycle ?? ""),
  }));

  return (
    <GovernanceCard title={t("gov.tab.rulesets")} createLabel={t("gov.ruleset.createButton")} onCreate={() => setCreateOpen(true)}
      refreshing={list.isFetching} onRefresh={() => void list.refetch()}>
      <PaneStatus loading={list.isLoading} error={list.error}>
        <SubTable
          rows={rows}
          columns={["name", "scope", "version", "lifecycle", "is_active", "rule_count", "validated_at", "shadow_started_at"]}
          empty={t("gov.ruleset.empty")}
          rowTail={(row) => {
            const lifecycle = String(row.lifecycle_code ?? "");
            const isActive = row.is_active === true;
            return (
              <div className="row-actions">
                {["eligible", "shadow", "canary", "active"].includes(lifecycle) && (
                  <ActionButton tip={t("group.version.validate")} icon="check" disabled={actions.busy} onClick={() => void actions.run(row, "validate", { titleKey: "group.version.validate" })} />
                )}
                <ActionButton tip={t("group.version.simulate")} icon="activity" disabled={actions.busy} onClick={() => setSimulateRow(row)} />
                {!isActive && ["eligible", "shadow", "canary"].includes(lifecycle) && (
                  <ActionButton tip={t("group.version.activate")} icon="play" disabled={actions.busy} onClick={() => void actions.run(row, "activate", { titleKey: "group.version.activate", danger: true })} />
                )}
              </div>
            );
          }}
        />
      </PaneStatus>
      {createOpen && <RulesetCreateDialog onClose={() => setCreateOpen(false)} onCreated={async () => { await queryClient.invalidateQueries({ queryKey: [RULESETS] }); }} />}
      {simulateRow && <RulesetSimulateDialog row={simulateRow} endpoint={RULESETS} onClose={() => setSimulateRow(null)} />}
    </GovernanceCard>
  );
}

/* ============================================================
   价格版本:模型单价(美元/百万 token)
   ============================================================ */

function PriceCreateDialog({ latest, onClose, onCreated }: { latest: Row | undefined; onClose(): void; onCreated(): Promise<void> }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const models = useQuery({ queryKey: [MODELS], queryFn: () => api<ModelRecord[]>(MODELS), retry: false });
  const published = (models.data ?? []).filter((model) => model.lifecycle === "published");
  const latestEntries = new Map(items(latest?.entries).map((entry) => [String(entry.model_id ?? ""), entry]));

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const entries = published
      .map((model) => {
        const id = String(model.id ?? "");
        const value = (field: string) => String(data.get(`${field}:${id}`) ?? "").trim();
        return {
          model_id: id,
          input_per_million: value("input"),
          output_per_million: value("output"),
          cache_write_per_million: value("cache_write"),
          cache_read_per_million: value("cache_read"),
        };
      })
      .filter((entry) => entry.input_per_million || entry.output_per_million || entry.cache_write_per_million || entry.cache_read_per_million);
    if (entries.length === 0 || entries.some((entry) => !entry.input_per_million || !entry.output_per_million || !entry.cache_write_per_million || !entry.cache_read_per_million)) {
      setError(t("gov.price.entryRequired"));
      return;
    }
    const effectiveFrom = String(data.get("effective_from") ?? "");
    setError(null);
    setSubmitting(true);
    try {
      await api(PRICES, {
        method: "POST",
        body: JSON.stringify({
          currency: "USD",
          entries,
          effective_from: new Date(effectiveFrom).toISOString(),
          source_uri: String(data.get("source_uri") ?? "").trim() || null,
          reason: String(data.get("reason") ?? "").trim(),
        }),
      });
      toast.success(t("action.success"));
      await onCreated();
      onClose();
    } catch (cause) {
      setError(rowActionError(cause, locale));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <GovernanceDialog titleKey="gov.price.createTitle" wide onClose={onClose}>
      <form onSubmit={(event) => void submit(event)}>
        <div className="modal-body">
          <p className="muted">{t("gov.price.createDescription")}</p>
          {error && <div className="alert alert-err" role="alert"><Icon name="alert" /><div><div className="ad">{error}</div></div></div>}
          <div className="config-draft-grid">
            <div className="field"><label htmlFor="gov-price-from">{t("gov.price.effectiveFrom")}</label>
              <input id="gov-price-from" name="effective_from" className="inp" type="datetime-local" required /></div>
            <div className="field"><label htmlFor="gov-price-source">{t("gov.price.sourceUri")}</label>
              <input id="gov-price-source" name="source_uri" className="inp mono" placeholder="https://docs.claude.com/pricing" /></div>
            <div className="field form-wide"><label htmlFor="gov-price-reason">{t("action.reason.create")}</label>
              <input id="gov-price-reason" name="reason" className="inp" maxLength={2048} /></div>
          </div>
          <PaneStatus loading={models.isLoading} error={models.error}>
            {published.length === 0
              ? <p className="muted">{t("group.config.noPublishedModels")}</p>
              : (
                <div className="tbl-wrap">
                  <table className="tbl">
                    <thead><tr>
                      <th scope="col">{t("gov.price.model")}</th>
                      <th scope="col">{t("gov.price.input")}</th>
                      <th scope="col">{t("gov.price.output")}</th>
                      <th scope="col">{t("gov.price.cacheWrite")}</th>
                      <th scope="col">{t("gov.price.cacheRead")}</th>
                    </tr></thead>
                    <tbody>
                      {published.map((model) => {
                        const id = String(model.id ?? "");
                        const previous = record(latestEntries.get(id));
                        const cell = (field: string, previousValue: unknown) => (
                          <td><input className="inp mono gov-price-input" name={`${field}:${id}`} inputMode="decimal" placeholder="0"
                            aria-label={`${String(model.display_name ?? id)} ${field}`} defaultValue={typeof previousValue === "string" ? previousValue : ""} /></td>
                        );
                        return (
                          <tr key={id}>
                            <td>{String(model.display_name ?? model.upstream_model_id ?? id)}</td>
                            {cell("input", previous.input_per_million)}
                            {cell("output", previous.output_per_million)}
                            {cell("cache_write", previous.cache_write_per_million)}
                            {cell("cache_read", previous.cache_read_per_million)}
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
          </PaneStatus>
          <p className="muted governance-pane-hint">{t("gov.price.unitHint")}</p>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn btn-ghost" onClick={onClose} disabled={submitting}>{t("common.cancel")}</button>
          <button type="submit" className="btn btn-primary" disabled={submitting}>{submitting ? t("common.submitting") : t("gov.price.submit")}</button>
        </div>
      </form>
    </GovernanceDialog>
  );
}

function PricePane() {
  const { t } = useI18n();
  const list = useQuery({ queryKey: [PRICES], queryFn: () => api<Row[]>(PRICES), retry: false });
  const [createOpen, setCreateOpen] = useState(false);
  const queryClient = useQueryClient();
  const rows = items(list.data).map((row) => ({ ...row, entry_count: items(row.entries).length }));

  return (
    <GovernanceCard title={t("gov.tab.prices")} createLabel={t("gov.price.createButton")} onCreate={() => setCreateOpen(true)}
      refreshing={list.isFetching} onRefresh={() => void list.refetch()}>
      <p className="muted governance-pane-hint">{t("gov.price.hint")}</p>
      <PaneStatus loading={list.isLoading} error={list.error}>
        <SubTable
          rows={rows}
          columns={["price_version", "currency", "entry_count", "effective_from", "effective_to", "source_uri", "created_at"]}
          empty={t("gov.price.empty")}
        />
      </PaneStatus>
      {createOpen && <PriceCreateDialog latest={items(list.data)[0]} onClose={() => setCreateOpen(false)} onCreated={async () => { await queryClient.invalidateQueries({ queryKey: [PRICES] }); }} />}
    </GovernanceCard>
  );
}

export function GovernancePage() {
  const { t } = useI18n();
  const [view, setView] = useState<View>("rulesets");
  const tabs: { key: View; label: MessageKey }[] = [
    { key: "rulesets", label: "gov.tab.rulesets" },
    { key: "prices", label: "gov.tab.prices" },
  ];
  return (
    <div className="page-stack">
      <header className="page-heading"><div><p className="eyebrow mono">GOVERNANCE / POLICY</p><h1>{t("nav.governance")}</h1><p>{t("gov.description")}</p></div></header>
      <div className="segmented local" role="group" aria-label={t("nav.governance")}>
        {tabs.map((tab) => (
          <button key={tab.key} type="button" className={view === tab.key ? "active" : ""} aria-pressed={view === tab.key} onClick={() => setView(tab.key)}>{t(tab.label)}</button>
        ))}
      </div>
      {view === "rulesets" && <RulesetsPane />}
      {view === "prices" && <PricePane />}
    </div>
  );
}