import { FormEvent, useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "./api";
import { useConfirm, useToast } from "./feedback";
import { MessageKey, useI18n } from "./i18n";
import { SelectField } from "./select-field";
import { rowActionError } from "./row-actions";
import { DataGrid, Icon, PaneStatus, Row, SubTable } from "./detail-kit";

/* ============================================================
   凭据详情对话框:概览 / 调度配置 / 维护记录 / 重认证策略 /
   浏览器操作 五页签 + 高阶运维动作(迁组/重绑出口/迁批次/
   重建设备/刷新令牌/发起恢复)
   ============================================================ */

type Tab = "overview" | "scheduling" | "maintenance" | "reauth" | "browser";
type OpsForm = "migrate-group" | "rebind-egress" | "migrate-profile-cohort" | "rebuild-device-identity";

function SchedulingPane({ endpoint, record, revision, onSaved }: { endpoint: string; record: Row; revision: number | undefined; onSaved(): Promise<void> }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const [priority, setPriority] = useState(String(record.priority_layer ?? record.priority ?? "0"));
  const [weight, setWeight] = useState(String(record.scheduling_weight ?? record.weight ?? "1"));
  const [concurrency, setConcurrency] = useState(record.max_concurrency === null || record.max_concurrency === undefined ? "" : String(record.max_concurrency));
  const [rpm, setRpm] = useState(record.rpm_limit === null || record.rpm_limit === undefined ? "" : String(record.rpm_limit));
  const [saving, setSaving] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (revision === undefined) return;
    setSaving(true);
    try {
      await api(`${endpoint}/scheduling-config`, {
        method: "PATCH",
        headers: { "If-Match": `"rev-${revision}"` },
        body: JSON.stringify({
          priority: Number(priority),
          weight: Number(weight),
          concurrency: concurrency === "" ? null : Number(concurrency),
          messages_rpm: rpm === "" ? null : Number(rpm),
        }),
      });
      toast.success(t("action.success"));
      await onSaved();
    } catch (error) {
      toast.error(rowActionError(error, locale));
    } finally {
      setSaving(false);
    }
  }
  return (
    <form className="credential-scheduling-form" onSubmit={(event) => void submit(event)}>
      <p className="muted">{t("credential.scheduling.hint")}</p>
      <div className="ops-grid">
        <div className="field"><label htmlFor="sched-priority">{t("credential.scheduling.priority")}</label><input id="sched-priority" className="inp" type="number" min={0} max={65535} required value={priority} onChange={(event) => setPriority(event.target.value)} /></div>
        <div className="field"><label htmlFor="sched-weight">{t("credential.scheduling.weight")}</label><input id="sched-weight" className="inp" type="number" min={1} max={4294967} required value={weight} onChange={(event) => setWeight(event.target.value)} /></div>
        <div className="field"><label htmlFor="sched-concurrency">{t("credential.scheduling.concurrency")}</label><input id="sched-concurrency" className="inp" type="number" min={1} value={concurrency} onChange={(event) => setConcurrency(event.target.value)} placeholder={t("credential.scheduling.inherit")} /></div>
        <div className="field"><label htmlFor="sched-rpm">{t("credential.scheduling.messagesRpm")}</label><input id="sched-rpm" className="inp" type="number" min={1} value={rpm} onChange={(event) => setRpm(event.target.value)} placeholder={t("credential.scheduling.inherit")} /></div>
      </div>
      <div className="modal-foot"><button type="submit" className="btn btn-primary" disabled={saving || revision === undefined}>{saving ? t("common.loading") : t("credential.scheduling.save")}</button></div>
    </form>
  );
}

function ReauthPane({ endpoint, credentialRevision, onChanged }: { endpoint: string; credentialRevision: number | undefined; onChanged(): Promise<void> }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const strategyEndpoint = `${endpoint}/reauth-strategy`;
  const strategy = useQuery({ queryKey: [strategyEndpoint], queryFn: () => api<Row>(strategyEndpoint), retry: false });
  const [busy, setBusy] = useState(false);
  const notConfigured = strategy.error instanceof ApiError && strategy.error.status === 404;
  const record = strategy.data;
  const state = typeof record?.state === "string" ? record.state : "";
  const strategyRevision = typeof record?.revision === "number" ? record.revision : undefined;

  async function run(action: "initialize" | "disable" | "reactivate", ifMatch: number | undefined, titleKey: MessageKey) {
    if (ifMatch === undefined) return;
    const result = await confirm({ titleKey, bodyKey: "credential.reauth.confirmBody", withReason: true, danger: action === "disable" });
    if (!result.ok) return;
    setBusy(true);
    try {
      await api(`${strategyEndpoint}:${action}`, {
        method: "POST",
        headers: { "If-Match": `"rev-${ifMatch}"` },
        body: JSON.stringify({ reason: result.reason, expected_revision: ifMatch }),
      });
      toast.success(t("action.success"));
      await queryClient.invalidateQueries({ queryKey: [strategyEndpoint] });
      await onChanged();
    } catch (error) {
      // 托管浏览器在本机不可用或凭据前置条件不满足时后端返回 409/412
      toast.error(error instanceof ApiError && (error.status === 409 || error.status === 412) ? t("credential.reauth.unavailable") : rowActionError(error, locale));
    } finally {
      setBusy(false);
    }
  }

  if (strategy.isLoading) return <PaneStatus loading error={null}>{null}</PaneStatus>;
  if (notConfigured) {
    return (
      <div className="empty">
        <div className="empty-orbit"><Icon name="shield" /></div>
        <h3>{t("credential.reauth.none")}</h3>
        <p>{t("credential.reauth.noneBody")}</p>
        <button type="button" className="btn btn-primary" disabled={busy || credentialRevision === undefined} onClick={() => void run("initialize", credentialRevision, "credential.reauth.initialize")}>{t("credential.reauth.initialize")}</button>
      </div>
    );
  }
  return (
    <PaneStatus loading={false} error={strategy.error}>
      {record && (
        <div className="reauth-pane">
          <DataGrid record={record} />
          <div className="modal-foot">
            {(state === "disabled" || state === "invalid" || state === "degraded") && <button type="button" className="btn btn-primary" disabled={busy || credentialRevision === undefined} onClick={() => void run("reactivate", credentialRevision, "credential.reauth.reactivate")}>{t("credential.reauth.reactivate")}</button>}
            {state !== "disabled" && <button type="button" className="btn btn-ghost" disabled={busy || strategyRevision === undefined} onClick={() => void run("disable", strategyRevision, "credential.reauth.disable")}>{t("credential.reauth.disable")}</button>}
          </div>
        </div>
      )}
    </PaneStatus>
  );
}

function BrowserPane({ endpoint }: { endpoint: string }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const listEndpoint = `${endpoint}/browser-operations`;
  const operations = useQuery({ queryKey: [listEndpoint], queryFn: () => api<Row[]>(listEndpoint), retry: false });
  const rows = (operations.data ?? []).filter((item): item is Row => typeof item === "object" && item !== null);

  async function cancel(operation: Row) {
    const generation = typeof operation.generation === "number" ? operation.generation : undefined;
    if (generation === undefined) return;
    const result = await confirm({ titleKey: "credential.browser.cancel", bodyKey: "credential.browser.cancelBody", withReason: true, danger: true });
    if (!result.ok) return;
    try {
      // 浏览器操作的乐观锁是 operation_generation
      await api(`${listEndpoint}/${encodeURIComponent(String(operation.id))}:cancel`, {
        method: "POST",
        headers: { "If-Match": `"rev-${generation}"` },
        body: JSON.stringify({ reason: result.reason, expected_revision: generation }),
      });
      toast.success(t("action.success"));
      await queryClient.invalidateQueries({ queryKey: [listEndpoint] });
    } catch (error) {
      toast.error(rowActionError(error, locale));
    }
  }

  return (
    <PaneStatus loading={operations.isLoading} error={operations.error}>
      <SubTable
        rows={rows}
        columns={["kind", "state", "browser_provider", "attempt_count", "job_state", "outcome_code", "created_at"]}
        empty={t("credential.browser.none")}
        rowTail={(row) => row.can_cancel === true
          ? <button type="button" className="ibtn outline sm danger" data-tip={t("credential.browser.cancel")} aria-label={t("credential.browser.cancel")} onClick={() => void cancel(row)}><Icon name="close" /></button>
          : null}
      />
    </PaneStatus>
  );
}

function OpsFormPane({ kind, endpoint, record, revision, onBack, onDone }: { kind: OpsForm; endpoint: string; record: Row; revision: number | undefined; onBack(): void; onDone(): Promise<void> }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const [reason, setReason] = useState("");
  const [targetGroup, setTargetGroup] = useState("");
  const [mode, setMode] = useState<"direct" | "proxy">("direct");
  const [proxyId, setProxyId] = useState("");
  const [archetypeVersion, setArchetypeVersion] = useState("");
  const [cohort, setCohort] = useState("");
  const [approvalCase, setApprovalCase] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const groups = useQuery({ queryKey: ["/admin/v1/groups"], queryFn: () => api<Row[]>("/admin/v1/groups"), enabled: kind === "migrate-group" });
  const proxies = useQuery({ queryKey: ["/admin/v1/proxies"], queryFn: () => api<Row[]>("/admin/v1/proxies"), enabled: kind === "rebind-egress" });
  const profileEpoch = typeof record.profile_epoch === "number" ? record.profile_epoch : undefined;
  const egressEpoch = typeof record.egress_epoch === "number" ? record.egress_epoch : undefined;
  const epochMissing = kind === "rebind-egress" && (profileEpoch === undefined || egressEpoch === undefined);
  const titles: Record<OpsForm, MessageKey> = {
    "migrate-group": "credential.ops.migrateGroup",
    "rebind-egress": "credential.ops.rebindEgress",
    "migrate-profile-cohort": "credential.ops.migrateCohort",
    "rebuild-device-identity": "credential.ops.rebuildDevice",
  };

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (revision === undefined) return;
    let body: Row;
    if (kind === "migrate-group") body = { target_group_id: targetGroup, reason, expected_revision: revision };
    else if (kind === "rebind-egress") body = { target: mode === "direct" ? { mode: "direct" } : { mode: "proxy", proxy_id: proxyId }, reason, expected_profile_epoch: profileEpoch, expected_egress_epoch: egressEpoch };
    else if (kind === "migrate-profile-cohort") body = { target_archetype_version_id: archetypeVersion.trim(), target_capture_cohort: cohort.trim(), reason, expected_revision: revision };
    else body = { approval_case_id: approvalCase.trim(), reason, expected_revision: revision };
    setSubmitting(true);
    try {
      await api(`${endpoint}:${kind}`, { method: "POST", headers: { "If-Match": `"rev-${revision}"` }, body: JSON.stringify(body) });
      toast.success(t("action.success"));
      await onDone();
    } catch (error) {
      toast.error(rowActionError(error, locale));
    } finally {
      setSubmitting(false);
    }
  }

  const activeGroups = (groups.data ?? []).filter((item): item is Row => typeof item === "object" && item !== null);
  const activeProxies = (proxies.data ?? []).filter((item): item is Row => typeof item === "object" && item !== null && item.lifecycle !== "archived");
  return (
    <form className="credential-ops-form" onSubmit={(event) => void submit(event)}>
      <div className="ops-form-head">
        <button type="button" className="ibtn outline sm" aria-label={t("credential.form.back")} data-tip={t("credential.form.back")} onClick={onBack}><Icon name="arrow-left" /></button>
        <h4>{t(titles[kind])}</h4>
      </div>
      {kind === "migrate-group" && (
        <div className="field"><label htmlFor="ops-group">{t("credential.form.targetGroup")}</label>
          <SelectField
            id="ops-group"
            required
            value={targetGroup}
            onChange={setTargetGroup}
            placeholder={groups.isLoading ? t("common.loading") : t("credential.form.pick")}
            options={activeGroups.map((group) => ({ value: String(group.id), label: String(group.name ?? group.id) }))}
          />
        </div>
      )}
      {kind === "rebind-egress" && (
        <>
          {epochMissing && <div className="alert alert-warn" role="alert"><Icon name="alert" /><div><div className="ad">{t("credential.form.epochMissing")}</div></div></div>}
          <div className="field"><span className="field-label">{t("credential.form.mode")}</span>
            <div className="segmented local" role="group" aria-label={t("credential.form.mode")}>
              <button type="button" className={mode === "direct" ? "active" : ""} onClick={() => setMode("direct")}>{t("credential.form.direct")}</button>
              <button type="button" className={mode === "proxy" ? "active" : ""} onClick={() => setMode("proxy")}>{t("credential.form.proxy")}</button>
            </div>
          </div>
          {mode === "proxy" && (
            <div className="field"><label htmlFor="ops-proxy">{t("credential.form.proxyEndpoint")}</label>
              <SelectField
                id="ops-proxy"
                required
                value={proxyId}
                onChange={setProxyId}
                placeholder={proxies.isLoading ? t("common.loading") : t("credential.form.pick")}
                options={activeProxies.map((proxy) => ({ value: String(proxy.id), label: String(proxy.name ?? proxy.id) }))}
              />
            </div>
          )}
        </>
      )}
      {kind === "migrate-profile-cohort" && (
        <>
          <div className="field"><label htmlFor="ops-archetype">{t("credential.form.archetypeVersion")}</label><input id="ops-archetype" className="inp mono" required value={archetypeVersion} onChange={(event) => setArchetypeVersion(event.target.value)} placeholder="00000000-0000-0000-0000-000000000000" /></div>
          <div className="field"><label htmlFor="ops-cohort">{t("credential.form.cohort")}</label><input id="ops-cohort" className="inp mono" required maxLength={128} value={cohort} onChange={(event) => setCohort(event.target.value)} /></div>
        </>
      )}
      {kind === "rebuild-device-identity" && (
        <div className="field"><label htmlFor="ops-approval">{t("credential.form.approvalCase")}</label><input id="ops-approval" className="inp mono" required value={approvalCase} onChange={(event) => setApprovalCase(event.target.value)} placeholder="00000000-0000-0000-0000-000000000000" /></div>
      )}
      <div className="field"><label htmlFor="ops-reason">{t("credential.form.reason")}</label><textarea id="ops-reason" className="inp" rows={2} maxLength={2048} value={reason} onChange={(event) => setReason(event.target.value)} /></div>
      <div className="modal-foot">
        <button type="button" className="btn btn-ghost" onClick={onBack}>{t("credential.form.back")}</button>
        <button type="submit" className="btn btn-primary" disabled={submitting || revision === undefined || epochMissing}>{submitting ? t("common.loading") : t("credential.form.submit")}</button>
      </div>
    </form>
  );
}

export function CredentialDetailDialog({ row, onClose }: { row: Row; onClose(): void }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const id = String(row.id ?? "");
  const endpoint = `/admin/v1/credentials/${encodeURIComponent(id)}`;
  const detail = useQuery({ queryKey: [endpoint], queryFn: () => api<Row>(endpoint), retry: false });
  const maintenanceEndpoint = `${endpoint}/maintenance-operations`;
  const maintenance = useQuery({ queryKey: [maintenanceEndpoint], queryFn: () => api<Row[]>(maintenanceEndpoint), retry: false, enabled: !detail.isLoading });
  const [tab, setTab] = useState<Tab>("overview");
  const [opsForm, setOpsForm] = useState<OpsForm | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      if (opsForm) setOpsForm(null);
      else onClose();
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [opsForm, onClose]);
  const record = detail.data ?? {};
  const revision = typeof record.revision === "number" ? record.revision : undefined;
  const maintenanceRows = (maintenance.data ?? []).filter((item): item is Row => typeof item === "object" && item !== null);

  async function refreshAll() {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: [endpoint] }),
      queryClient.invalidateQueries({ queryKey: [maintenanceEndpoint] }),
      queryClient.invalidateQueries({ queryKey: ["/admin/v1/credentials"] }),
    ]);
  }

  /** 仅需原因确认的高阶动作:刷新令牌 / 发起恢复 */
  async function runReasonAction(suffix: "refresh-token" | "begin-recovery", titleKey: MessageKey, bodyKey: MessageKey) {
    if (revision === undefined) return;
    const result = await confirm({ titleKey, bodyKey, withReason: true, danger: suffix === "begin-recovery" });
    if (!result.ok) return;
    setBusy(true);
    try {
      await api(`${endpoint}:${suffix}`, { method: "POST", headers: { "If-Match": `"rev-${revision}"` }, body: JSON.stringify({ reason: result.reason, expected_revision: revision }) });
      toast.success(t("action.success"));
      await refreshAll();
    } catch (error) {
      toast.error(rowActionError(error, locale));
    } finally {
      setBusy(false);
    }
  }

  const tabs: { key: Tab; label: MessageKey }[] = [
    { key: "overview", label: "credential.tab.overview" },
    { key: "scheduling", label: "credential.tab.scheduling" },
    { key: "maintenance", label: "credential.tab.maintenance" },
    { key: "reauth", label: "credential.tab.reauth" },
    { key: "browser", label: "credential.tab.browser" },
  ];

  return createPortal(
    <div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section className="modal credential-detail-modal" role="dialog" aria-modal="true" aria-labelledby="credential-detail-title">
        <div className="modal-head">
          <div>
            <p className="eyebrow mono">CREDENTIAL / OPS</p>
            <h3 id="credential-detail-title">{t("credential.detail.title")}</h3>
            <p className="muted mono breakable">{String(record.account_uuid ?? id)}</p>
          </div>
          <button type="button" className="ibtn outline" aria-label={t("common.close")} onClick={onClose}>×</button>
        </div>
        <div className="modal-body credential-detail-body">
          <PaneStatus loading={detail.isLoading} error={detail.error}>
            {opsForm === null ? (
              <>
                <div className="credential-ops-bar" role="group" aria-label={t("credential.ops")}>
                  <button type="button" className="btn btn-ghost sm" disabled={busy || revision === undefined} onClick={() => void runReasonAction("refresh-token", "credential.ops.refreshToken", "credential.ops.refreshTokenBody")}><Icon name="refresh" />{t("credential.ops.refreshToken")}</button>
                  <button type="button" className="btn btn-ghost sm" disabled={busy || revision === undefined} onClick={() => void runReasonAction("begin-recovery", "credential.ops.beginRecovery", "credential.ops.beginRecoveryBody")}><Icon name="heart" />{t("credential.ops.beginRecovery")}</button>
                  <button type="button" className="btn btn-ghost sm" disabled={revision === undefined} onClick={() => setOpsForm("migrate-group")}><Icon name="layers" />{t("credential.ops.migrateGroup")}</button>
                  <button type="button" className="btn btn-ghost sm" disabled={revision === undefined} onClick={() => setOpsForm("rebind-egress")}><Icon name="globe" />{t("credential.ops.rebindEgress")}</button>
                  <button type="button" className="btn btn-ghost sm" disabled={revision === undefined} onClick={() => setOpsForm("migrate-profile-cohort")}><Icon name="box" />{t("credential.ops.migrateCohort")}</button>
                  <button type="button" className="btn btn-ghost sm" disabled={revision === undefined} onClick={() => setOpsForm("rebuild-device-identity")}><Icon name="settings" />{t("credential.ops.rebuildDevice")}</button>
                </div>
                <div className="segmented local detail-tabs" role="group" aria-label={t("credential.detail.title")}>
                  {tabs.map((item) => <button key={item.key} type="button" className={tab === item.key ? "active" : ""} aria-pressed={tab === item.key} onClick={() => setTab(item.key)}>{t(item.label)}</button>)}
                </div>
                <div className="detail-pane">
                  {tab === "overview" && <DataGrid record={record} />}
                  {tab === "scheduling" && <SchedulingPane endpoint={endpoint} record={record} revision={revision} onSaved={refreshAll} />}
                  {tab === "maintenance" && (
                    <PaneStatus loading={maintenance.isLoading} error={maintenance.error}>
                      <SubTable rows={maintenanceRows} columns={["kind", "state", "trigger", "attempt_count", "outcome_code", "error_category", "created_at", "completed_at"]} empty={t("credential.maintenance.none")} />
                    </PaneStatus>
                  )}
                  {tab === "reauth" && <ReauthPane endpoint={endpoint} credentialRevision={revision} onChanged={refreshAll} />}
                  {tab === "browser" && <BrowserPane endpoint={endpoint} />}
                </div>
              </>
            ) : (
              <OpsFormPane kind={opsForm} endpoint={endpoint} record={record} revision={revision} onBack={() => setOpsForm(null)} onDone={async () => { setOpsForm(null); await refreshAll(); }} />
            )}
          </PaneStatus>
        </div>
      </section>
    </div>,
    document.body,
  );
}
