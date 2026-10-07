import { FormEvent, ReactNode, useEffect, useId, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Principal, api, setCsrfToken } from "./api";
import { useToast } from "./feedback";
import { MessageKey, useI18n } from "./i18n";
import { RowActionDef, postLifecycle, rowActionError } from "./row-actions";
import { CredentialDetailDialog } from "./credential-detail";
import { SelectField } from "./select-field";

/* ============================================================
   P1 资源行操作注册表:users / proxies / models / approvals /
   alerts / jobs / sessions,外加 users·proxies 的轻量编辑弹窗
   ============================================================ */

type Row = Record<string, unknown>;

function text(row: Row, key: string): string {
  const value = row[key];
  return typeof value === "string" ? value : "";
}

function isStatus(row: Row, key: string, ...states: string[]): boolean {
  return states.includes(text(row, key));
}

/** 需要 step-up 授权的操作:先用当前密码换取短时授权,再携带 grant 发起动作 */
async function runWithStepUp(purpose: string, password: string | undefined, action: (grantId: string) => Promise<unknown>): Promise<unknown> {
  const grant = await api<{ id: string; csrf_token: string }>("/admin/v1/auth/step-up", {
    method: "POST",
    body: JSON.stringify({ purpose, current_password: password ?? "" }),
  });
  setCsrfToken(grant.csrf_token);
  return action(grant.id);
}

type DialogState = { kind: "edit-user" | "edit-proxy" | "replace-secret" | "credential-detail"; row: Row } | null;

function buildActions(path: string, principal: Principal, openDialog: (state: DialogState) => void): RowActionDef<Row>[] | undefined {
  switch (path) {
    case "/users": {
      const endpoint = "/admin/v1/users";
      const manageable = (row: Row) => String(row.id) !== principal.id && !isStatus(row, "status", "archived");
      return [
        {
          key: "edit", labelKey: "rowaction.edit", icon: "edit", primary: true,
          when: (row) => !isStatus(row, "status", "archived"),
          custom: (row) => openDialog({ kind: "edit-user", row }),
        },
        {
          key: "disable", labelKey: "rowaction.disable", icon: "pause", danger: true, primary: true,
          when: (row) => manageable(row) && isStatus(row, "status", "active", "mfa_pending"),
          confirm: { titleKey: "rowaction.confirm.disable.title", bodyKey: "rowaction.confirm.disable.body" },
          run: (row, reason) => postLifecycle(endpoint, row, "disable", reason),
          invalidate: endpoint,
        },
        {
          key: "reactivate", labelKey: "rowaction.reactivate", icon: "play", primary: true,
          when: (row) => manageable(row) && isStatus(row, "status", "disabled"),
          confirm: { titleKey: "rowaction.confirm.reactivate.title", bodyKey: "rowaction.confirm.reactivate.body" },
          run: (row, reason) => postLifecycle(endpoint, row, "reactivate", reason),
          invalidate: endpoint,
        },
        {
          key: "unlock", labelKey: "rowaction.unlock", icon: "unlock",
          when: (row) => manageable(row) && isStatus(row, "status", "disabled"),
          confirm: { titleKey: "rowaction.confirm.unlock.title", bodyKey: "rowaction.confirm.unlock.body" },
          run: (row, reason) => postLifecycle(endpoint, row, "unlock", reason),
          invalidate: endpoint,
        },
        {
          key: "revokeSessions", labelKey: "rowaction.revokeSessions", icon: "logout", danger: true,
          when: manageable,
          confirm: { titleKey: "rowaction.confirm.revokeSessions.title", bodyKey: "rowaction.confirm.revokeSessions.body", withReason: true },
          run: (row, reason) => api(`${endpoint}/${encodeURIComponent(String(row.id))}/sessions:revoke-all`, {
            method: "POST",
            headers: { "If-Match": `"rev-${Number(row.revision)}"` },
            body: JSON.stringify({ reason, expected_revision: row.revision }),
          }),
          invalidate: endpoint,
        },
        {
          key: "archive", labelKey: "rowaction.archive", icon: "package", danger: true,
          when: manageable,
          confirm: { titleKey: "rowaction.confirm.archive.title", bodyKey: "rowaction.confirm.archive.body" },
          run: (row, reason) => postLifecycle(endpoint, row, "archive", reason),
          invalidate: endpoint,
        },
      ];
    }
    case "/credentials": {
      const endpoint = "/admin/v1/credentials";
      return [
        {
          key: "detail", labelKey: "rowaction.detail", icon: "eye", primary: true,
          custom: (row) => openDialog({ kind: "credential-detail", row }),
        },
        {
          key: "disable", labelKey: "rowaction.disable", icon: "pause", danger: true, primary: true,
          when: (row) => isStatus(row, "lifecycle_state", "active"),
          confirm: { titleKey: "rowaction.confirm.disable.title", bodyKey: "rowaction.confirm.disable.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "disable", reason), invalidate: endpoint,
        },
        {
          key: "reactivate", labelKey: "rowaction.reactivate", icon: "play", primary: true,
          when: (row) => isStatus(row, "lifecycle_state", "disabled"),
          confirm: { titleKey: "rowaction.confirm.reactivate.title", bodyKey: "rowaction.confirm.reactivate.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "reactivate", reason), invalidate: endpoint,
        },
        {
          key: "clearCooldown", labelKey: "rowaction.clearCooldown", icon: "refresh",
          when: (row) => isStatus(row, "scheduling_state", "cooldown"),
          confirm: { titleKey: "rowaction.confirm.clearCooldown.title", bodyKey: "rowaction.confirm.clearCooldown.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "clear-cooldown", reason), invalidate: endpoint,
        },
        {
          key: "refreshPlan", labelKey: "rowaction.refreshPlan", icon: "activity",
          when: (row) => isStatus(row, "lifecycle_state", "active"),
          confirm: { titleKey: "rowaction.confirm.refreshPlan.title", bodyKey: "rowaction.confirm.refreshPlan.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "refresh-plan", reason), invalidate: endpoint,
        },
        {
          key: "revoke", labelKey: "rowaction.revoke", icon: "lock", danger: true,
          when: (row) => !isStatus(row, "lifecycle_state", "revoked", "archived"),
          confirm: { titleKey: "rowaction.confirm.revoke.title", bodyKey: "rowaction.confirm.revoke.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "revoke", reason), invalidate: endpoint,
        },
        {
          key: "archive", labelKey: "rowaction.archive", icon: "package", danger: true, primary: true,
          when: (row) => isStatus(row, "lifecycle_state", "disabled", "revoked"),
          confirm: { titleKey: "rowaction.confirm.archive.title", bodyKey: "rowaction.confirm.archive.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "archive", reason), invalidate: endpoint,
        },
      ];
    }
    case "/egress": {
      const endpoint = "/admin/v1/proxies";
      return [
        {
          key: "edit", labelKey: "rowaction.edit", icon: "edit", primary: true,
          when: (row) => !isStatus(row, "lifecycle", "archived"),
          custom: (row) => openDialog({ kind: "edit-proxy", row }),
        },
        {
          key: "probe", labelKey: "rowaction.probe", icon: "activity", primary: true,
          when: (row) => isStatus(row, "lifecycle", "active", "disabled"),
          confirm: { titleKey: "rowaction.confirm.probe.title", bodyKey: "rowaction.confirm.probe.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "probe", reason),
          invalidate: endpoint,
        },
        {
          key: "disable", labelKey: "rowaction.disable", icon: "pause", danger: true,
          when: (row) => isStatus(row, "lifecycle", "active", "draining"),
          confirm: { titleKey: "rowaction.confirm.disable.title", bodyKey: "rowaction.confirm.disable.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "disable", reason),
          invalidate: endpoint,
        },
        {
          key: "reactivate", labelKey: "rowaction.reactivate", icon: "play",
          when: (row) => isStatus(row, "lifecycle", "disabled"),
          confirm: { titleKey: "rowaction.confirm.reactivate.title", bodyKey: "rowaction.confirm.reactivate.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "reactivate", reason),
          invalidate: endpoint,
        },
        {
          key: "replaceSecret", labelKey: "rowaction.replaceSecret", icon: "refresh",
          when: (row) => !isStatus(row, "lifecycle", "archived"),
          custom: (row) => openDialog({ kind: "replace-secret", row }),
        },
        {
          key: "archive", labelKey: "rowaction.archive", icon: "package", danger: true,
          when: (row) => isStatus(row, "lifecycle", "disabled"),
          confirm: { titleKey: "rowaction.confirm.archive.title", bodyKey: "rowaction.confirm.archive.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "archive", reason),
          invalidate: endpoint,
        },
      ];
    }
    case "/models": {
      const endpoint = "/admin/v1/models";
      const nameOf = (row: Row) => text(row, "display_name") || text(row, "upstream_model_id");
      return [
        {
          key: "approve", labelKey: "rowaction.approve", icon: "check", primary: true,
          when: (row) => isStatus(row, "lifecycle", "discovered", "reviewing"),
          confirm: { titleKey: "rowaction.confirm.approve.title", bodyKey: "rowaction.confirm.approve.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "approve", reason),
          invalidate: endpoint, nameOf,
        },
        {
          key: "deprecate", labelKey: "rowaction.deprecate", icon: "flag",
          when: (row) => isStatus(row, "lifecycle", "published"),
          confirm: { titleKey: "rowaction.confirm.deprecate.title", bodyKey: "rowaction.confirm.deprecate.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "deprecate", reason),
          invalidate: endpoint, nameOf,
        },
        {
          key: "disable", labelKey: "rowaction.disable", icon: "pause", danger: true,
          when: (row) => !isStatus(row, "lifecycle", "disabled"),
          confirm: { titleKey: "rowaction.confirm.disable.title", bodyKey: "rowaction.confirm.disable.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "disable", reason),
          invalidate: endpoint, nameOf,
        },
      ];
    }
    case "/security": {
      const endpoint = "/admin/v1/approval-cases";
      const pending = (row: Row) => isStatus(row, "state", "pending");
      const others = (row: Row) => pending(row) && text(row, "requested_by") !== principal.id;
      const decide = (decision: "approve" | "reject"): RowActionDef<Row>["run"] =>
        (row, reason, password) => runWithStepUp("approval_decision", password, (grantId) =>
          api(`${endpoint}/${encodeURIComponent(String(row.id))}:${decision}`, {
            method: "POST",
            body: JSON.stringify({ reason, step_up_grant_id: grantId }),
          }));
      return [
        {
          key: "approve", labelKey: "rowaction.approve", icon: "check", primary: true,
          when: others,
          confirm: { titleKey: "rowaction.confirm.approve.title", bodyKey: "rowaction.confirm.approve.body", withReason: true, withPassword: true },
          run: decide("approve"),
          invalidate: endpoint,
          nameOf: (row) => text(row, "kind"),
        },
        {
          key: "reject", labelKey: "rowaction.reject", icon: "close", danger: true, primary: true,
          when: others,
          confirm: { titleKey: "rowaction.confirm.reject.title", bodyKey: "rowaction.confirm.reject.body", withReason: true, withPassword: true },
          run: decide("reject"),
          invalidate: endpoint,
          nameOf: (row) => text(row, "kind"),
        },
        {
          key: "cancel", labelKey: "rowaction.withdraw", icon: "close",
          when: (row) => pending(row) && text(row, "requested_by") === principal.id,
          confirm: { titleKey: "rowaction.confirm.withdraw.title", bodyKey: "rowaction.confirm.withdraw.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "cancel", reason),
          invalidate: endpoint,
          nameOf: (row) => text(row, "kind"),
        },
      ];
    }
    case "/alerts": {
      const endpoint = "/admin/v1/alerts";
      const nameOf = (row: Row) => text(row, "summary");
      return [
        {
          key: "acknowledge", labelKey: "rowaction.acknowledge", icon: "flag", primary: true,
          when: (row) => isStatus(row, "state", "open"),
          confirm: { titleKey: "rowaction.confirm.acknowledge.title", bodyKey: "rowaction.confirm.acknowledge.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "acknowledge", reason),
          invalidate: endpoint, nameOf,
        },
        {
          key: "resolve", labelKey: "rowaction.resolve", icon: "check", primary: true,
          when: (row) => isStatus(row, "state", "open", "acknowledged", "silenced"),
          confirm: { titleKey: "rowaction.confirm.resolve.title", bodyKey: "rowaction.confirm.resolve.body", withReason: true },
          run: (row, reason) => postLifecycle(endpoint, row, "resolve", reason),
          invalidate: endpoint, nameOf,
        },
      ];
    }
    case "/operations": {
      const endpoint = "/admin/v1/operations/jobs";
      return [
        {
          key: "cancel", labelKey: "rowaction.cancel", icon: "close", danger: true, primary: true,
          requiresRevision: false,
          when: (row) => isStatus(row, "state", "scheduled", "retry_wait") && typeof row.lease_generation === "number",
          confirm: { titleKey: "rowaction.confirm.cancel.title", bodyKey: "rowaction.confirm.cancel.body", withReason: true },
          // 任务没有 revision,乐观锁使用 lease_generation + 1(后端约定)
          run: (row, reason) => {
            const generation = Number(row.lease_generation) + 1;
            return api(`${endpoint}/${encodeURIComponent(String(row.id))}:cancel`, {
              method: "POST",
              headers: { "If-Match": `"rev-${generation}"` },
              body: JSON.stringify({ reason, expected_revision: generation }),
            });
          },
          invalidate: endpoint,
          nameOf: (row) => text(row, "kind"),
        },
      ];
    }
    case "/account": {
      const endpoint = "/admin/v1/auth/sessions";
      return [
        {
          key: "revoke", labelKey: "rowaction.revokeSession", icon: "logout", danger: true, primary: true,
          requiresRevision: false,
          when: (row) => row.current !== true,
          confirm: { titleKey: "rowaction.confirm.revokeSession.title", bodyKey: "rowaction.confirm.revokeSession.body" },
          run: (row) => api(`${endpoint}/${encodeURIComponent(String(row.id))}`, { method: "DELETE" }),
          invalidate: endpoint,
          nameOf: (row) => text(row, "user_agent_summary") || text(row, "id"),
        },
      ];
    }
    default:
      return undefined;
  }
}

export function useResourceRowActions(path: string, principal: Principal): { rowActions?: RowActionDef<Row>[]; rowDialogs?: ReactNode } {
  const [dialog, setDialog] = useState<DialogState>(null);
  const rowActions = useMemo(() => buildActions(path, principal, setDialog), [path, principal]);
  let rowDialogs: ReactNode = null;
  if (dialog?.kind === "edit-user") rowDialogs = <UserEditDialog row={dialog.row} onClose={() => setDialog(null)} />;
  else if (dialog?.kind === "edit-proxy") rowDialogs = <ProxyEditDialog row={dialog.row} onClose={() => setDialog(null)} />;
  else if (dialog?.kind === "replace-secret") rowDialogs = <ProxySecretDialog row={dialog.row} onClose={() => setDialog(null)} />;
  else if (dialog?.kind === "credential-detail") rowDialogs = <CredentialDetailDialog row={dialog.row} onClose={() => setDialog(null)} />;
  return { rowActions, rowDialogs };
}

/* ============================================================
   轻量编辑/密钥更换弹窗(复用 overlay/modal 样式)
   ============================================================ */

interface FieldDef {
  name: string;
  labelKey: MessageKey;
  type?: string;
  required?: boolean;
  defaultValue?: string;
  min?: number;
  max?: number;
  step?: number | "any";
  maxLength?: number;
  autoFocus?: boolean;
  autoComplete?: string;
  options?: { value: string; labelKey: MessageKey }[];
}

function RowFormDialog({ titleKey, subtitle, submitKey, danger, fields, onSubmit, onClose }: {
  titleKey: MessageKey;
  subtitle: string;
  submitKey?: MessageKey;
  danger?: boolean;
  fields: FieldDef[];
  onSubmit(form: FormData): Promise<unknown>;
  onClose(): void;
}) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const titleId = useId();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape" && !pending) onClose(); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [pending, onClose]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await onSubmit(new FormData(event.currentTarget));
      toast.success(t("action.success"));
      onClose();
    } catch (cause) {
      setError(cause);
    } finally {
      setPending(false);
    }
  }

  return createPortal(
    <div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget && !pending) onClose(); }}>
      <section className="modal confirm-modal" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <form onSubmit={(event) => void submit(event)}>
          <div className="modal-head">
            <div><h3 id={titleId}>{t(titleKey)}</h3><p className="muted">{subtitle}</p></div>
            <button type="button" className="ibtn outline" aria-label={t("common.close")} onClick={onClose} disabled={pending}>×</button>
          </div>
          <div className="modal-body">
            {error !== null && <div className="alert alert-err action-error" role="alert"><div><div className="at">{t("action.submitFailed")}</div><div className="ad">{rowActionError(error, locale)}</div></div></div>}
            {fields.map((field) => (
              <div className="field" key={field.name}>
                <label htmlFor={`${titleId}-${field.name}`}>{t(field.labelKey)}</label>
                {field.type === "textarea"
                  ? <textarea id={`${titleId}-${field.name}`} name={field.name} className="inp" rows={3} required={field.required} maxLength={field.maxLength} autoFocus={field.autoFocus} />
                  : field.type === "select"
                    ? <SelectField id={`${titleId}-${field.name}`} name={field.name} required={field.required} defaultValue={field.defaultValue ?? ""} autoFocus={field.autoFocus} options={(field.options ?? []).map((option) => ({ value: option.value, label: t(option.labelKey) }))} />
                    : <input id={`${titleId}-${field.name}`} name={field.name} className="inp" type={field.type ?? "text"} required={field.required} defaultValue={field.defaultValue} min={field.min} max={field.max} step={field.step} maxLength={field.maxLength} autoFocus={field.autoFocus} autoComplete={field.autoComplete} />}
              </div>
            ))}
          </div>
          <div className="modal-foot">
            <button type="button" className="btn btn-ghost" onClick={onClose} disabled={pending}>{t("common.cancel")}</button>
            <button type="submit" className={`btn ${danger ? "btn-danger" : "btn-primary"}`} disabled={pending}>{pending ? t("common.submitting") : t(submitKey ?? "common.save")}</button>
          </div>
        </form>
      </section>
    </div>,
    document.body,
  );
}

function useInvalidate(endpoint: string) {
  const queryClient = useQueryClient();
  return () => queryClient.invalidateQueries({ queryKey: [endpoint] });
}

function UserEditDialog({ row, onClose }: { row: Row; onClose(): void }) {
  const invalidate = useInvalidate("/admin/v1/users");
  return (
    <RowFormDialog
      titleKey="edit.user.title"
      subtitle={text(row, "username")}
      fields={[
        { name: "display_name", labelKey: "edit.field.displayName", required: true, maxLength: 128, defaultValue: text(row, "display_name"), autoFocus: true },
        { name: "email", labelKey: "edit.field.email", type: "email", maxLength: 320, defaultValue: text(row, "email") },
        { name: "role", labelKey: "action.user.role", type: "select", required: true, defaultValue: text(row, "role"), options: [{ value: "key_owner", labelKey: "user.role.key_owner" }, { value: "platform_admin", labelKey: "user.role.platform_admin" }] },
        { name: "max_concurrency", labelKey: "action.user.maxConcurrency", type: "number", required: true, min: 1, max: 1_000_000, defaultValue: String(row.max_concurrency ?? 5) },
        { name: "rpm", labelKey: "action.user.rpm", type: "number", required: true, min: 1, max: 1_000_000, defaultValue: String(row.rpm ?? 60) },
        { name: "balance_amount", labelKey: "action.user.balance", type: "number", min: 0, step: 0.01, defaultValue: row.balance_amount === null ? "" : String(row.balance_amount ?? "") },
      ]}
      onSubmit={async (form) => {
        const displayName = String(form.get("display_name") ?? "").trim();
        const email = String(form.get("email") ?? "").trim();
        const role = String(form.get("role") ?? "");
        const maxConcurrency = Number(form.get("max_concurrency"));
        const rpm = Number(form.get("rpm"));
        const balance = String(form.get("balance_amount") ?? "").trim();
        await api(`/admin/v1/users/${encodeURIComponent(String(row.id))}`, {
          method: "PATCH",
          headers: { "If-Match": `"rev-${Number(row.revision)}"` },
          body: JSON.stringify({ display_name: displayName, email, role, max_concurrency: maxConcurrency, rpm, balance_amount: balance || null }),
        });
        await invalidate();
      }}
      onClose={onClose}
    />
  );
}

function ProxyEditDialog({ row, onClose }: { row: Row; onClose(): void }) {
  const invalidate = useInvalidate("/admin/v1/proxies");
  return (
    <RowFormDialog
      titleKey="edit.proxy.title"
      subtitle={`${text(row, "host")}:${String(row.port ?? "")}`}
      fields={[
        { name: "name", labelKey: "edit.field.name", required: true, maxLength: 128, defaultValue: text(row, "name"), autoFocus: true },
        { name: "max_active_credentials", labelKey: "edit.field.capacity", type: "number", required: true, min: 1, max: 1000, defaultValue: String(row.max_active_credentials ?? "") },
      ]}
      onSubmit={async (form) => {
        const name = String(form.get("name") ?? "").trim();
        const capacity = Number(form.get("max_active_credentials"));
        await api(`/admin/v1/proxies/${encodeURIComponent(String(row.id))}`, {
          method: "PATCH",
          headers: { "If-Match": `"rev-${Number(row.revision)}"` },
          body: JSON.stringify({ ...(name ? { name } : {}), ...(Number.isInteger(capacity) ? { max_active_credentials: capacity } : {}) }),
        });
        await invalidate();
      }}
      onClose={onClose}
    />
  );
}

function ProxySecretDialog({ row, onClose }: { row: Row; onClose(): void }) {
  const invalidate = useInvalidate("/admin/v1/proxies");
  return (
    <RowFormDialog
      titleKey="rowaction.confirm.replaceSecret.title"
      subtitle={text(row, "name")}
      submitKey="rowaction.replaceSecret"
      danger
      fields={[
        { name: "username", labelKey: "rowaction.secretUsername", required: true, maxLength: 1024, autoFocus: true, autoComplete: "off" },
        { name: "password", labelKey: "rowaction.secretPassword", type: "password", required: true, maxLength: 4096, autoComplete: "new-password" },
        { name: "reason", labelKey: "rowaction.reason", type: "textarea", maxLength: 2048 },
        { name: "current_password", labelKey: "confirm.currentPassword", type: "password", required: true, autoComplete: "current-password" },
      ]}
      onSubmit={async (form) => {
        const username = String(form.get("username") ?? "");
        const password = String(form.get("password") ?? "");
        const reason = String(form.get("reason") ?? "").trim();
        const currentPassword = String(form.get("current_password") ?? "");
        await runWithStepUp("key_provider_change", currentPassword, (grantId) =>
          api(`/admin/v1/proxies/${encodeURIComponent(String(row.id))}:replace-secret`, {
            method: "POST",
            headers: { "If-Match": `"rev-${Number(row.revision)}"` },
            body: JSON.stringify({ username, password, reason, step_up_grant_id: grantId, expected_revision: row.revision }),
          }));
        await invalidate();
      }}
      onClose={onClose}
    />
  );
}
