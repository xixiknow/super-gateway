import { FormEvent, useEffect, useId, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "./api";
import { useToast } from "./feedback";
import { Locale, MessageKey, useI18n } from "./i18n";
import { rowActionError } from "./row-actions";
import { SelectField } from "./select-field";

type FieldType = "text" | "email" | "password" | "number" | "select" | "checkbox-group" | "radio-cards" | "datetime-local" | "json" | "resource" | "textarea" | "model-checkboxes";
type ResourceSource = "groups";

interface ActionField {
  name: string;
  labelKey: MessageKey;
  type: FieldType;
  required?: boolean;
  advanced?: boolean;
  defaultValue?: string;
  placeholderKey?: MessageKey;
  hintKey?: MessageKey;
  min?: number;
  max?: number;
  step?: number | "any";
  minLength?: number;
  maxLength?: number;
  options?: { value: string; labelKey?: MessageKey; label?: string }[];
  source?: ResourceSource;
}

interface ResourceActionConfig {
  buttonKey: MessageKey;
  titleKey: MessageKey;
  descriptionKey: MessageKey;
  endpoint: string;
  fields: ActionField[];
  buildPayload(values: FormData): unknown;
  invalidate: string[];
  intent?: "create" | "refresh";
  icon?: "plus" | "refresh" | "globe";
  policyNoteKey?: MessageKey;
  hideResultId?: boolean;
  direct?: boolean;
}

interface SubmittedJob {
  id: string;
  type: string;
  status: string;
}

interface DurableJob {
  id: string;
  kind: string;
  state: string;
  last_error: string | null;
}

const terminalJobStates = new Set(["succeeded", "dead_letter", "cancelled", "failed", "partially_succeeded"]);

export type ResourceActionKey =
  | "group" | "credential" | "user" | "platform-key" | "proxy" | "model-refresh"
  | "approval" | "alert-silence" | "upgrade-check" | "export";

class InvalidJsonFieldError extends Error {
  constructor(readonly field: string) { super(field); }
}

const text = (data: FormData, name: string): string => String(data.get(name) ?? "").trim();
const integer = (data: FormData, name: string): number => Number.parseInt(text(data, name), 10);
const optionalText = (data: FormData, name: string): string | null => text(data, name) || null;
const stringList = (data: FormData, name: string): string[] => data.getAll(name).flatMap((value) => String(value).split(/[,\r\n]/)).map((item) => item.trim()).filter(Boolean);
const isoDate = (data: FormData, name: string): string | null => {
  const value = text(data, name);
  return value ? new Date(value).toISOString() : null;
};
const json = (data: FormData, name: string): unknown => {
  try { return JSON.parse(text(data, name)); }
  catch { throw new InvalidJsonFieldError(name); }
};

const authMethods = [
  { value: "oauth_pkce", labelKey: "action.auth.oauth" },
  { value: "setup_token", labelKey: "action.auth.setupToken" },
  { value: "existing_oauth_material", labelKey: "action.auth.existingOauth" },
  { value: "console_api_key", labelKey: "action.auth.consoleKey" },
] satisfies ActionField["options"];

const approvalKinds = ["device_rebuild", "key_provider_change"].map((value) => ({ value }));

const actionConfigs: Record<ResourceActionKey, ResourceActionConfig> = {
  group: {
    buttonKey: "action.group.button", titleKey: "action.group.title", descriptionKey: "action.group.description",
    endpoint: "/admin/v1/groups", invalidate: ["/admin/v1/groups"], policyNoteKey: "action.group.policyNote",
    fields: [{ name: "name", labelKey: "action.group.name", type: "text", required: true, maxLength: 128, placeholderKey: "action.group.placeholder" }],
    buildPayload: (data) => ({ name: text(data, "name") }),
  },
  credential: {
    buttonKey: "action.credential.button", titleKey: "action.credential.title", descriptionKey: "action.credential.description",
    endpoint: "/admin/v1/credential-enrollments", invalidate: ["/admin/v1/credentials", "/admin/v1/credential-enrollments"],
    fields: [
      { name: "mode", labelKey: "action.mode", type: "select", required: true, defaultValue: "create", options: [{ value: "create", labelKey: "action.mode.create" }, { value: "recover", labelKey: "action.mode.recover" }] },
      { name: "target_group_id", labelKey: "action.group.select", type: "resource", source: "groups", required: true },
      { name: "auth_method", labelKey: "action.authMethod", type: "radio-cards", required: true, defaultValue: "oauth_pkce", options: authMethods },
      { name: "recovery_credential_id", labelKey: "action.recoveryCredential", type: "text", hintKey: "action.recoveryOnly", advanced: true },
      { name: "expected_credential_revision", labelKey: "action.expectedRevision", type: "number", min: 1, hintKey: "action.recoveryOnly", advanced: true },
    ],
    buildPayload: (data) => ({
      mode: text(data, "mode"), target_group_id: text(data, "target_group_id"), auth_method: text(data, "auth_method"),
      recovery_credential_id: optionalText(data, "recovery_credential_id"),
      expected_credential_revision: text(data, "expected_credential_revision") ? integer(data, "expected_credential_revision") : null,
    }),
  },
  user: {
    buttonKey: "action.user.button", titleKey: "action.user.title", descriptionKey: "action.user.description",
    endpoint: "/admin/v1/users", invalidate: ["/admin/v1/users"],
    fields: [
      { name: "username", labelKey: "action.user.username", type: "text", required: true },
      { name: "display_name", labelKey: "action.user.displayName", type: "text", required: true },
      { name: "email", labelKey: "action.user.email", type: "email", required: true },
      { name: "role", labelKey: "action.user.role", type: "select", required: true, defaultValue: "key_owner", options: [{ value: "key_owner", labelKey: "user.role.key_owner" }, { value: "platform_admin", labelKey: "user.role.platform_admin" }] },
      { name: "max_concurrency", labelKey: "action.user.maxConcurrency", type: "number", required: true, min: 1, max: 1_000_000, defaultValue: "5" },
      { name: "rpm", labelKey: "action.user.rpm", type: "number", required: true, min: 1, max: 1_000_000, defaultValue: "60" },
      { name: "balance_amount", labelKey: "action.user.balance", type: "number", min: 0, step: 0.01, defaultValue: "", hintKey: "action.user.balanceHint", advanced: true },
      { name: "temporary_password", labelKey: "action.user.temporaryPassword", type: "password", required: true, minLength: 14, maxLength: 128, hintKey: "action.user.passwordHint" },
    ],
    buildPayload: (data) => ({ username: text(data, "username"), display_name: text(data, "display_name"), email: text(data, "email"), role: text(data, "role"), temporary_password: text(data, "temporary_password"), max_concurrency: integer(data, "max_concurrency"), rpm: integer(data, "rpm"), balance_amount: optionalText(data, "balance_amount") }),
  },
  "platform-key": {
    buttonKey: "action.key.button", titleKey: "action.key.title", descriptionKey: "action.key.description", policyNoteKey: "action.key.policyHint",
    endpoint: "/admin/v1/platform-keys", invalidate: ["/admin/v1/platform-keys"],
    hideResultId: true,
    fields: [
      { name: "name", labelKey: "action.key.name", type: "text", required: true },
      { name: "group_id", labelKey: "action.key.group", type: "resource", source: "groups", required: true },
      { name: "spend_limit_amount", labelKey: "key.column.spendLimit", type: "number", min: 0, step: 0.01, hintKey: "key.edit.spendHint", advanced: true },
      { name: "endpoint_permissions", labelKey: "action.key.permissions", type: "checkbox-group", required: true, defaultValue: "messages,models", hintKey: "action.key.permissionsHint", options: [{ value: "messages", labelKey: "option.endpoint.messages" }, { value: "models", labelKey: "option.endpoint.models" }], advanced: true },
      { name: "model_allowlist", labelKey: "action.key.modelAllowlist", type: "model-checkboxes", hintKey: "action.key.modelAllowlistHint", advanced: true },
      { name: "ip_allowlist", labelKey: "action.key.ipAllowlist", type: "textarea", hintKey: "action.key.ipAllowlistHint", advanced: true },
      { name: "expires_at", labelKey: "action.key.expires", type: "datetime-local", advanced: true },
    ],
    buildPayload: (data) => ({
      name: text(data, "name"), group_id: text(data, "group_id"),
      endpoint_permissions: stringList(data, "endpoint_permissions"),
      model_allowlist: stringList(data, "model_allowlist"),
      ip_allowlist: stringList(data, "ip_allowlist"),
      expires_at: isoDate(data, "expires_at"),
      spend_limit_amount: optionalText(data, "spend_limit_amount"),
    }),
  },
  proxy: {
    buttonKey: "action.proxy.button", titleKey: "action.proxy.title", descriptionKey: "action.proxy.description",
    endpoint: "/admin/v1/proxies", invalidate: ["/admin/v1/proxies"],
    fields: [
      { name: "name", labelKey: "action.name", type: "text", required: true },
      { name: "type", labelKey: "action.proxy.type", type: "select", required: true, defaultValue: "http_connect", options: [{ value: "http_connect", labelKey: "option.proxy.httpConnect" }, { value: "socks5", labelKey: "option.proxy.socks5" }] },
      { name: "host", labelKey: "action.proxy.host", type: "text", required: true },
      { name: "port", labelKey: "action.proxy.port", type: "number", required: true, min: 1, max: 65535 },
      { name: "username", labelKey: "action.proxy.username", type: "text", advanced: true },
      { name: "password", labelKey: "action.proxy.password", type: "password", advanced: true },
      { name: "max_active_credentials", labelKey: "action.proxy.maxCredentials", type: "number", required: true, min: 1, defaultValue: "5", advanced: true },
    ],
    buildPayload: (data) => ({ name: text(data, "name"), type: text(data, "type"), host: text(data, "host"), port: integer(data, "port"), username: optionalText(data, "username"), password: optionalText(data, "password"), stability: "static", max_active_credentials: integer(data, "max_active_credentials") }),
  },
  "model-refresh": {
    buttonKey: "action.model.button", titleKey: "action.model.title", descriptionKey: "action.model.description",
    endpoint: "/admin/v1/models:refresh", invalidate: ["/admin/v1/models"], intent: "refresh", icon: "globe", direct: true,
    fields: [],
    buildPayload: () => ({ reason: "admin_console_public_catalog_sync" }),
  },
  approval: {
    buttonKey: "action.approval.button", titleKey: "action.approval.title", descriptionKey: "action.approval.description",
    endpoint: "/admin/v1/approval-cases", invalidate: ["/admin/v1/approval-cases"],
    fields: [
      { name: "kind", labelKey: "action.approval.kind", type: "select", required: true, defaultValue: "content_read", options: approvalKinds },
      { name: "scope", labelKey: "action.approval.scope", type: "json", required: true, defaultValue: "{}" },
      { name: "reason", labelKey: "action.approval.reason", type: "text" },
      { name: "action_snapshot_digest", labelKey: "action.approval.digest", type: "text", required: true, minLength: 64, maxLength: 64, advanced: true },
      { name: "step_up_grant_id", labelKey: "action.approval.grant", type: "text", required: true, advanced: true },
    ],
    buildPayload: (data) => ({ kind: text(data, "kind"), scope: json(data, "scope"), reason: text(data, "reason"), action_snapshot_digest: text(data, "action_snapshot_digest"), step_up_grant_id: text(data, "step_up_grant_id") }),
  },
  "alert-silence": {
    buttonKey: "action.silence.button", titleKey: "action.silence.title", descriptionKey: "action.silence.description",
    endpoint: "/admin/v1/alert-silences", invalidate: ["/admin/v1/alerts", "/admin/v1/alert-silences"],
    fields: [
      { name: "fingerprint_pattern", labelKey: "action.silence.pattern", type: "text", required: true, maxLength: 512 },
      { name: "reason", labelKey: "action.silence.reason", type: "text", maxLength: 2048 },
      { name: "starts_at", labelKey: "action.silence.starts", type: "datetime-local", advanced: true },
      { name: "expires_at", labelKey: "action.silence.expires", type: "datetime-local", required: true },
    ],
    buildPayload: (data) => ({ fingerprint_pattern: text(data, "fingerprint_pattern"), reason: text(data, "reason"), starts_at: isoDate(data, "starts_at"), expires_at: isoDate(data, "expires_at") }),
  },
  "upgrade-check": {
    buttonKey: "action.upgrade.button", titleKey: "action.upgrade.title", descriptionKey: "action.upgrade.description",
    endpoint: "/admin/v1/operations/upgrade-checks", invalidate: ["/admin/v1/operations/jobs"],
    fields: [{ name: "reason", labelKey: "action.upgrade.reason", type: "text", maxLength: 2048 }, { name: "release_manifest", labelKey: "action.upgrade.manifest", type: "json", required: true, defaultValue: "{}", hintKey: "action.upgrade.manifestHint" }],
    buildPayload: (data) => ({ reason: text(data, "reason"), release_manifest: json(data, "release_manifest") }),
  },
  export: {
    buttonKey: "action.export.button", titleKey: "action.export.title", descriptionKey: "action.export.description",
    endpoint: "/admin/v1/exports", invalidate: [],
    fields: [
      { name: "format", labelKey: "action.export.format", type: "select", required: true, defaultValue: "csv", options: [{ value: "csv", labelKey: "option.csv" }, { value: "jsonl", labelKey: "option.jsonl" }] },
      { name: "scope", labelKey: "action.export.scope", type: "select", required: true, defaultValue: "own", options: [{ value: "own", labelKey: "action.export.own" }, { value: "all", labelKey: "action.export.all" }] },
      { name: "from", labelKey: "action.export.from", type: "datetime-local", required: true },
      { name: "to", labelKey: "action.export.to", type: "datetime-local", required: true },
      { name: "filters", labelKey: "action.export.filters", type: "json", defaultValue: "{}", hintKey: "action.export.filtersHint", advanced: true },
    ],
    buildPayload: (data) => ({ dataset: "usage_requests_v1", format: text(data, "format"), scope: text(data, "scope"), from: isoDate(data, "from"), to: isoDate(data, "to"), filters: json(data, "filters") }),
  },
};

interface ResourceRecord { id?: unknown; name?: unknown; status?: unknown; credential_count?: unknown }

function resourceOptionLabel(item: ResourceRecord, credentialCount: (count: number) => string): string {
  const name = String(item.name || item.id || "");
  return typeof item.credential_count === "number" ? `${name} · ${credentialCount(item.credential_count)}` : name;
}

function ResourceSelect({ field, id, autoFocus }: { field: ActionField; id: string; autoFocus: boolean }) {
  const { t } = useI18n();
  const endpoint = "/admin/v1/groups";
  const result = useQuery({ queryKey: [endpoint], queryFn: () => api<ResourceRecord[]>(endpoint), retry: false });
  const options = (result.data ?? []).filter((item) => item.status === "active");
  return (
    <>
      <SelectField
        id={id}
        name={field.name}
        required={field.required}
        defaultValue=""
        autoFocus={autoFocus}
        disabled={result.isLoading || result.isError || options.length === 0}
        placeholder={result.isLoading ? t("common.loading") : options.length === 0 ? t("common.noneAvailable") : t("common.select")}
        options={options.map((item) => ({ value: String(item.id), label: resourceOptionLabel(item, (count) => t("action.credentialCount", { count })) }))}
      />
      {result.isError && <small className="field-error" role="alert">{t("action.optionLoadFailed")}</small>}
    </>
  );
}

function humanizeEnum(value: string, locale: Locale): string {
  const zh: Record<string, string> = {
    device_rebuild: "设备身份重建", key_provider_change: "密钥提供方变更",
  };
  if (locale === "zh-CN" && zh[value]) return zh[value];
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function FieldControl({ field, titleId, index }: { field: ActionField; titleId: string; index: number }) {
  const { locale, t } = useI18n();
  const id = `${titleId}-${field.name}`;
  const label = t(field.labelKey);
  return (
    <div className={`field ${field.type === "json" || field.type === "textarea" || field.type === "model-checkboxes" || field.type === "checkbox-group" || field.type === "radio-cards" ? "field-wide" : ""}`}>
      {field.type !== "checkbox-group" && field.type !== "radio-cards" && <label htmlFor={id}>{label}{field.hintKey && <span className="hint">{t(field.hintKey)}</span>}</label>}
      {field.type === "resource" ? <ResourceSelect field={field} id={id} autoFocus={index === 0} />
        : field.type === "checkbox-group" ? <fieldset className="choice-field"><legend>{label}{field.hintKey && <span className="hint">{t(field.hintKey)}</span>}</legend><div className="choice-grid">{field.options?.map((option) => <label key={option.value} className="choice-card"><input type="checkbox" name={field.name} value={option.value} defaultChecked={field.defaultValue?.split(",").includes(option.value)} /><span>{option.labelKey ? t(option.labelKey) : option.label ?? humanizeEnum(option.value, locale)}</span></label>)}</div></fieldset>
        : field.type === "radio-cards" ? <fieldset className="choice-field"><legend>{label}{field.hintKey && <span className="hint">{t(field.hintKey)}</span>}</legend><div className="choice-grid">{field.options?.map((option) => <label key={option.value} className="choice-card"><input type="radio" name={field.name} value={option.value} required={field.required} defaultChecked={field.defaultValue === option.value} /><span>{option.labelKey ? t(option.labelKey) : option.label ?? humanizeEnum(option.value, locale)}</span></label>)}</div></fieldset>
        : field.type === "select" ? <SelectField id={id} name={field.name} required={field.required} defaultValue={field.defaultValue ?? ""} autoFocus={index === 0} options={(field.options ?? []).map((option) => ({ value: option.value, label: option.labelKey ? t(option.labelKey) : option.label ?? humanizeEnum(option.value, locale) }))} />
        : field.type === "model-checkboxes" ? <ModelAllowlistField name={field.name} label={label} hint={field.hintKey ? t(field.hintKey) : undefined} />
        : field.type === "json" ? <textarea className="inp mono" id={id} name={field.name} required={field.required} defaultValue={field.defaultValue} rows={8} autoFocus={index === 0} />
        : field.type === "textarea" ? <textarea className="inp mono" id={id} name={field.name} required={field.required} defaultValue={field.defaultValue} rows={4} autoFocus={index === 0} placeholder="192.0.2.0/24" />
        : <input className="inp" id={id} name={field.name} type={field.type} required={field.required} defaultValue={field.defaultValue} placeholder={field.placeholderKey ? t(field.placeholderKey) : undefined} min={field.min} max={field.max} step={field.step} minLength={field.minLength} maxLength={field.maxLength} autoFocus={index === 0} autoComplete={field.type === "password" ? "new-password" : undefined} />}
    </div>
  );
}

function ModelAllowlistField({ name, label, hint }: { name: string; label: string; hint?: string }) {
  const { t } = useI18n();
  const models = useQuery({
    queryKey: ["/admin/v1/models"],
    queryFn: () => api<Array<{ id?: unknown; display_name?: unknown; upstream_model_id?: unknown; lifecycle?: unknown }>>("/admin/v1/models"),
    retry: false,
  });
  const published = (models.data ?? []).filter((model) => model.lifecycle === "published");
  return <fieldset className="choice-field"><legend>{label}{hint && <span className="hint">{hint}</span>}</legend>
    {models.isLoading ? <p className="muted">{t("common.loading")}</p> : models.isError ? <small className="field-error" role="alert">{t("action.optionLoadFailed")}</small> : published.length === 0 ? <p className="muted">{t("action.key.noPublishedModels")}</p> : <div className="choice-grid">{published.map((model) => { const id = String(model.id ?? ""); return <label key={id} className="choice-card"><input type="checkbox" name={name} value={id} /><span>{String(model.display_name ?? model.upstream_model_id ?? id)}</span></label>; })}</div>}
  </fieldset>;
}

function ActionIcon({ intent, icon }: { intent?: "create" | "refresh"; icon?: "plus" | "refresh" | "globe" }) {
  return <svg className="icon sm" aria-hidden="true"><use href={`#i-${icon ?? (intent === "refresh" ? "refresh" : "plus")}`} /></svg>;
}

function ResultSummary({ result, hideId = false }: { result: unknown; hideId?: boolean }) {
  const { locale, t } = useI18n();
  const record = typeof result === "object" && result !== null ? result as Record<string, unknown> : {};
  const summary = [
    [t("action.createdName"), record.name], ...(hideId ? [] : [[t("action.createdId"), record.id]]), [t("action.createdStatus"), record.status ? humanizeEnum(String(record.status), locale) : record.status],
  ].filter((item): item is [string, unknown] => item[1] !== undefined && item[1] !== null);
  const technicalResult = hideId && typeof result === "object" && result !== null
    ? Object.fromEntries(Object.entries(result as Record<string, unknown>).filter(([key]) => !key.endsWith("_id") && key !== "id"))
    : result;
  return (
    <>
      {summary.length > 0 && <dl className="action-summary">{summary.map(([label, value]) => <div key={label}><dt>{label}</dt><dd className="mono">{String(value)}</dd></div>)}</dl>}
      {record.secret !== undefined && <div className="one-time-secret"><span>{t("action.oneTimeSecret")}</span><code>{String(record.secret)}</code></div>}
      {result === undefined && <p className="muted">{t("action.completed")}</p>}
      <details className="result-details"><summary>{t("common.technicalDetails")}</summary><pre className="action-result mono">{technicalResult === undefined ? t("action.completed") : JSON.stringify(technicalResult, null, 2)}</pre></details>
    </>
  );
}

/* ============================================================
   凭据注册续办:创建后按服务端返回的 next_action 指引完成后续步骤
   oauth_pkce:打开授权页 → 提交回调(授权码 + state + 一次性随机数)
   其余方式:提交对应认证材料;随后轮询交换任务直至 succeeded
   ============================================================ */

interface EnrollmentRecord extends Record<string, unknown> {
  id: string;
  revision: number;
  state: string;
  next_action: string;
  auth_method: string;
  authorization_uri?: string | null;
  oauth_callback_nonce?: string | null;
}

const ENROLLMENT_TERMINAL = ["succeeded", "failed", "cancelled", "expired"];
const ENROLLMENT_ACTIONABLE = ["open_authorization_url", "complete_oauth_callback", "submit_setup_material", "submit_existing_oauth_material", "complete_browser_login", "retry", "manual_recovery"];

function CredentialEnrollmentFlow({ initial, onClose }: { initial: EnrollmentRecord; onClose(): void }) {
  const { locale, t } = useI18n();
  const queryClient = useQueryClient();
  const [copied, setCopied] = useState(false);
  const [authCode, setAuthCode] = useState("");
  const [oauthState, setOauthState] = useState("");
  // 回调页展示的代码为「授权码#state」连体格式,整段粘贴时自动拆分到两个字段
  function onAuthCodeChange(value: string) {
    const hashIndex = value.indexOf("#");
    if (hashIndex >= 0) {
      setAuthCode(value.slice(0, hashIndex));
      const rest = value.slice(hashIndex + 1);
      if (rest) setOauthState(rest);
    } else {
      setAuthCode(value);
    }
  }
  // 回调随机数仅在创建响应中返回一次,保存在组件内存里自动填入回调表单
  const nonce = typeof initial.oauth_callback_nonce === "string" ? initial.oauth_callback_nonce : "";
  const endpoint = `/admin/v1/credential-enrollments/${encodeURIComponent(initial.id)}`;
  const enrollment = useQuery({
    queryKey: [endpoint],
    queryFn: () => api<EnrollmentRecord>(endpoint),
    initialData: initial,
    refetchInterval: (query) => {
      const record = query.state.data;
      if (!record || ENROLLMENT_TERMINAL.includes(record.state) || ENROLLMENT_ACTIONABLE.includes(record.next_action)) return false;
      return 4000;
    },
  });
  const record = enrollment.data ?? initial;
  useEffect(() => {
    if (record.state === "succeeded") void queryClient.invalidateQueries({ queryKey: ["/admin/v1/credentials"] });
  }, [record.state, queryClient]);
  // state 由后端生成且已作为查询参数嵌入授权链接,直接解析预填,无需用户手动抄写
  const expectedState = useMemo(() => {
    if (typeof record.authorization_uri !== "string") return "";
    try {
      return new URL(record.authorization_uri).searchParams.get("state") ?? "";
    } catch {
      return "";
    }
  }, [record.authorization_uri]);
  useEffect(() => {
    if (expectedState) setOauthState((current) => current || expectedState);
  }, [expectedState]);
  const advance = useMutation({
    mutationFn: ({ suffix, body }: { suffix: string; body: Record<string, unknown> }) =>
      api<EnrollmentRecord>(`${endpoint}:${suffix}`, {
        method: "POST",
        headers: { "If-Match": `"rev-${record.revision}"` },
        body: JSON.stringify(body),
      }),
    onSuccess: (updated) => queryClient.setQueryData([endpoint], updated),
  });
  function submitCallback(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    advance.mutate({
      suffix: "complete-callback",
      body: {
        authorization_code: authCode.trim(),
        state: (oauthState || expectedState).trim(),
        callback_nonce: nonce,
      },
    });
  }
  function submitMaterial(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const body = record.next_action === "submit_setup_material"
      ? { setup_token: text(data, "setup_token") }
      : record.auth_method === "console_api_key"
        ? { console_api_key: text(data, "console_api_key") }
        : { access_token: text(data, "access_token"), refresh_token: text(data, "refresh_token") };
    advance.mutate({ suffix: "submit-material", body });
  }
  async function copyAuthUri() {
    if (typeof record.authorization_uri !== "string") return;
    try {
      await navigator.clipboard.writeText(record.authorization_uri);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch { /* 剪贴板不可用时静默失败,链接仍以明文展示 */ }
  }
  const statusChips = <div className="enroll-status" aria-live="polite">
    <span className="tag t-teal">{t("enroll.stateLabel")} · <span className="mono">{record.state}</span></span>
    <span className="tag t-gray">{t("enroll.nextActionLabel")} · <span className="mono">{record.next_action}</span></span>
  </div>;
  const errorAlert = advance.isError && <div className="alert alert-err" role="alert"><div><div className="at">{t("action.submitFailed")}</div><div className="ad">{rowActionError(advance.error, locale)}</div></div></div>;

  if (record.state === "succeeded") {
    return <><div className="modal-body">{statusChips}<div className="alert alert-ok" role="status"><div><div className="at">{t("enroll.succeeded")}</div><div className="ad">{t("enroll.succeededBody")}</div></div></div></div><div className="modal-foot"><button type="button" className="btn btn-primary" onClick={onClose}>{t("common.done")}</button></div></>;
  }
  if (ENROLLMENT_TERMINAL.includes(record.state) || ["retry", "manual_recovery"].includes(record.next_action)) {
    return <><div className="modal-body">{statusChips}<div className="alert alert-warn" role="alert"><div><div className="at">{t("enroll.failed")}</div><div className="ad">{t("enroll.failedBody")}</div></div></div></div><div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>{t("common.close")}</button></div></>;
  }
  if (record.next_action === "open_authorization_url" || record.next_action === "complete_oauth_callback") {
    return <form onSubmit={submitCallback}>
      <div className="modal-body">
        {statusChips}
        {errorAlert}
        <div className="policy-note"><svg className="icon sm" aria-hidden="true"><use href="#i-info" /></svg><span>{t("enroll.authGuide")}</span></div>
        {typeof record.authorization_uri === "string" && <>
          <div className="enroll-auth">
            <button type="button" className="btn btn-primary" onClick={() => window.open(String(record.authorization_uri), "_blank", "noopener")}><svg className="icon sm" aria-hidden="true"><use href="#i-globe" /></svg>{t("enroll.openAuth")}</button>
            <button type="button" className="tbtn" onClick={() => void copyAuthUri()}>{copied ? t("enroll.copied") : t("enroll.copyLink")}</button>
          </div>
          <p className="enroll-uri">{record.authorization_uri}</p>
        </>}
        <div className="field"><label htmlFor="enroll-code">{t("enroll.authorizationCode")}<span className="hint">{t("enroll.codeHint")}</span></label><input className="inp mono" id="enroll-code" name="authorization_code" value={authCode} onChange={(event) => onAuthCodeChange(event.target.value)} required autoComplete="off" /></div>
      </div>
      <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose} disabled={advance.isPending}>{t("common.close")}</button><button type="submit" className="btn btn-primary" disabled={advance.isPending}>{advance.isPending ? t("common.submitting") : t("enroll.submitCallback")}</button></div>
    </form>;
  }
  if (record.next_action === "submit_setup_material" || record.next_action === "submit_existing_oauth_material") {
    return <form onSubmit={submitMaterial}>
      <div className="modal-body">
        {statusChips}
        {errorAlert}
        {record.next_action === "submit_setup_material"
          ? <div className="field"><label htmlFor="enroll-setup">{t("enroll.setupToken")}</label><input className="inp mono" id="enroll-setup" name="setup_token" required autoComplete="off" /></div>
          : record.auth_method === "console_api_key"
            ? <div className="field"><label htmlFor="enroll-console">{t("enroll.consoleKey")}</label><input className="inp mono" id="enroll-console" name="console_api_key" required autoComplete="off" /></div>
            : <>
              <div className="field"><label htmlFor="enroll-access">{t("enroll.accessToken")}</label><input className="inp mono" id="enroll-access" name="access_token" required autoComplete="off" /></div>
              <div className="field"><label htmlFor="enroll-refresh">{t("enroll.refreshToken")}</label><input className="inp mono" id="enroll-refresh" name="refresh_token" required autoComplete="off" /></div>
            </>}
      </div>
      <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose} disabled={advance.isPending}>{t("common.close")}</button><button type="submit" className="btn btn-primary" disabled={advance.isPending}>{advance.isPending ? t("common.submitting") : t("enroll.submitMaterial")}</button></div>
    </form>;
  }
  return <><div className="modal-body">{statusChips}{errorAlert}<div className="enroll-wait"><span className="spin sm" aria-hidden="true" /><span>{record.next_action === "complete_browser_login" ? t("enroll.browserLogin") : t("enroll.waiting")}</span></div></div><div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>{t("common.close")}</button><button type="button" className="btn btn-outline" disabled={enrollment.isFetching} onClick={() => void enrollment.refetch()}>{t("enroll.refreshState")}</button></div></>;
}

export function ResourceActionButton({ action, className = "btn btn-primary", iconOnly = false }: { action: ResourceActionKey; className?: string; iconOnly?: boolean }) {
  const { t } = useI18n();
  const toast = useToast();
  const config = actionConfigs[action];
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [modelSyncJobId, setModelSyncJobId] = useState<string | null>(null);
  const titleId = useId();
  function describeError(error: unknown): string {
    const invalidField = error instanceof InvalidJsonFieldError ? config.fields.find((field) => field.name === error.field) : undefined;
    const apiMessage = error instanceof ApiError && error.message === "request_failed" ? t("common.requestFailed") : error instanceof Error ? error.message : undefined;
    if (invalidField) return t("common.jsonInvalid", { field: t(invalidField.labelKey) });
    if (error instanceof ApiError) return error.status ? t("common.http", { status: error.status, message: apiMessage ?? t("common.requestFailed") }) : apiMessage ?? t("common.requestFailed");
    return error instanceof Error ? error.message : t("common.operationFailed");
  }
  const mutation = useMutation({
    mutationFn: (values: FormData) => api<unknown>(config.endpoint, { method: "POST", body: JSON.stringify(config.buildPayload(values)) }),
    onSuccess: (result) => {
      if (action === "model-refresh") {
        const submitted = result as Partial<SubmittedJob>;
        if (!submitted.id || typeof submitted.id !== "string") {
          toast.error(t("action.model.syncFailed", { error: t("common.requestFailed") }));
          return;
        }
        setModelSyncJobId(submitted.id);
        return;
      }
      for (const queryKey of config.invalidate) void queryClient.invalidateQueries({ queryKey: [queryKey] });
      toast.success(t("action.success"));
    },
    onError: (error) => toast.error(describeError(error)),
  });
  const modelSyncJob = useQuery({
    queryKey: ["/admin/v1/operations/jobs", modelSyncJobId],
    queryFn: () => api<DurableJob>(`/admin/v1/operations/jobs/${encodeURIComponent(modelSyncJobId ?? "")}`),
    enabled: modelSyncJobId !== null,
    retry: false,
    refetchInterval: (query) => {
      const state = (query.state.data as DurableJob | undefined)?.state;
      return state && terminalJobStates.has(state) ? false : 1_000;
    },
  });
  useEffect(() => {
    if (!modelSyncJobId || !modelSyncJob.data) return;
    const job = modelSyncJob.data;
    if (job.state === "succeeded") {
      setModelSyncJobId(null);
      void Promise.all([
        queryClient.invalidateQueries({ queryKey: ["/admin/v1/models"] }),
        queryClient.invalidateQueries({ queryKey: ["/admin/v1/capability-versions"] }),
      ]).then(() => {
        toast.success(t("action.model.completed"));
      });
      return;
    }
    if (terminalJobStates.has(job.state)) {
      setModelSyncJobId(null);
      toast.error(t("action.model.syncFailed", { error: job.last_error || job.state }));
    }
  }, [modelSyncJob.data, modelSyncJobId, queryClient, t, toast]);
  useEffect(() => {
    if (!modelSyncJobId || !modelSyncJob.isError) return;
    setModelSyncJobId(null);
    toast.error(t("action.model.syncFailed", { error: describeError(modelSyncJob.error) }));
  }, [modelSyncJob.error, modelSyncJob.isError, modelSyncJobId, t, toast]);
  useEffect(() => {
    if (!open) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape" && !mutation.isPending) setOpen(false); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [open, mutation.isPending]);
  function triggerAction() {
    mutation.reset();
    if (config.direct) mutation.mutate(new FormData());
    else setOpen(true);
  }
  function closeDialog() { if (!mutation.isPending) { setOpen(false); mutation.reset(); } }
  function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); mutation.mutate(new FormData(event.currentTarget)); }

  const mutationError = mutation.error;
  const errorMessage = mutation.isError ? describeError(mutationError) : "";
  const basicFields = config.fields.filter((field) => !field.advanced);
  const advancedFields = config.fields.filter((field) => field.advanced);
  const working = mutation.isPending || modelSyncJobId !== null;
  const buttonLabel = action === "model-refresh" && working ? t("action.model.syncing") : t(config.buttonKey);

  return <>
    {iconOnly
      ? <button type="button" className={`ibtn outline${working ? " loading" : ""}`} data-tip={buttonLabel} aria-label={buttonLabel} aria-busy={working} disabled={working} onClick={triggerAction}><ActionIcon intent={config.intent} icon={config.icon} /></button>
      : <button type="button" className={`${className}${working ? " loading" : ""}`} aria-busy={working} disabled={working} onClick={triggerAction}><ActionIcon intent={config.intent} icon={config.icon} />{buttonLabel}</button>}
    {open && createPortal(<div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget) closeDialog(); }}>
      <section className="modal resource-action-modal" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <div className="modal-head"><div><p className="eyebrow mono">{t("action.eyebrow")}</p><h3 id={titleId}>{t(config.titleKey)}</h3><p className="muted resource-action-description">{t(config.descriptionKey)}</p></div><button type="button" className="ibtn outline" aria-label={t("common.close")} onClick={closeDialog} disabled={mutation.isPending}>×</button></div>
        {mutation.isSuccess ? (action === "credential"
          ? <CredentialEnrollmentFlow initial={mutation.data as EnrollmentRecord} onClose={closeDialog} />
          : <><div className="modal-body"><div className="alert alert-ok" role="status"><div><div className="at">{t("action.success")}</div><div className="ad">{t("action.successBody")}</div></div></div><ResultSummary result={mutation.data} hideId={config.hideResultId} /></div><div className="modal-foot"><button type="button" className="btn btn-primary" onClick={closeDialog}>{t("common.done")}</button></div></>)
          : <form onSubmit={submit}><div className="modal-body resource-action-grid">{mutation.isError && <div className="alert alert-err action-error" role="alert"><div><div className="at">{t("action.submitFailed")}</div><div className="ad">{errorMessage}</div></div></div>}{config.policyNoteKey && <div className="policy-note field-wide"><svg className="icon sm" aria-hidden="true"><use href="#i-lock" /></svg><span>{t(config.policyNoteKey)}</span></div>}{basicFields.map((field, index) => <FieldControl key={field.name} field={field} titleId={titleId} index={index} />)}{advancedFields.length > 0 && <details className="advanced-settings field-wide"><summary>{t("common.advanced")}</summary><p>{t("common.advancedHint")}</p><div className="resource-action-grid">{advancedFields.map((field, index) => <FieldControl key={field.name} field={field} titleId={titleId} index={basicFields.length + index} />)}</div></details>}</div><div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={closeDialog} disabled={mutation.isPending}>{t("common.cancel")}</button><button type="submit" className="btn btn-primary" disabled={mutation.isPending}>{mutation.isPending ? t("common.submitting") : t(config.buttonKey)}</button></div></form>}
      </section>
    </div>, document.body)}
  </>;
}
