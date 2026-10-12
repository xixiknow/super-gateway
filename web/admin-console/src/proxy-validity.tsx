import { ReactNode, useId, useMemo, useState } from "react";
import { displayCell } from "./display";
import { formatDateTime } from "./format";
import { Locale, MessageKey, useI18n } from "./i18n";
import { SelectField } from "./select-field";

/* ============================================================
   代理有效期字段组:开始时间 + 有效期(预设/自定义/永不过期)
   + 到期策略 + 到期提醒。到期时间 = 开始时间 + 时长,只读预览,
   由服务端最终计算。创建与编辑弹窗共用。
   ============================================================ */

export const VALIDITY_PRESETS = ["7", "30", "90", "180", "365"] as const;
export const EXPIRY_POLICIES = [
  { value: "none", labelKey: "option.expiryPolicy.none" },
  { value: "fallback_direct", labelKey: "option.expiryPolicy.fallbackDirect" },
  { value: "switch_proxy", labelKey: "option.expiryPolicy.switchProxy" },
] satisfies { value: string; labelKey: MessageKey }[];
export const REMIND_OPTIONS = ["0", "24", "72", "168"] as const;

export interface ProxyValidityValues {
  startsAt: string;
  validityDays: number | null;
  expiryPolicy: string;
  remindBeforeHours: number;
}

/** 将 Date 格式化为 datetime-local 控件需要的本地时间字符串 */
export function toLocalInput(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** 从表单读取有效期字段;自定义天数非法时返回 null 由调用方报错 */
export function readProxyValidity(data: FormData): ProxyValidityValues | null {
  const startsAtLocal = String(data.get("starts_at") ?? "").trim();
  const startsAt = startsAtLocal ? new Date(startsAtLocal) : null;
  if (!startsAt || Number.isNaN(startsAt.getTime())) return null;
  const validity = String(data.get("validity") ?? "");
  let validityDays: number | null;
  if (validity === "never") validityDays = null;
  else if (validity === "custom") validityDays = Number.parseInt(String(data.get("validity_custom_days") ?? ""), 10);
  else validityDays = Number.parseInt(validity, 10);
  if (validityDays !== null && (!Number.isInteger(validityDays) || validityDays < 1 || validityDays > 3650)) return null;
  return {
    startsAt: startsAt.toISOString(),
    validityDays,
    expiryPolicy: String(data.get("expiry_policy") ?? "none"),
    remindBeforeHours: Number.parseInt(String(data.get("remind_before_hours") ?? "72"), 10),
  };
}

export function validityPayload(values: ProxyValidityValues) {
  return {
    starts_at: values.startsAt,
    validity_days: values.validityDays,
    expiry_policy: values.expiryPolicy,
    remind_before_hours: values.remindBeforeHours,
  };
}

function initialValidity(days: number | null | undefined): string {
  if (days === null) return "never";
  if (days === undefined) return "30";
  return (VALIDITY_PRESETS as readonly string[]).includes(String(days)) ? String(days) : "custom";
}

export function ProxyValidityFields({ initial, idPrefix }: {
  initial?: { startsAt?: string | null; validityDays?: number | null; expiryPolicy?: string; remindBeforeHours?: number };
  idPrefix?: string;
}) {
  const { locale, t } = useI18n();
  const generated = useId();
  const prefix = idPrefix ?? generated;
  const [startsAt, setStartsAt] = useState(() => toLocalInput(initial?.startsAt ? new Date(initial.startsAt) : new Date()));
  const [validity, setValidity] = useState(() => initialValidity(initial?.validityDays));
  const [customDays, setCustomDays] = useState(() => validity === "custom" && initial?.validityDays ? String(initial.validityDays) : "");
  const days = validity === "never" ? null : Number.parseInt(validity === "custom" ? customDays : validity, 10);
  const expires = useMemo(() => {
    const start = new Date(startsAt);
    if (days === null || !Number.isInteger(days) || days < 1 || Number.isNaN(start.getTime())) return null;
    return new Date(start.getTime() + days * 86_400_000);
  }, [startsAt, days]);
  const preview = validity === "never"
    ? t("action.proxy.neverExpires")
    : expires ? formatDateTime(expires) : "—";

  return <>
    <div className="field">
      <label htmlFor={`${prefix}-starts_at`}>{t("action.proxy.startsAt")}</label>
      <input className="inp" id={`${prefix}-starts_at`} name="starts_at" type="datetime-local" required value={startsAt} onChange={(event) => setStartsAt(event.target.value)} />
    </div>
    <div className="field">
      <label htmlFor={`${prefix}-validity`}>{t("action.proxy.validity")}</label>
      <SelectField
        id={`${prefix}-validity`}
        name="validity"
        required
        value={validity}
        onChange={setValidity}
        options={[
          ...VALIDITY_PRESETS.map((value) => ({ value, label: t(`option.validity.${value}` as MessageKey) })),
          { value: "custom", label: t("option.validity.custom") },
          { value: "never", label: t("option.validity.never") },
        ]}
      />
    </div>
    {validity === "custom" && <div className="field">
      <label htmlFor={`${prefix}-validity_custom_days`}>{t("action.proxy.validityCustomDays")}</label>
      <input className="inp" id={`${prefix}-validity_custom_days`} name="validity_custom_days" type="number" required min={1} max={3650} step={1} value={customDays} onChange={(event) => setCustomDays(event.target.value)} />
    </div>}
    <p className="muted field-wide proxy-expiry-preview" role="status">{t("action.proxy.expiresPreview", { value: preview })}</p>
    <div className="field">
      <label htmlFor={`${prefix}-expiry_policy`}>{t("action.proxy.expiryPolicy")}<span className="hint">{t("action.proxy.expiryPolicyHint")}</span></label>
      <SelectField id={`${prefix}-expiry_policy`} name="expiry_policy" required defaultValue={initial?.expiryPolicy ?? "none"} options={EXPIRY_POLICIES.map((option) => ({ value: option.value, label: t(option.labelKey) }))} />
    </div>
    <div className="field">
      <label htmlFor={`${prefix}-remind_before_hours`}>{t("action.proxy.remindBefore")}<span className="hint">{t("action.proxy.remindBeforeHint")}</span></label>
      <SelectField
        id={`${prefix}-remind_before_hours`}
        name="remind_before_hours"
        required
        defaultValue={String(initial?.remindBeforeHours ?? 72)}
        options={[
          ...REMIND_OPTIONS.map((value) => ({ value, label: t(`option.remind.${value}` as MessageKey) })),
          ...(initial?.remindBeforeHours !== undefined && !(REMIND_OPTIONS as readonly string[]).includes(String(initial.remindBeforeHours))
            ? [{ value: String(initial.remindBeforeHours), label: `${initial.remindBeforeHours}h` }]
            : []),
        ]}
      />
    </div>
  </>;
}

const PROTOCOL_LABELS: Record<string, string> = { http_connect: "HTTP", https_connect: "HTTPS", socks5: "SOCKS5" };
const EXPIRY_STATES: readonly string[] = ["not_started", "active", "expiring_soon", "expired", "never"];

function ProxyCell({ column, record }: { column: string; record: Record<string, unknown> }) {
  const { locale, t } = useI18n();
  return <>{proxyCellContent(column, record, locale, t)}</>;
}

function proxyCellContent(
  column: string,
  record: Record<string, unknown>,
  locale: Locale,
  t: (key: MessageKey, vars?: Record<string, string | number>) => string,
): ReactNode {
  const value = record[column];
  if (column === "type") return PROTOCOL_LABELS[String(value)] ?? displayCell(value, locale);
  if (column === "host") return record.port ? `${String(value ?? "")}:${String(record.port)}` : displayCell(value, locale);
  if (column === "expires_at") {
    if (value === null || value === undefined) return t("action.proxy.neverExpires");
    return formatDateTime(String(value));
  }
  if (column === "expiry_state" && typeof value === "string" && EXPIRY_STATES.includes(value)) {
    return <span className={`validity-badge validity-${value}`}>{t(`proxy.expiryState.${value}` as MessageKey)}</span>;
  }
  return displayCell(value, locale);
}

/** 代理列表的单元格渲染:协议简称、主机:端口、到期时间与有效期状态徽标 */
export function renderProxyCell(column: string, record: Record<string, unknown>): ReactNode {
  return <ProxyCell column={column} record={record} />;
}
