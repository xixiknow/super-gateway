import type { Locale } from "./i18n";

export function formatCount(value: unknown, locale: Locale): string {
  return typeof value === "number" ? value.toLocaleString(locale) : "—";
}

export function formatAmount(value: unknown): string {
  return typeof value === "string" && value ? `$${Number(value).toFixed(2)}` : "—";
}

function toDate(value: unknown): Date | null {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value !== "string" && typeof value !== "number") return null;
  if (typeof value === "string" && !value.trim()) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

/** 全站统一时间格式:本地时区 YYYY-MM-DD HH:MM:SS */
export function formatDateTime(value: unknown, _locale?: Locale): string {
  const date = toDate(value);
  if (!date) return "—";
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/** 仅需年月日的场景:YYYY-MM-DD(由统一时间格式演变) */
export function formatDate(value: unknown, locale?: Locale): string {
  const formatted = formatDateTime(value, locale);
  return formatted === "—" ? formatted : formatted.slice(0, 10);
}

/** Cooldown/resume countdown as `HH:MM:SS`-style compact text. */
export function formatCountdown(totalSeconds: number, locale: Locale): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  const pad = (value: number) => value.toString().padStart(2, "0");
  if (locale === "zh-CN") {
    if (hours > 0) return `${hours}时${pad(minutes)}分`;
    if (minutes > 0) return `${minutes}分${pad(rest)}秒`;
    return `${rest}秒`;
  }
  if (hours > 0) return `${hours}h ${pad(minutes)}m`;
  if (minutes > 0) return `${minutes}m ${pad(rest)}s`;
  return `${rest}s`;
}
