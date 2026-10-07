import type { Locale } from "./i18n";

export function formatCount(value: unknown, locale: Locale): string {
  return typeof value === "number" ? value.toLocaleString(locale) : "—";
}

export function formatAmount(value: unknown): string {
  return typeof value === "string" && value ? `$${Number(value).toFixed(2)}` : "—";
}

export function formatDateTime(value: unknown, locale: Locale): string {
  if (typeof value !== "string" || !value || Number.isNaN(Date.parse(value))) return "—";
  return new Date(value).toLocaleString(locale);
}

export function formatRelative(value: unknown, locale: Locale): string {
  if (typeof value !== "string" || !value || Number.isNaN(Date.parse(value))) return "—";
  const diffMs = Date.now() - Date.parse(value);
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  const minutes = Math.round(diffMs / 60_000);
  if (Math.abs(minutes) < 60) return formatter.format(-minutes, "minute");
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return formatter.format(-hours, "hour");
  return formatter.format(-Math.round(hours / 24), "day");
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
