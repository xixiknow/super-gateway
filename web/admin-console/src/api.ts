export type Role = "platform_admin" | "key_owner";

export interface Principal {
  id: string;
  role: Role;
  session_id: string;
  csrf_token: string;
  mfa_verified: boolean;
  password_change_required: boolean;
}

interface Envelope<T> {
  data: T;
  meta: Record<string, unknown>;
  page?: { next_cursor?: string | null };
}

interface ApiErrorEnvelope {
  error?: { code?: string; type?: string; message?: string };
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code = "api_error",
  ) {
    super(message);
  }
}

let csrfToken = "";

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  return (await apiEnvelope<T>(path, init)).data;
}

export async function apiEnvelope<T>(path: string, init: RequestInit = {}): Promise<Envelope<T>> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (method !== "GET" && method !== "HEAD") {
    if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
    if (!headers.has("Idempotency-Key")) headers.set("Idempotency-Key", crypto.randomUUID());
  }
  const response = await fetch(path, {
    ...init,
    method,
    headers,
    credentials: "include",
    cache: "no-store",
  });
  if (response.status === 204) return { data: undefined as T, meta: {} };
  const payload = (await response.json().catch(() => ({}))) as ApiErrorEnvelope | Envelope<T>;
  if (!response.ok) {
    const error = (payload as ApiErrorEnvelope).error;
    throw new ApiError(response.status, error?.message ?? "request_failed", error?.code ?? error?.type);
  }
  return payload as Envelope<T>;
}

export async function login(username: string, password: string): Promise<{ next_action: string; csrf_token: string }> {
  const result = await api<{ next_action: string; csrf_token: string }>("/admin/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  setCsrfToken(result.csrf_token);
  return result;
}

export async function currentPrincipal(): Promise<Principal> {
  const principal = await api<Principal>("/admin/v1/auth/me");
  setCsrfToken(principal.csrf_token);
  return principal;
}

export async function verifyMfa(code: string): Promise<void> {
  await api("/admin/v1/auth/mfa/verify", { method: "POST", body: JSON.stringify({ code }) });
}

export interface MfaEnrollment {
  id: string;
  secret: string;
  otpauth_uri: string;
}

export async function enrollMfa(): Promise<MfaEnrollment> {
  return api<MfaEnrollment>("/admin/v1/auth/mfa/enrollments", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function confirmMfa(enrollmentId: string, code: string): Promise<void> {
  await api(`/admin/v1/auth/mfa/enrollments/${encodeURIComponent(enrollmentId)}:confirm`, {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  await api("/admin/v1/auth/password/change", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

export async function logout(): Promise<void> {
  await api("/admin/v1/auth/session", { method: "DELETE" });
  setCsrfToken("");
}
