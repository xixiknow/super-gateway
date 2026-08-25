import { afterEach, describe, expect, it, vi } from "vitest";
import { api, changePassword, setCsrfToken } from "../api";

afterEach(() => vi.restoreAllMocks());

describe("management API adapter", () => {
  it("keeps credentials same-origin and adds CSRF/idempotency on writes", async () => {
    setCsrfToken("csrf-fixture");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "ok" }, meta: {} }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    await api("/admin/v1/users/user-1:disable", { method: "POST", body: "{}" });
    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(init?.credentials).toBe("include");
    expect(init?.cache).toBe("no-store");
    expect(headers.get("x-csrf-token")).toBe("csrf-fixture");
    expect(headers.get("idempotency-key")).toBeTruthy();
  });

  it("uses the OpenAPI password-change route", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: null, meta: {} }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    await changePassword("old-password", "new-password");
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/admin/v1/auth/password/change");
  });
});
