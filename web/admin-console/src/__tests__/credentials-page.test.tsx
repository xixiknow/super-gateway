import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Principal } from "../api";
import { CredentialsPage } from "../CredentialsPage";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";

const principal: Principal = {
  id: "00000000-0000-7000-8000-000000000001",
  role: "platform_admin",
  session_id: "00000000-0000-7000-8000-0000000000aa",
  csrf_token: "csrf",
  mfa_verified: true,
  password_change_required: false,
};

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function jsonResponse(data: unknown) {
  return new Response(JSON.stringify({ data, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><CredentialsPage principal={principal} /></QueryClientProvider></FeedbackProvider></I18nProvider>);
}

describe("credentials page (merged credential groups)", () => {
  it("renders credentials with the group column resolved from the group list and both create entries", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path === "/admin/v1/groups") return jsonResponse([
        { id: "g-1", name: "研发组", status: "active", credential_count: 1 },
        { id: "g-2", name: "备用组", status: "disabled", credential_count: 0 },
      ]);
      if (path === "/admin/v1/credentials") return jsonResponse([
        { id: "c-1", group_id: "g-1", account_uuid: "acct-a", purpose: "claude_subscription", auth_kind: "oauth_pkce", lifecycle_state: "active", scheduling_state: "eligible", updated_at: "2026-10-01T00:00:00Z" },
      ]);
      return jsonResponse([]);
    });
    renderPage();
    // 分组列由 group_id 客户端映射为名称
    expect(await screen.findByRole("button", { name: "研发组" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "新建凭据" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "新建分组" })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/admin/v1/credentials", expect.anything());
  });

  it("filters credentials through the group credentials endpoint when a group is selected", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path === "/admin/v1/groups") return jsonResponse([{ id: "g-1", name: "研发组", status: "active", credential_count: 1 }]);
      if (path === "/admin/v1/credentials") return jsonResponse([
        { id: "c-1", group_id: "g-1", account_uuid: "acct-a", lifecycle_state: "active" },
      ]);
      if (path === "/admin/v1/groups/g-1/credentials") return jsonResponse([
        { id: "c-2", group_id: "g-1", account_uuid: "acct-b", lifecycle_state: "disabled" },
      ]);
      return jsonResponse([]);
    });
    const user = userEvent.setup();
    renderPage();
    const filter = await screen.findByRole("combobox", { name: "按分组筛选" });
    await waitFor(() => expect(filter).toBeEnabled());
    await user.click(filter);
    await user.click(await screen.findByRole("option", { name: "研发组" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/admin/v1/groups/g-1/credentials", expect.anything()));
    expect(await screen.findByText("acct-b")).toBeInTheDocument();
  });
});
