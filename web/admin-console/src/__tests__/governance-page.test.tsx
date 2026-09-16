import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GovernancePage } from "../GovernancePage";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const GROUP_ID = "00000000-0000-0000-0000-000000000021";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><GovernancePage /></QueryClientProvider></FeedbackProvider></I18nProvider>);
}

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

function mockApi(rulesets: unknown[] = []) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const path = String(input);
    const method = init?.method ?? "GET";
    if (method === "GET" && path.endsWith("/admin/v1/rulesets")) return jsonResponse({ data: rulesets, meta: {} });
    if (method === "GET" && path.endsWith("/admin/v1/groups")) {
      return jsonResponse({ data: [{ id: GROUP_ID, name: "研发组", status: "active" }], meta: {} });
    }
    if (method === "GET") return jsonResponse({ data: [], meta: {} });
    if (method === "POST" && path.endsWith("/admin/v1/rulesets")) {
      return jsonResponse({ data: { id: "ruleset-1", kind: "ruleset", version: 1, lifecycle: "eligible" }, meta: {} }, 201);
    }
    if (method === "POST" && path.includes(":validate")) {
      return jsonResponse({ data: { id: "ruleset-1", valid: true, rule_count: 1, revision: 1 }, meta: {} });
    }
    return jsonResponse({ error: { message: "not found" } }, 404);
  });
}

describe("governance page", () => {
  it("creates a ruleset through the structured editor without a raw JSON field", async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "创建规则集" }));
    const dialog = screen.getByRole("dialog", { name: "创建规则集" });
    expect(within(dialog).queryByLabelText("规则列表")).not.toBeInTheDocument();

    await user.type(within(dialog).getByLabelText("名称"), "默认上限");
    const groupSelect = within(dialog).getByRole("combobox", { name: "目标分组" });
    await waitFor(() => expect(groupSelect).toBeEnabled());
    await user.click(groupSelect);
    await user.click(await screen.findByRole("option", { name: "研发组" }));
    await user.type(within(dialog).getByLabelText("创建原因"), "回归测试");
    await user.type(within(dialog).getByLabelText("值（JSON 或文本）"), "4096");
    await user.type(within(dialog).getByLabelText("规则原因"), "默认 max_tokens");
    await user.click(within(dialog).getByRole("button", { name: "创建规则集" }));

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([path, init]) => String(path).endsWith("/admin/v1/rulesets") && init?.method === "POST")).toBe(true);
    });
    const post = fetchMock.mock.calls.find(([path, init]) => String(path).endsWith("/admin/v1/rulesets") && init?.method === "POST");
    const body = JSON.parse(String(post?.[1]?.body));
    expect(body.name).toBe("默认上限");
    expect(body.scope_type).toBe("group");
    expect(body.scope_id).toBe(GROUP_ID);
    expect(body.schema_version).toBe(1);
    expect(body.rules).toHaveLength(1);
    expect(body.rules[0]).toMatchObject({
      phase: "default",
      action: { action: "set_default", path: "body:/max_tokens", value: 4096 },
      when: { op: "always" },
      reason: "默认 max_tokens",
      risk: "low",
    });
  });

  it("shows lifecycle actions for an eligible ruleset and validates without a confirmation step", async () => {
    const fetchMock = mockApi([{
      id: "ruleset-1", kind: "ruleset", version: 3, lifecycle: "eligible", scope_type: "group", scope_id: GROUP_ID,
      payload: { name: "默认规则", rules: [{ id: "r1" }], source_refs: [] },
      is_active: false, validated_at: "2026-08-30T00:00:00Z", shadow_started_at: null, created_at: "2026-08-30T00:00:00Z",
    }]);
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("默认规则")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "发布 Shadow" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "模拟" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "激活" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "校验" }));
    expect(screen.queryByRole("alertdialog", { name: "校验" })).not.toBeInTheDocument();

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([path, init]) => String(path).includes("/admin/v1/rulesets/ruleset-1:validate") && init?.method === "POST")).toBe(true);
    });
    const call = fetchMock.mock.calls.find(([path]) => String(path).includes(":validate"));
    const headers = new Headers(call?.[1]?.headers);
    expect(headers.get("If-Match")).toBe('"rev-3"');
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({ reason: "", expected_revision: 3 });
  });
});
