import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ResourceActionButton } from "../ResourceAction";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function renderAction(action: Parameters<typeof ResourceActionButton>[0]["action"]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const rendered = render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><ResourceActionButton action={action} /></QueryClientProvider></FeedbackProvider></I18nProvider>);
  return { ...rendered, client };
}

describe("resource create actions", () => {
  it("starts public model synchronization directly without an audit confirmation dialog", async () => {
    let jobReads = 0;
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/admin/v1/models:refresh" && init?.method === "POST") return new Response(JSON.stringify({ data: {
        id: "job-1", type: "model_catalog_discovery_v1", status: "queued", progress: { completed: 0, total: 1 },
      }, meta: {} }), { status: 202, headers: { "content-type": "application/json" } });
      if (path === "/admin/v1/operations/jobs/job-1") {
        jobReads += 1;
        return new Response(JSON.stringify({ data: {
          id: "job-1", kind: "model_catalog_discovery_v1", state: jobReads === 1 ? "scheduled" : "succeeded", last_error: null,
        }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response("{}", { status: 404 });
    });
    const user = userEvent.setup();
    const { client } = renderAction("model-refresh");
    const invalidate = vi.spyOn(client, "invalidateQueries");

    await user.click(screen.getByRole("button", { name: "同步公开目录" }));

    expect(screen.queryByRole("dialog", { name: "同步 Anthropic 公开模型目录" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "同步中…" })).toBeDisabled();
    expect(screen.queryByText(/模型表格已刷新/, { selector: ".toast-text" })).not.toBeInTheDocument();
    expect(await screen.findByText(/模型表格已刷新/, { selector: ".toast-text" }, { timeout: 3_000 })).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([path]) => String(path) === "/admin/v1/operations/jobs/job-1")).toBe(true);
    const postCall = fetchMock.mock.calls.find(([path, init]) => String(path) === "/admin/v1/models:refresh" && init?.method === "POST");
    expect(JSON.parse(String(postCall?.[1]?.body))).toEqual({ reason: "admin_console_public_catalog_sync" });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["/admin/v1/models"] });
    expect(screen.getByRole("button", { name: "同步公开目录" })).toBeEnabled();
  });

  it("reports a terminal public model synchronization job failure", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/admin/v1/models:refresh" && init?.method === "POST") return new Response(JSON.stringify({ data: {
        id: "job-failed", type: "model_catalog_discovery_v1", status: "queued",
      }, meta: {} }), { status: 202, headers: { "content-type": "application/json" } });
      if (path === "/admin/v1/operations/jobs/job-failed") return new Response(JSON.stringify({ data: {
        id: "job-failed", kind: "model_catalog_discovery_v1", state: "dead_letter", last_error: "public_catalog_schema_invalid",
      }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
      return new Response("{}", { status: 404 });
    });
    const { client } = renderAction("model-refresh");
    const invalidate = vi.spyOn(client, "invalidateQueries");

    await userEvent.setup().click(screen.getByRole("button", { name: "同步公开目录" }));

    expect(await screen.findByText(/public_catalog_schema_invalid/, { selector: ".toast-text" })).toBeInTheDocument();
    expect(invalidate).not.toHaveBeenCalledWith({ queryKey: ["/admin/v1/models"] });
    expect(screen.getByRole("button", { name: "同步公开目录" })).toBeEnabled();
  });

  it("opens the group form and submits the documented POST payload", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ data: { id: "group-1", name: "研发团队" }, meta: {} }), {
      status: 201,
      headers: { "content-type": "application/json" },
    }));
    const user = userEvent.setup();
    renderAction("group");

    await user.click(screen.getByRole("button", { name: "新建" }));
    const dialog = screen.getByRole("dialog", { name: "新建凭据分组" });
    expect(dialog).toBeInTheDocument();
    await user.type(screen.getByLabelText("分组名称"), "研发团队");
    await user.click(within(dialog).getByRole("button", { name: "新建" }));

    expect(await screen.findByText("操作成功", { selector: ".at" })).toBeInTheDocument();
    expect(screen.getByText("操作成功", { selector: ".toast-text" })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe("/admin/v1/groups");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ name: "研发团队" });
    expect(screen.getByText("group-1", { selector: "dd" })).toBeInTheDocument();
  });

  it("reports malformed nested JSON before sending a request", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const user = userEvent.setup();
    renderAction("upgrade-check");

    await user.click(screen.getByRole("button", { name: "新建升级检查" }));
    const dialog = screen.getByRole("dialog", { name: "新建升级检查" });
    await user.type(screen.getByLabelText("检查原因"), "回归测试");
    await user.clear(screen.getByLabelText(/版本发布清单/));
    await user.type(screen.getByLabelText(/版本发布清单/), "not-json");
    await user.click(within(dialog).getByRole("button", { name: "新建升级检查" }));

    expect((await screen.findAllByText(/不是有效的结构化数据/)).length).toBeGreaterThan(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses the signed-in owner and selected group without sending client-side policy", async () => {
    const groupId = "00000000-0000-0000-0000-000000000022";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path.endsWith("/admin/v1/groups")) return new Response(JSON.stringify({ data: [{ id: groupId, name: "Primary Group", status: "active", credential_count: 2 }], meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
      if (path.endsWith("/admin/v1/platform-keys") && init?.method === "POST") return new Response(JSON.stringify({ data: { id: "key-1", name: "Desktop Key", status: "active" }, meta: {} }), { status: 201, headers: { "content-type": "application/json" } });
      return new Response("{}", { status: 404 });
    });
    const user = userEvent.setup();
    renderAction("platform-key");

    await user.click(screen.getByRole("button", { name: "创建" }));
    const dialog = screen.getByRole("dialog", { name: "创建平台密钥" });
    await user.type(screen.getByLabelText("名称"), "Desktop Key");
    const groupSelect = await screen.findByRole("combobox", { name: "凭据分组" });
    await waitFor(() => expect(groupSelect).toBeEnabled());
    await user.click(groupSelect);
    await user.click(await screen.findByRole("option", { name: "Primary Group · 2 个凭据" }));
    await user.click(within(dialog).getByRole("button", { name: "创建" }));

    expect(await screen.findByText("操作成功", { selector: ".at" })).toBeInTheDocument();
    expect(screen.getByText("操作成功", { selector: ".toast-text" })).toBeInTheDocument();
    const postCall = fetchMock.mock.calls.find(([path, init]) => String(path).endsWith("/admin/v1/platform-keys") && init?.method === "POST");
    expect(postCall).toBeTruthy();
    const payload = JSON.parse(String(postCall?.[1]?.body));
    expect(payload).toMatchObject({ name: "Desktop Key", group_id: groupId, endpoint_permissions: ["messages", "models"] });
    expect(payload).not.toHaveProperty("owner_user_id");
    expect(payload).not.toHaveProperty("body_limit_bytes");
    expect(payload).not.toHaveProperty("messages_rate");
    expect(payload).not.toHaveProperty("models_rate");
    expect(payload).not.toHaveProperty("concurrency");
  });

  it("submits an OAuth enrollment callback with the current revision", async () => {
    const groupId = "00000000-0000-0000-0000-000000000023";
    const enrollmentId = "00000000-0000-0000-0000-000000000024";
    const initial = {
      id: enrollmentId,
      revision: 7,
      state: "pending",
      next_action: "open_authorization_url",
      auth_method: "oauth_pkce",
      authorization_uri: "https://example.test/authorize?state=oauth-state",
      oauth_callback_nonce: "callback-nonce",
    };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/admin/v1/groups") return new Response(JSON.stringify({ data: [{ id: groupId, name: "Primary Group", status: "active", credential_count: 0 }], meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
      if (path === "/admin/v1/credential-enrollments" && init?.method === "POST") return new Response(JSON.stringify({ data: initial, meta: {} }), { status: 201, headers: { "content-type": "application/json" } });
      if (path === `/admin/v1/credential-enrollments/${enrollmentId}`) return new Response(JSON.stringify({ data: initial, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
      if (path === `/admin/v1/credential-enrollments/${enrollmentId}:complete-callback` && init?.method === "POST") return new Response(JSON.stringify({ data: { ...initial, revision: 8, next_action: "wait" }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
      return new Response("{}", { status: 404 });
    });
    const user = userEvent.setup();
    renderAction("credential");

    await user.click(screen.getByRole("button", { name: "新建" }));
    const dialog = screen.getByRole("dialog", { name: "发起凭据注册" });
    const groupSelect = await screen.findByRole("combobox", { name: "目标凭据分组" });
    await waitFor(() => expect(groupSelect).toBeEnabled());
    await user.click(groupSelect);
    await user.click(await screen.findByRole("option", { name: "Primary Group · 0 个凭据" }));
    await user.click(within(dialog).getByRole("button", { name: "新建" }));
    await user.type(await screen.findByLabelText(/^授权码/), "authorization-code");
    expect(screen.queryByLabelText(/^回调 state/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^回调随机数/)).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "提交回调完成注册" }));

    const callbackCall = fetchMock.mock.calls.find(([path, init]) => String(path).endsWith(":complete-callback") && init?.method === "POST");
    expect(callbackCall).toBeTruthy();
    expect(new Headers(callbackCall?.[1]?.headers).get("If-Match")).toBe('"rev-7"');
    expect(JSON.parse(String(callbackCall?.[1]?.body))).toEqual({
      authorization_code: "authorization-code",
      state: "oauth-state",
      callback_nonce: "callback-nonce",
    });
  });

  it("submits credential material with the current revision", async () => {
    const groupId = "00000000-0000-0000-0000-000000000025";
    const enrollmentId = "00000000-0000-0000-0000-000000000026";
    const initial = {
      id: enrollmentId,
      revision: 11,
      state: "pending",
      next_action: "submit_setup_material",
      auth_method: "setup_token",
      authorization_uri: null,
      oauth_callback_nonce: null,
    };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/admin/v1/groups") return new Response(JSON.stringify({ data: [{ id: groupId, name: "Primary Group", status: "active", credential_count: 0 }], meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
      if (path === "/admin/v1/credential-enrollments" && init?.method === "POST") return new Response(JSON.stringify({ data: initial, meta: {} }), { status: 201, headers: { "content-type": "application/json" } });
      if (path === `/admin/v1/credential-enrollments/${enrollmentId}`) return new Response(JSON.stringify({ data: initial, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
      if (path === `/admin/v1/credential-enrollments/${enrollmentId}:submit-material` && init?.method === "POST") return new Response(JSON.stringify({ data: { ...initial, revision: 12, next_action: "wait" }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
      return new Response("{}", { status: 404 });
    });
    const user = userEvent.setup();
    renderAction("credential");

    await user.click(screen.getByRole("button", { name: "新建" }));
    const dialog = screen.getByRole("dialog", { name: "发起凭据注册" });
    const groupSelect = await screen.findByRole("combobox", { name: "目标凭据分组" });
    await waitFor(() => expect(groupSelect).toBeEnabled());
    await user.click(groupSelect);
    await user.click(await screen.findByRole("option", { name: "Primary Group · 0 个凭据" }));
    await user.click(screen.getByLabelText("安装令牌"));
    await user.click(within(dialog).getByRole("button", { name: "新建" }));
    await user.type(await screen.findByLabelText("安装令牌"), "setup-token");
    await user.click(within(dialog).getByRole("button", { name: "提交认证材料" }));

    const materialCall = fetchMock.mock.calls.find(([path, init]) => String(path).endsWith(":submit-material") && init?.method === "POST");
    expect(materialCall).toBeTruthy();
    expect(new Headers(materialCall?.[1]?.headers).get("If-Match")).toBe('"rev-11"');
  });
});
