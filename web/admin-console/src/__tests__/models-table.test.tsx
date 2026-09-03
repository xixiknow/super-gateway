import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";
import { ModelsTable } from "../ModelsTable";

const baseVersion = {
  id: "capability-3",
  model_id: "model-1",
  capability_version: 3,
  lifecycle: "candidate",
  origin: "system_discovery",
  model_revision: 4,
  revision: 4,
  created_at: "2026-08-28T00:01:00Z",
  schema_payload: {
    schema_version: 1,
    metadata: {
      profile_completeness: "complete",
      profile_version: "2026-08-28.1",
      source_urls: ["https://platform.claude.com/docs/en/models/overview"],
    },
    rules: [{
      id: "provider-max-output-tokens",
      path: "body:/max_tokens",
      action: "required",
      types: ["integer"],
      enum_values: [],
      minimum: 1,
      maximum: 128000,
      exclusive_maximum_path: null,
      required_children: [],
      when: { op: "always" },
    }],
  },
};

function response(data: unknown, status = 200): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify({ data, meta: {} }), { status, headers: { "content-type": "application/json" } }));
}

function renderModels(version: Record<string, unknown> = baseVersion) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<I18nProvider initialLocale="zh-CN"><QueryClientProvider client={client}><FeedbackProvider><ModelsTable
    loading={false}
    title="模型与能力"
    items={[{
      id: "model-1",
      upstream_model_id: "claude-opus-fixture",
      display_name: "Claude Opus Fixture",
      source: "anthropic_public_docs",
      lifecycle: "published",
      capability_version: version.lifecycle === "active" ? 3 : null,
      capability_state: version.lifecycle === "active" ? "active" : null,
      max_input_tokens: 1_000_000,
      max_output_tokens: 128_000,
      provider_capabilities: { catalog_status: "current", thinking: "Adaptive", default_effort: "high", thinking_modes: ["adaptive", "disabled"], effort_levels: ["low", "medium", "high"], sampling_profile: "default_only", profile_completeness: "complete", profile_version: "2026-08-28.1" },
      revision: 4,
      last_seen_at: "2026-08-28T00:00:00Z",
      released_at: "2026-07-24T00:00:00Z",
    }]}
    onRefresh={() => undefined}
  /></FeedbackProvider></QueryClientProvider></I18nProvider>);
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it("opens capabilities in a right drawer and edits a system version as a new structured candidate", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
    const path = String(input);
    if (path === "/admin/v1/capability-versions" && init?.method === "POST") {
      return response({ ...baseVersion, id: "capability-4", capability_version: 4, origin: "manual" }, 201);
    }
    return response([baseVersion]);
  });
  renderModels();
  expect(screen.getByText("1M")).toBeInTheDocument();
  expect(screen.getByText("128K")).toBeInTheDocument();
  expect(screen.getByRole("columnheader", { name: "发布时间" })).toBeInTheDocument();
  expect(screen.getByText("2026/07/24")).toBeInTheDocument();
  const user = userEvent.setup();
  const trigger = screen.getByRole("button", { name: "查看能力 · Claude Opus Fixture" });
  await user.click(trigger);

  expect(screen.getByRole("dialog", { name: "Claude Opus Fixture" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "供应商公开能力" })).toBeInTheDocument();
  expect(screen.getByText("Adaptive")).toBeInTheDocument();
  expect(screen.getByText("系统生成")).toBeInTheDocument();
  expect(screen.getByText("完整能力")).toBeInTheDocument();
  expect(screen.getByText("矩阵 2026-08-28.1")).toBeInTheDocument();
  expect(screen.getByText("输出限制")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "编辑为新候选" }));
  expect(screen.getByRole("heading", { name: "结构化规则编辑器" })).toBeInTheDocument();
  expect(screen.getByLabelText("校验路径")).toHaveValue("body:/max_tokens");
  await user.clear(screen.getByLabelText("最大值"));
  await user.type(screen.getByLabelText("最大值"), "64000");
  await user.type(screen.getByLabelText("变更说明"), "按产品策略收紧最大输出");
  await user.click(screen.getByRole("button", { name: "保存为候选版本" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/admin/v1/capability-versions", expect.objectContaining({ method: "POST" })));
  const createCall = fetchMock.mock.calls.find(([path, init]) => String(path) === "/admin/v1/capability-versions" && init?.method === "POST");
  const payload = JSON.parse(String(createCall?.[1]?.body));
  expect(payload).toMatchObject({
    model_id: "model-1",
    schema_version: 1,
    reason: "按产品策略收紧最大输出",
    rules: [{ id: "provider-max-output-tokens", path: "body:/max_tokens", maximum: 64000, exclusive_maximum_path: null, when: { op: "always" } }],
  });
});

it("keeps the capability drawer open when its cascading candidate editor closes", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(() => response([baseVersion]));
  renderModels();
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "查看能力 · Claude Opus Fixture" }));
  const edit = await screen.findByRole("button", { name: "编辑为新候选" });
  await user.click(edit);

  const capabilityDrawer = screen.getByRole("dialog", { name: "Claude Opus Fixture" });
  const editorDrawer = screen.getByRole("dialog", { name: "结构化规则编辑器" });
  expect(screen.getAllByRole("dialog")).toHaveLength(2);
  expect(editorDrawer).toHaveClass("cascade", "capability-editor-drawer");
  expect(document.querySelector(".drawer-mask.cascade")).toBeInTheDocument();
  // 编辑器打开时,下层能力抽屉被向左推开(pushed),而不是被遮盖
  expect(capabilityDrawer).toHaveClass("pushed");

  await user.click(within(editorDrawer).getByRole("button", { name: "关闭" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "结构化规则编辑器" })).not.toBeInTheDocument());
  expect(capabilityDrawer).toBeInTheDocument();
  // 编辑器关闭后,能力抽屉滑回原位
  expect(capabilityDrawer).not.toHaveClass("pushed");
  expect(edit).toHaveFocus();
});

it("round-trips the relative exclusive maximum constraint in the structured editor", async () => {
  const relativeVersion = {
    ...baseVersion,
    schema_payload: {
      ...baseVersion.schema_payload,
      rules: [{
        ...baseVersion.schema_payload.rules[0],
        id: "thinking-budget",
        path: "body:/thinking/budget_tokens",
        minimum: 1024,
        maximum: null,
        exclusive_maximum_path: "body:/max_tokens",
        when: { op: "equals", path: "body:/thinking/type", value: "enabled", mode: "any_match" },
      }],
    },
  };
  vi.spyOn(globalThis, "fetch").mockImplementation(() => response([relativeVersion]));
  renderModels(relativeVersion);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "查看能力 · Claude Opus Fixture" }));
  await user.click(screen.getByRole("button", { name: "编辑为新候选" }));
  expect(screen.getByLabelText("必须小于字段")).toHaveValue("body:/max_tokens");
  expect(screen.getAllByText("Thinking").length).toBeGreaterThan(0);
});

it("requires validation before activating a candidate and sends the model revision precondition", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
    const path = String(input);
    if (path.endsWith(":validate")) return response({ id: baseVersion.id, valid: true, revision: 4 });
    if (path.endsWith(":activate")) return response({ id: baseVersion.id, lifecycle: "active", revision: 5 });
    if (path === "/admin/v1/models") return response([]);
    return response([baseVersion]);
  });
  renderModels();
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "查看能力 · Claude Opus Fixture" }));
  const activate = await screen.findByRole("button", { name: "激活版本" });
  expect(activate).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "校验候选" }));
  await waitFor(() => expect(activate).toBeEnabled());
  await user.click(activate);

  const confirm = screen.getByRole("alertdialog", { name: "激活网关能力版本" });
  expect(confirm).toBeInTheDocument();
  await user.type(screen.getByLabelText("操作原因"), "审核通过并发布");
  await user.click(screen.getByRole("button", { name: "确认激活" }));
  await waitFor(() => expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith(":activate"))).toBe(true));

  const validateCall = fetchMock.mock.calls.find(([path]) => String(path).endsWith(":validate"));
  expect(new Headers(validateCall?.[1]?.headers).get("If-Match")).toBe('"rev-4"');
  expect(JSON.parse(String(validateCall?.[1]?.body))).toEqual({ expected_revision: 4 });
  const activateCall = fetchMock.mock.calls.find(([path]) => String(path).endsWith(":activate"));
  expect(new Headers(activateCall?.[1]?.headers).get("If-Match")).toBe('"rev-4"');
  expect(JSON.parse(String(activateCall?.[1]?.body))).toEqual({ reason: "审核通过并发布", expected_revision: 4 });
});
