import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ArchetypeBundlePage } from "../ArchetypeBundles";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><ArchetypeBundlePage /></QueryClientProvider></FeedbackProvider></I18nProvider>);
}

function mockApi() {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const path = String(input);
    if (!init?.method || init.method === "GET") return new Response(JSON.stringify({ data: [], meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
    if (path.endsWith("/admin/v1/environment-archetypes")) return new Response(JSON.stringify({ data: { id: "archetype-1", version: 1, version_lifecycle: "draft" }, meta: {} }), { status: 201, headers: { "content-type": "application/json" } });
    if (path.endsWith("/admin/v1/transport-bundles")) return new Response(JSON.stringify({ data: { id: "bundle-1", artifact_version: 1, lifecycle: "draft" }, meta: {} }), { status: 201, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify({ error: { message: "not found" } }), { status: 404, headers: { "content-type": "application/json" } });
  });
}

describe("environment archetype and transport bundle workflow", () => {
  it("creates an archetype with localized fields instead of a raw JSON editor", async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    renderPage();

    await user.click(screen.getByRole("button", { name: "创建环境原型" }));
    const dialog = screen.getByRole("dialog", { name: "创建环境原型" });
    expect(within(dialog).queryByText("环境原型载荷")).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("textbox", { name: /JSON/i })).not.toBeInTheDocument();

    await user.type(within(dialog).getByLabelText("原型名称"), "Windows 桌面环境");
    await user.type(within(dialog).getByLabelText("系统版本 / 构建号"), "Windows 11 24H2");
    await user.type(within(dialog).getByLabelText("Claude Code 版本"), "2.1.241");
    await user.type(within(dialog).getByLabelText("操作原因"), "建立本地运行环境");
    await user.click(within(dialog).getByRole("button", { name: "创建环境原型" }));

    expect(await screen.findByText("环境原型草稿已创建", { selector: ".toast-text" })).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([path, init]) => String(path).endsWith("/admin/v1/environment-archetypes") && init?.method === "POST");
    expect(post).toBeTruthy();
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({
      name: "Windows 桌面环境",
      schema_version: 1,
      archetype_id: null,
      payload: {
        os_family: "windows",
        architecture: "x86_64",
        os_build: "Windows 11 24H2",
        client_family: "claude_code_cli",
        runtime: "node",
        runtime_version: "24",
        client_version: "2.1.241",
        profile_schema_version: 1,
        capture_cohort: "local",
        protocol_profile: {},
        evidence_set_id: null,
        capacity: { max_credentials: 10, allocation_weight: 1, allocation_cohort: "default" },
      },
      source_refs: [],
      reason: "建立本地运行环境",
    });
  });

  it("uploads a signed bundle file without exposing its JSON as a textarea", async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    renderPage();

    await user.click(screen.getByRole("tab", { name: "传输包" }));
    await user.click(screen.getByRole("button", { name: "上传传输包" }));
    const dialog = screen.getByRole("dialog", { name: "上传签名传输包" });
    const envelope = {
      envelope_version: "1.0.0",
      payload: { artifact_version: 7, source_archetype_version_id: "version-1", application: { protocol: "h1" } },
      signature: { algorithm: "ed25519", detached_signature_base64: "signed" },
    };
    const file = new File([JSON.stringify(envelope)], "transport-bundle.json", { type: "application/json" });
    await user.upload(within(dialog).getByLabelText("签名传输包文件"), file);

    expect(await within(dialog).findByText("transport-bundle.json")).toBeInTheDocument();
    expect(within(dialog).getByText("7")).toBeInTheDocument();
    expect(within(dialog).queryByRole("textbox", { name: /JSON/i })).not.toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("上传记录名称"), "Windows H1 传输包");
    await user.type(within(dialog).getByLabelText("操作原因"), "发布新的传输实现");
    await user.click(within(dialog).getByRole("button", { name: "上传传输包" }));

    await waitFor(() => expect(fetchMock.mock.calls.some(([path, init]) => String(path).endsWith("/admin/v1/transport-bundles") && init?.method === "POST")).toBe(true));
    const post = fetchMock.mock.calls.find(([path, init]) => String(path).endsWith("/admin/v1/transport-bundles") && init?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ name: "Windows H1 传输包", schema_version: 1, signed_envelope: envelope, source_refs: [], reason: "发布新的传输实现" });
  });
});
