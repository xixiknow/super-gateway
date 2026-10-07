import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "../App";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";
import { formatRequestTime, formatRequestDuration, RequestMetrics, requestClient } from "../RequestContent";

const record = {
  id: "request-fixture-uuid", platform_key_id: "key-fixture-uuid", group_id: "group-fixture-uuid",
  platform_key_name: "团队_Key", group_name: "研发组", model: "test_model-v1", reasoning_effort: "high",
  client_class: "claude_code_cli", input_tokens: 123, output_tokens: 0,
  client_name: "Claude Code", client_version: "2.1.245", request_type: "streaming",
  first_content_ms: 125, duration_ms: 2500, tps: 10.5, tps_estimated: false,
  cache_read_input_tokens: 45, cache_creation_input_tokens: null, http_status: 200,
  created_at: "2026-09-29T00:00:00Z", usage_completeness: "complete",
};

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function setup(body: unknown, status = 200, locale: "zh-CN" | "en-US" = "zh-CN", previewStatus = 200, previewData: unknown = { preview_status: "available", source: "original_request", body: { model: "test_model-v1" }, network_sent: false }) {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const path = String(input);
    let data: unknown = [];
    if (path.endsWith("/auth/me")) data = { id: "admin", role: "platform_admin", session_id: "session", csrf_token: "csrf", mfa_verified: true, password_change_required: false };
    else if (path.endsWith("/body")) return new Response(JSON.stringify(status === 200 ? { data: body } : { error: { message: "fixture error" } }), { status });
    else if (path.endsWith("/preview")) return new Response(JSON.stringify(previewStatus === 200 ? { data: previewData } : { error: { message: "preview fixture error" } }), { status: previewStatus });
    else if (path.endsWith("/requests")) data = [record];
    else if (path.endsWith(`/requests/${record.id}`)) data = record;
    return new Response(JSON.stringify({ data, meta: {} }), { status: 200 });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<I18nProvider initialLocale={locale}><FeedbackProvider><QueryClientProvider client={client}><MemoryRouter initialEntries={["/requests"]}><App /></MemoryRouter></QueryClientProvider></FeedbackProvider></I18nProvider>);
}

it("shows named resources and all four token counts, keeps IDs out of the list, and opens a right drawer", async () => {
  setup({ capture_status: "captured", original_request: { model: "test_model-v1" }, policy_request: null });
  const table = await screen.findByRole("table");
  expect(within(table).getByText("2026-09-29 08:00:00")).toBeInTheDocument();
  expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual([
    "创建时间", "平台 Key", "分组", "模型", "思考强度", "客户端", "请求类型", "TOKEN", "耗时", "用量完整度", "操作",
  ]);
  for (const value of ["团队_Key", "研发组", "test_model-v1", "high", "Claude Code 2.1.245", "流式", "125 ms", "2.50 s", "10.5 token/s", "123", "0", "45", "—"]) expect(within(table).getByText(value)).toBeInTheDocument();
  expect(within(table).queryByRole("columnheader", { name: "HTTP 状态" })).not.toBeInTheDocument();
  for (const id of [record.id, record.platform_key_id, record.group_id]) expect(within(table).queryByText(id)).not.toBeInTheDocument();
  const user = userEvent.setup();
  const opener = within(table).getByRole("button", { name: /查看详情/ });
  await user.click(opener);
  const drawer = await screen.findByRole("dialog");
  expect(drawer).toHaveClass("drawer", "request-detail-drawer");
  expect(await within(drawer).findByText(/"model": "test_model-v1"/)).toBeInTheDocument();
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(opener).toHaveFocus();
});

it("formats Beijing time with explicit timezone conversion and zero padding", () => {
  expect(formatRequestTime("2026-09-29T23:04:05Z")).toBe("2026-09-30 07:04:05");
  expect(formatRequestTime("2026-09-29 20:47:58.799916+08")).toBe("2026-09-29 20:47:58");
  expect(formatRequestTime("2026-09-29T05:04:05-07:00")).toBe("2026-09-29 20:04:05");
  expect(formatRequestTime("2026-09-29T16:00:00Z")).toBe("2026-09-30 00:00:00");
  expect(formatRequestTime(null)).toBe("—");
  expect(formatRequestTime("invalid")).toBe("—");
  expect(formatRequestTime("2026-09-29T12:00:00")).toBe("—");
});

it.each(["streaming", "websocket", "sync"])("shows the appropriate timing fields for %s", (request_type) => {
  render(<I18nProvider initialLocale="zh-CN"><RequestMetrics record={{ request_type, duration_ms: 2500, first_content_ms: 125, tps: 40, tps_estimated: true }} /></I18nProvider>);
  expect(screen.getByText("2.50 s")).toBeInTheDocument();
  expect(screen.getByText(/40.0 token\/s/)).toBeInTheDocument();
  expect(screen.getByText(/估算/)).toBeInTheDocument();
  expect(Boolean(screen.queryByText("首字"))).toBe(request_type !== "sync");
});

it("keeps unknown timing and versions distinct from measured zero", () => {
  expect(formatRequestDuration(null)).toBe("—");
  expect(formatRequestDuration(0)).toBe("0 ms");
  expect(formatRequestDuration(-1)).toBe("—");
  expect(requestClient({ client_name: "Codex", client_version: null }, "zh-CN")).toBe("Codex —");
  render(<I18nProvider initialLocale="zh-CN"><RequestMetrics record={{ request_type: "websocket" }} /></I18nProvider>);
  expect(screen.getAllByText("—")).toHaveLength(3);
});

it("opens a preview from an existing original body and copies full content", async () => {
  const user = userEvent.setup();
  const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
  const original = { messages: [{ content: "long content ".repeat(100) }] };
  setup({ original_request: original });
  await user.click(await screen.findByRole("button", { name: /查看详情/ }));
  await user.click(await screen.findByRole("button", { name: "复制原始请求" }));
  expect(write).toHaveBeenCalledWith(JSON.stringify(original, null, 2));
  await user.click(screen.getByRole("button", { name: "重组预览" }));
  expect(await screen.findByText(/"network_sent": false/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "复制无凭证重组预览" }));
  expect(JSON.parse(write.mock.calls.at(-1)?.[0] ?? "{}")).toMatchObject({ source: "original_request", network_sent: false });
  expect(screen.queryByText(/没有可用的已采集正文/)).not.toBeInTheDocument();
});

it("copies each body stage independently and reports clipboard failure", async () => {
  const user = userEvent.setup();
  const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
  const stages = [
    ["original_request", "原始请求", { stage: "original" }],
    ["policy_request", "策略处理后", { stage: "policy" }],
    ["final_upstream_request", "最终上行", { stage: "final" }],
    ["upstream_response", "响应原文", "event: message\ndata: raw\n\n"],
    ["upstream_response_final", "响应消息", { stage: "response" }],
  ] as const;
  setup(Object.fromEntries(stages.map(([key, , value]) => [key, value])));
  await user.click(await screen.findByRole("button", { name: /查看详情/ }));
  const panel = document.querySelector(".request-body-panel") as HTMLElement;
  for (const [, label, value] of stages) {
    await user.click(within(panel).getByRole("button", { name: label }));
    await user.click(within(panel).getByRole("button", { name: `复制${label}` }));
    expect(write).toHaveBeenLastCalledWith(typeof value === "string" ? value : JSON.stringify(value, null, 2));
  }
  write.mockRejectedValueOnce(new Error("clipboard denied"));
  await user.click(within(panel).getByRole("button", { name: "复制响应消息" }));
  expect(await screen.findByText(/复制失败，请手动选择内容复制/)).toBeInTheDocument();
});

it("explains a missing preview capture and disables copying", async () => {
  setup({}, 200, "zh-CN", 200, { preview_status: "missing_capture" });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: /查看详情/ }));
  expect(screen.getByRole("button", { name: "复制原始请求" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "重组预览" }));
  expect(await screen.findByText("没有可用的已采集正文")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "复制无凭证重组预览" })).toBeDisabled();
});

it("copies the final upstream and original response headers", async () => {
  const user = userEvent.setup();
  const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
  const snapshot = { entries: [{ name: "content-type", value: "application/json", redacted: false }], captured_at_ms: 0, transport: "http", reused: false, attempt_ordinal: 1, truncated: false };
  setup({ final_upstream_headers: snapshot, upstream_response_headers: { ...snapshot, entries: [{ name: "x-request-id", value: "upstream-id", redacted: false }] } });
  await user.click(await screen.findByRole("button", { name: /查看详情/ }));
  const panel = document.querySelector(".request-headers-panel") as HTMLElement;
  await user.click(within(panel).getByRole("button", { name: "最终上行" }));
  await user.click(within(panel).getByRole("button", { name: "复制最终上行" }));
  expect(write).toHaveBeenLastCalledWith("content-type: application/json");
  await user.click(within(panel).getByRole("button", { name: "上游响应" }));
  await user.click(within(panel).getByRole("button", { name: "复制上游响应" }));
  expect(write).toHaveBeenLastCalledWith("x-request-id: upstream-id");
});

it.each([403, 404, 503])("reports preview HTTP %s instead of claiming missing capture", async (status) => {
  setup({ original_request: { model: "test_model-v1" } }, 200, "zh-CN", status);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: /查看详情/ }));
  await user.click(screen.getByRole("button", { name: "重组预览" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(String(status));
});

it("shows redacted repeated headers, copies them, and identifies reused handshakes", async () => {
  const user = userEvent.setup();
  const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
  const snapshot = { entries: [{ name: "authorization", value: "[REDACTED]", redacted: true }, { name: "x-trace", value: "one", redacted: false }, { name: "x-trace", value: "two", redacted: false }], captured_at_ms: Date.parse("2026-09-29T00:00:00Z"), transport: "websocket_handshake", reused: true, attempt_ordinal: 2, truncated: true };
  setup({ original_headers: snapshot, final_upstream_headers: null, upstream_response_headers: snapshot });
  await user.click(await screen.findByRole("button", { name: /查看详情/ }));
  expect(await screen.findByText("复用握手")).toBeInTheDocument();
  expect(screen.getByText("尝试 #2")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "复制原始入站" }));
  expect(write).toHaveBeenCalledWith("authorization: [REDACTED]\nx-trace: one\nx-trace: two");
  const panel = document.querySelector(".request-headers-panel") as HTMLElement;
  await user.click(within(panel).getByRole("button", { name: "最终上行" }));
  expect(within(panel).getByRole("button", { name: "复制最终上行" })).toBeDisabled();
  await user.click(within(panel).getByRole("button", { name: "上游响应" }));
  expect(within(panel).getByRole("button", { name: "复制上游响应" })).toBeEnabled();
});

it("explains the current disabled capture setting without claiming it is the historical cause", async () => {
  setup({ capture_status: "unavailable", capture_enabled: false, retention_days: 7, max_bytes: 4194304 });
  await userEvent.setup().click(await screen.findByRole("button", { name: /查看详情/ }));
  expect(await screen.findByText(/当前正文采集已关闭/)).toBeInTheDocument();
  expect(screen.getByText(/历史正文不补录/)).toBeInTheDocument();
  expect(screen.getByText(/当前保留 7 天/)).toBeInTheDocument();
});

it.each([403, 500])("shows a body API %s error instead of calling it an expired capture", async (status) => {
  setup(null, status);
  await userEvent.setup().click(await screen.findByRole("button", { name: /查看详情/ }));
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent(String(status));
  expect(screen.queryByText(/此请求没有留存正文/)).not.toBeInTheDocument();
});

it("preserves model and resource names verbatim in English", async () => {
  setup({}, 200, "en-US");
  const table = await screen.findByRole("table");
  expect(within(table).getByText("test_model-v1")).toBeInTheDocument();
  expect(within(table).getByText("团队_Key")).toBeInTheDocument();
});
