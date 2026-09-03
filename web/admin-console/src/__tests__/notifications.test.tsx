import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "../App";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";

afterEach(() => vi.restoreAllMocks());

it("opens a detail dialog, marks one read on open, and marks all read", async () => {
  const notifications = [
    { id: "notice-1", alert_id: "alert-1", severity: "critical", title: "关键告警", summary: "第一条消息的完整说明。", read_at: null, created_at: "2026-08-26T08:00:00Z" },
    { id: "notice-2", alert_id: null, severity: "warning", title: "容量提醒", summary: "第二条消息的完整说明。", read_at: null, created_at: "2026-08-26T07:00:00Z" },
  ];
  const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const path = String(input);
    if (path.endsWith("/auth/me")) return new Response(JSON.stringify({ data: { id: "019-admin", role: "platform_admin", session_id: "session-1", csrf_token: "csrf", mfa_verified: true, password_change_required: false }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
    if (path.endsWith("/notifications") && (!init?.method || init.method === "GET")) return new Response(JSON.stringify({ data: notifications, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
    if (path.endsWith("/notifications/notice-1:read") && init?.method === "POST") return new Response(JSON.stringify({ data: { ...notifications[0], read_at: "2026-08-26T08:01:00Z" }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
    if (path.endsWith("/notifications:read-all") && init?.method === "POST") return new Response(JSON.stringify({ data: { updated_count: 1 }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify({ data: {}, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const user = userEvent.setup();
  render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><MemoryRouter><App /></MemoryRouter></QueryClientProvider></FeedbackProvider></I18nProvider>);

  await user.click(await screen.findByRole("button", { name: "消息与通知" }));
  expect(await screen.findByText("2 条未读")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: /关键告警/ }));
  const detailDialog = await screen.findByRole("dialog", { name: "关键告警" });
  expect(within(detailDialog).getByText("消息详情")).toBeInTheDocument();
  expect(within(detailDialog).getByText("第一条消息的完整说明。", { selector: ".notification-detail-summary" })).toBeInTheDocument();
  expect(within(detailDialog).getByText("alert-1")).toBeInTheDocument();
  await waitFor(() => expect(screen.getByText("1 条未读")).toBeInTheDocument());
  const readCall = fetchMock.mock.calls.find(([path, init]) => String(path).endsWith("/notifications/notice-1:read") && init?.method === "POST");
  expect(new Headers(readCall?.[1]?.headers).get("If-Match")).toBe('"rev-1"');

  await user.click(within(detailDialog).getByRole("button", { name: "关闭" }));
  await user.click(screen.getByRole("button", { name: "全部标为已读" }));
  await waitFor(() => expect(screen.getByText("目前没有未读消息")).toBeInTheDocument());
  expect(fetchMock.mock.calls.some(([path, init]) => String(path).endsWith("/notifications:read-all") && init?.method === "POST")).toBe(true);
});
