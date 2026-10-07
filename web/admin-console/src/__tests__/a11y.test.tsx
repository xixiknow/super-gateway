import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import axe from "axe-core";
import { App } from "../App";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";

beforeEach(() => {
  document.documentElement.lang = "zh-CN";
  document.title = "Claude Code Gateway";
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it("renders the unauthenticated entry with labelled controls and one main landmark", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 401 }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><MemoryRouter><App /></MemoryRouter></QueryClientProvider></FeedbackProvider></I18nProvider>);
  expect(await screen.findByRole("main")).toBeInTheDocument();
  expect(await screen.findByLabelText("用户名")).toHaveAttribute("autocomplete", "username");
  expect(screen.getByLabelText("密码")).toHaveAttribute("type", "password");
  expect(screen.getByRole("button", { name: "继续" })).toBeEnabled();
  const results = await axe.run(document, {
    rules: {
      "color-contrast": { enabled: false },
    },
  });
  expect(results.violations).toEqual([]);
});

it("renders the authenticated admin navigation with a skip target and no automated structural violations", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const path = String(input);
    if (path.endsWith("/auth/me")) {
      return new Response(JSON.stringify({ data: {
        id: "019-admin", role: "platform_admin", session_id: "session-1", csrf_token: "csrf-fixture-token",
        mfa_verified: true, password_change_required: false,
      }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ data: [], meta: { has_more: false } }), { status: 200, headers: { "content-type": "application/json" } });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><MemoryRouter><App /></MemoryRouter></QueryClientProvider></FeedbackProvider></I18nProvider>);
  expect(await screen.findByRole("navigation", { name: "主导航" })).toBeInTheDocument();
  expect(screen.getByText("凭据")).toBeInTheDocument();
  expect(document.querySelector(".skip-link")).toHaveAttribute("href", "#main-content");
  await userEvent.setup().click(screen.getByRole("button", { name: "消息与通知" }));
  expect(screen.getByRole("dialog", { name: "通知" })).toBeInTheDocument();
  expect(await screen.findByText("暂无通知")).toBeInTheDocument();
  const results = await axe.run(document, { rules: { "color-contrast": { enabled: false } } });
  expect(results.violations).toEqual([]);
});

it("distinguishes upstream model synchronization from reloading the current table", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const path = String(input);
    if (path.endsWith("/auth/me")) {
      return new Response(JSON.stringify({ data: {
        id: "019-admin", role: "platform_admin", session_id: "session-1", csrf_token: "csrf-fixture-token",
        mfa_verified: true, password_change_required: false,
      }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (path.endsWith("/admin/v1/models")) {
      return new Response(JSON.stringify({ data: [{
        id: "model-1", upstream_model_id: "claude-public-fixture", display_name: "Claude Public Fixture",
        source: "anthropic_public_docs", lifecycle: "discovered", capability_version: null,
        capability_state: null, last_seen_at: "2026-08-28T00:00:00Z",
      }], meta: { has_more: false } }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ data: [], meta: { has_more: false } }), { status: 200, headers: { "content-type": "application/json" } });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><MemoryRouter initialEntries={["/models"]}><App /></MemoryRouter></QueryClientProvider></FeedbackProvider></I18nProvider>);

  expect(await screen.findByRole("heading", { name: "模型与能力", level: 1 })).toBeInTheDocument();
  const syncButton = screen.getByRole("button", { name: "同步目录与价格" });
  const reloadButton = screen.getByRole("button", { name: "刷新" });
  expect(syncButton.querySelector("use")).toHaveAttribute("href", "#i-globe");
  expect(reloadButton.querySelector("use")).toHaveAttribute("href", "#i-refresh");
  expect(await screen.findByRole("columnheader", { name: "目录来源" })).toBeInTheDocument();
  expect(await screen.findByText("Anthropic 公开目录")).toBeInTheDocument();
  await userEvent.setup().click(screen.getByRole("button", { name: "查看能力 · Claude Public Fixture" }));
  expect(screen.getByRole("dialog", { name: "Claude Public Fixture" })).toBeInTheDocument();
  const results = await axe.run(document, { rules: { "color-contrast": { enabled: false } } });
  expect(results.violations).toEqual([]);
});
