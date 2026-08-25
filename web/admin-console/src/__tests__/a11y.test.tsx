import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import axe from "axe-core";
import { App } from "../App";

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
  render(<QueryClientProvider client={client}><MemoryRouter><App /></MemoryRouter></QueryClientProvider>);
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
  render(<QueryClientProvider client={client}><MemoryRouter><App /></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByRole("navigation", { name: "主导航" })).toBeInTheDocument();
  expect(screen.getByText("Credential Group")).toBeInTheDocument();
  expect(document.querySelector(".skip-link")).toHaveAttribute("href", "#main-content");
  const results = await axe.run(document, { rules: { "color-contrast": { enabled: false } } });
  expect(results.violations).toEqual([]);
});
