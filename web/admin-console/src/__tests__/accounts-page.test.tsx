import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { AccountsPage } from "../AccountsPage";
import { formatCountdown } from "../format";
import { Meter } from "../meter";
import { I18nProvider } from "../i18n";
import { FeedbackProvider } from "../feedback";
import type { Principal } from "../api";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const principal: Principal = {
  id: "01900000-0000-7000-8000-000000000001",
  role: "platform_admin",
  session_id: "session",
  csrf_token: "csrf",
  mfa_verified: true,
  password_change_required: false,
};

const credentialRow = {
  id: "01900000-0000-7000-8000-0000000000aa",
  group_id: "01900000-0000-7000-8000-0000000000g1",
  account_uuid: "01900000-0000-7000-8000-0000000000ab",
  purpose: "business",
  auth_kind: "oauth_subscription",
  lifecycle_state: "active",
  auth_state: "healthy",
  scheduling_state: "cooldown",
  quota_state: "pressured",
  transport_state: "ready",
  management_class: "fully_managed",
  token_version: 1,
  cooldown_until: new Date(Date.now() + 60_000).toISOString(),
  last_error_code: "overloaded",
  last_error_message: "upstream overloaded (529)",
  last_error_at: new Date().toISOString(),
  egress_mode: "direct",
  subscription_plan: "claude_max",
  quota_windows: {
    five_hour: { utilization: 0.93, resets_at: null, observed_at: new Date().toISOString() },
    seven_day: { utilization: 0.4, resets_at: null, observed_at: new Date().toISOString() },
  },
  scheduling_config: { concurrency: 3, messages_rpm: 60, priority: 10, weight: 100 },
  revision: 7,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

it("renders meter tone thresholds", () => {
  const { container, rerender } = render(<Meter label="5h" value={0.5} />);
  expect(container.querySelector(".meter-teal")).not.toBeNull();
  rerender(<Meter label="5h" value={0.75} />);
  expect(container.querySelector(".meter-amber")).not.toBeNull();
  rerender(<Meter label="5h" value={0.95} />);
  expect(container.querySelector(".meter-coral")).not.toBeNull();
});

it("formats a cooldown countdown in mm:ss below one hour", () => {
  expect(formatCountdown(125, "en-US")).toBe("2m 05s");
});

it("renders account cards with status, quota meters and today usage", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith("/admin/v1/credentials")) {
      return new Response(JSON.stringify({ data: [credentialRow] }), { status: 200 });
    }
    if (url.endsWith("/admin/v1/usage/today-by-credential")) {
      return new Response(JSON.stringify({ data: [{ credential_id: credentialRow.id, request_count: 12, input_tokens: 100, output_tokens: 200, estimated_amount: "0.01" }] }), { status: 200 });
    }
    return new Response(JSON.stringify({ data: [] }), { status: 200 });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<I18nProvider initialLocale="en-US"><FeedbackProvider><QueryClientProvider client={client}><AccountsPage principal={principal} /></QueryClientProvider></FeedbackProvider></I18nProvider>);
  expect(await screen.findByText("claude_max")).toBeInTheDocument();
  expect(screen.getAllByText("Cooling down").length).toBeGreaterThan(0);
  expect(screen.getAllByText("93%").length).toBeGreaterThan(0);
  expect(screen.getAllByText("12").length).toBeGreaterThan(0);
});

it("opens the unified add-account wizard with both platforms", async () => {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify({ data: [] }), { status: 200 }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const user = userEvent.setup();
  render(<I18nProvider initialLocale="en-US"><FeedbackProvider><QueryClientProvider client={client}><AccountsPage principal={principal} /></QueryClientProvider></FeedbackProvider></I18nProvider>);
  await user.click(await screen.findByRole("button", { name: "Add account" }));
  expect(await screen.findByText("Choose the account type to add")).toBeInTheDocument();
  // 尚无分组时给出先建分组的引导
  expect(screen.getByText("No Anthropic credential group yet - create one before enrolling.")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: /OpenAI account/ }));
  expect(await screen.findByLabelText("API Key")).toBeInTheDocument();
});
