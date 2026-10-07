import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, renderHook, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Principal } from "../api";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";
import { RowActionDef, RowActionsCell } from "../row-actions";
import { useResourceRowActions } from "../resource-actions";

const principal: Principal = {
  id: "00000000-0000-7000-8000-000000000001",
  role: "platform_admin",
  session_id: "00000000-0000-7000-8000-0000000000aa",
  csrf_token: "csrf",
  mfa_verified: true,
  password_change_required: false,
};

type Row = Record<string, unknown>;

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return <I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}>{children}</QueryClientProvider></FeedbackProvider></I18nProvider>;
}

function actionsFor(path: string): RowActionDef<Row>[] {
  const { result } = renderHook(() => useResourceRowActions(path, principal), { wrapper });
  const actions = result.current.rowActions;
  expect(actions).toBeDefined();
  return actions as RowActionDef<Row>[];
}

function renderCell(row: Row, actions: RowActionDef<Row>[]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><RowActionsCell row={row} actions={actions} /></QueryClientProvider></FeedbackProvider></I18nProvider>);
}

function okResponse() {
  return new Response(JSON.stringify({ data: {}, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
}

describe("resource row action registries", () => {
  it("users: disable shows only for an active key_owner and posts with If-Match", async () => {
    const actions = actionsFor("/users");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(okResponse());
    const activeOwner = { id: "u-1", username: "dev01", role: "key_owner", status: "active", revision: 2 };
    renderCell(activeOwner, actions);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "禁用" }));
    await user.click(screen.getByRole("button", { name: "确认" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe("/admin/v1/users/u-1:disable");
    expect(new Headers(init?.headers).get("If-Match")).toBe('"rev-2"');
  });

  it("users: allows lifecycle management for another platform_admin", () => {
    const actions = actionsFor("/users");
    renderCell({ id: "u-2", username: "admin", role: "platform_admin", status: "active", revision: 1 }, actions);
    expect(screen.getByRole("button", { name: "禁用" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "编辑" })).toBeInTheDocument();
  });

  it("users: keeps destructive lifecycle actions off the current principal", () => {
    const actions = actionsFor("/users");
    renderCell({ id: principal.id, username: "admin", role: "platform_admin", status: "active", revision: 1 }, actions);
    expect(screen.queryByRole("button", { name: "禁用" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "编辑" })).toBeInTheDocument();
  });

  it("credentials: cooldown, refresh, revoke and archive actions follow the lifecycle state", async () => {
    const actions = actionsFor("/credentials");
    renderCell({ id: "c-1", lifecycle_state: "active", scheduling_state: "cooldown", revision: 2 }, actions);
    expect(screen.getByRole("button", { name: "禁用" })).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "更多操作" }));
    expect(screen.getByRole("menuitem", { name: "解除冷却" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "刷新订阅信息" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "吊销" })).toBeInTheDocument();
    cleanup();

    renderCell({ id: "c-1", lifecycle_state: "revoked", scheduling_state: "blocked", revision: 3 }, actions);
    expect(screen.getByRole("button", { name: "归档" })).toBeInTheDocument();
  });

  it("jobs: cancel uses lease_generation + 1 as the optimistic lock", async () => {
    const actions = actionsFor("/operations");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(okResponse());
    renderCell({ id: "j-1", kind: "key_rotation", state: "scheduled", lease_generation: 4 }, actions);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "取消任务" }));
    await user.type(screen.getByLabelText("操作原因"), "任务积压");
    await user.click(screen.getByRole("button", { name: "确认" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe("/admin/v1/operations/jobs/j-1:cancel");
    expect(new Headers(init?.headers).get("If-Match")).toBe('"rev-5"');
    expect(JSON.parse(String(init?.body))).toEqual({ reason: "任务积压", expected_revision: 5 });
  });

  it("jobs: running jobs cannot be cancelled", () => {
    const actions = actionsFor("/operations");
    renderCell({ id: "j-2", kind: "key_rotation", state: "running", lease_generation: 4 }, actions);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("sessions: current session offers no revoke, others issue a DELETE", async () => {
    const actions = actionsFor("/account");
    renderCell({ id: "s-current", current: true }, actions);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    cleanup();

    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    renderCell({ id: "s-old", current: false, user_agent_summary: "Chrome" }, actions);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "撤销会话" }));
    await user.click(screen.getByRole("button", { name: "确认" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe("/admin/v1/auth/sessions/s-old");
    expect(init?.method).toBe("DELETE");
  });

  it("approvals: approve collects reason + password, then step-up and POST", async () => {
    const actions = actionsFor("/security");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path.endsWith("/auth/step-up")) return new Response(JSON.stringify({ data: { id: "grant-9", csrf_token: "rotated" }, meta: {} }), { status: 201, headers: { "content-type": "application/json" } });
      return okResponse();
    });
    renderCell({ id: "a-1", kind: "credential_export", state: "pending", requested_by: "someone-else", revision: 1 }, actions);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "批准" }));
    await user.type(screen.getByLabelText("当前密码"), "password-value");
    await user.type(screen.getByLabelText("操作原因"), "风险可控");
    await user.click(screen.getByRole("button", { name: "确认" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(String(fetchMock.mock.calls[0][0])).toBe("/admin/v1/auth/step-up");
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({ purpose: "approval_decision", current_password: "password-value" });
    const [path, init] = fetchMock.mock.calls[1];
    expect(path).toBe("/admin/v1/approval-cases/a-1:approve");
    expect(JSON.parse(String(init?.body))).toEqual({ reason: "风险可控", step_up_grant_id: "grant-9" });
  });

  it("approvals: requester sees withdraw instead of approve/reject", async () => {
    const actions = actionsFor("/security");
    renderCell({ id: "a-2", kind: "credential_export", state: "pending", requested_by: principal.id, revision: 1 }, actions);
    const user = userEvent.setup();
    expect(screen.queryByRole("button", { name: "批准" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "更多操作" }));
    expect(screen.getByRole("menuitem", { name: "撤销" })).toBeInTheDocument();
  });

  it("alerts: acknowledge only for open alerts, resolve for open/acknowledged/silenced", () => {
    const actions = actionsFor("/alerts");
    renderCell({ id: "al-1", summary: "证书将过期", state: "acknowledged", revision: 2 }, actions);
    expect(screen.queryByRole("button", { name: "知悉" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "解决" })).toBeInTheDocument();
  });
});
