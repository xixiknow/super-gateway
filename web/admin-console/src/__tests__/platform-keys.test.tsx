import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PlatformKeysTable } from "../PlatformKeys";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";

const key = {
  id: "01a03d1f-fa97-7893-9237-4873f24493e9",
  name: "开发环境密钥",
  group_id: "00000000-0000-0000-0000-000000000022",
  display_prefix: "sgw_v1_hFPk0Vq3…",
  group_name: "研发分组",
  status: "active",
  expires_at: null,
  revision: 3,
  max_concurrency: 5,
  messages_rpm: 60,
  spend_limit_amount: "100",
  today_spend_amount: "1.25",
  thirty_day_spend_amount: "12.5",
  lifetime_spend_amount: "42.5",
  last_used_at: "2026-08-26T12:00:00Z",
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function renderTable() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><PlatformKeysTable loading={false} items={[key]} title="平台密钥" onRefresh={vi.fn()} /></QueryClientProvider></FeedbackProvider></I18nProvider>);
}

async function openMenu(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "更多操作" }));
}

describe("platform key management", () => {
  it("shows the group name, exposes edit/disable as icon buttons, and folds the rest into the overflow menu", async () => {
    const user = userEvent.setup();
    renderTable();

    expect(screen.getByText("研发分组")).toBeInTheDocument();
    expect(screen.queryByText(key.id)).not.toBeInTheDocument();
    expect(screen.queryByText(key.display_prefix)).not.toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "ID" })).not.toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "今日消费" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "近 30 天消费" })).toBeInTheDocument();
    // 外露的图标按钮(文字经 aria-label / 悬浮提示展示)
    for (const action of ["编辑", "禁用"]) {
      expect(screen.getByRole("button", { name: action })).toBeInTheDocument();
    }
    // 其余操作收进 ⋯ 菜单
    await openMenu(user);
    for (const action of ["显示密钥", "客户端配置", "配置历史", "审计记录", "吊销"]) {
      expect(screen.getByRole("menuitem", { name: action })).toBeInTheDocument();
    }
  });

  it("submits a localized disable action with revision protection", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ data: { ...key, status: "disabled", revision: 4 }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } }));
    const user = userEvent.setup();
    renderTable();

    await user.click(screen.getByRole("button", { name: "禁用" }));
    const dialog = screen.getByRole("dialog", { name: "禁用平台密钥" });
    await user.type(within(dialog).getByLabelText("操作原因"), "临时停止开发访问");
    await user.click(within(dialog).getByRole("button", { name: "确认禁用" }));

    expect(await screen.findByText("操作已完成")).toBeInTheDocument();
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe(`/admin/v1/platform-keys/${key.id}:disable`);
    expect(new Headers(init?.headers).get("If-Match")).toBe('"rev-3"');
    expect(JSON.parse(String(init?.body))).toEqual({ reason: "临时停止开发访问", expected_revision: 3 });
  });

  it("uses password-only step-up before revealing a key", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = String(input);
      if (path.endsWith("/auth/step-up")) return new Response(JSON.stringify({ data: { id: "grant-1", csrf_token: "rotated-csrf" }, meta: {} }), { status: 201, headers: { "content-type": "application/json" } });
      if (path.endsWith(":reveal")) return new Response(JSON.stringify({ data: { secret: "sgw_v1_secret", expires_in_seconds: 60 }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ error: { message: "unexpected" } }), { status: 500, headers: { "content-type": "application/json" } });
    });
    const user = userEvent.setup();
    renderTable();

    await openMenu(user);
    await user.click(screen.getByRole("menuitem", { name: "显示密钥" }));
    const dialog = screen.getByRole("dialog", { name: "显示完整密钥" });
    await user.type(within(dialog).getByLabelText("当前密码"), "password-value");
    await user.type(within(dialog).getByLabelText("操作原因"), "配置本地客户端");
    await user.click(within(dialog).getByRole("button", { name: "验证并显示" }));

    expect(await screen.findByText("sgw_v1_secret")).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    const stepUp = JSON.parse(String(fetchMock.mock.calls[0][1]?.body));
    expect(stepUp).toEqual({ purpose: "key_secret_reveal", current_password: "password-value" });
    expect(stepUp).not.toHaveProperty("totp_code");
    expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get("If-Match")).toBe('"rev-3"');
  });
});
