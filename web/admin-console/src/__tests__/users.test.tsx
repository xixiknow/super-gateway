import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UsersTable } from "../Users";
import { I18nProvider } from "../i18n";

const users = [
  { id: "u-1", username: "admin", display_name: "平台管理员", email: "admin@example.com", role: "platform_admin", status: "active", last_used_at: "2026-08-26T12:00:00Z", max_concurrency: 20, rpm: 300, balance_amount: null, lifetime_spend_amount: "5", revision: 1 },
  { id: "u-2", username: "dev", display_name: "研发用户", email: "dev@example.com", role: "key_owner", status: "disabled", last_used_at: null, max_concurrency: 5, rpm: 60, balance_amount: "95.5", lifetime_spend_amount: "4.5", revision: 2 },
];

afterEach(cleanup);

describe("user management table", () => {
  it("shows operational columns, filters immediately, and refreshes", async () => {
    const onRefresh = vi.fn();
    const user = userEvent.setup();
    render(<I18nProvider initialLocale="zh-CN"><UsersTable loading={false} items={users} title="用户管理" onRefresh={onRefresh} /></I18nProvider>);

    expect(screen.getByRole("columnheader", { name: "最后使用时间" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "密钥并发上限" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "余额" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "密钥 RPM 上限" })).toBeInTheDocument();
    expect(screen.getByText("平台管理员", { selector: "strong" })).toBeInTheDocument();
    expect(screen.getByText("研发用户", { selector: "strong" })).toBeInTheDocument();

    await user.click(screen.getByRole("combobox", { name: "状态" }));
    await user.click(screen.getByRole("option", { name: "已禁用" }));
    expect(screen.queryByText("平台管理员", { selector: "strong" })).not.toBeInTheDocument();
    expect(screen.getByText("研发用户", { selector: "strong" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "刷新" }));
    expect(onRefresh).toHaveBeenCalledTimes(1);
  });
});
