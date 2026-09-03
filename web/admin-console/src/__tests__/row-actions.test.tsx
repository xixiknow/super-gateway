import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FeedbackProvider } from "../feedback";
import { I18nProvider } from "../i18n";
import { RowActionDef, RowActionsCell, postLifecycle } from "../row-actions";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

type Row = Record<string, unknown>;

function okResponse() {
  return new Response(JSON.stringify({ data: { status: "disabled" }, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
}

function renderCell(row: Row, actions: RowActionDef<Row>[]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider><QueryClientProvider client={client}><RowActionsCell row={row} actions={actions} /></QueryClientProvider></FeedbackProvider></I18nProvider>);
}

const disableAction: RowActionDef<Row> = {
  key: "disable", labelKey: "rowaction.disable", icon: "pause", primary: true,
  confirm: { titleKey: "rowaction.confirm.disable.title", bodyKey: "rowaction.confirm.disable.body", withReason: true },
  run: (row, reason) => postLifecycle("/admin/v1/users", row, "disable", reason),
  invalidate: "/admin/v1/users",
};

const row = { id: "user-1", name: "张三", status: "active", revision: 3 };

describe("row actions", () => {
  it("exposes at most two primary actions as icon buttons and puts the rest in the overflow menu", async () => {
    const extra: RowActionDef<Row> = { ...disableAction, key: "archive", labelKey: "rowaction.archive", icon: "package", primary: false };
    const third: RowActionDef<Row> = { ...disableAction, key: "unlock", labelKey: "rowaction.unlock", icon: "unlock", primary: true };
    renderCell(row, [disableAction, third, extra]);
    const user = userEvent.setup();

    expect(screen.getByRole("button", { name: "禁用" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "解锁" })).toBeInTheDocument();
    expect(document.querySelector(".dropdown.open")).toBeNull();
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();

    const moreButton = screen.getByRole("button", { name: "更多操作" });
    vi.spyOn(moreButton, "getBoundingClientRect").mockReturnValue({
      x: 864, y: 400, left: 864, right: 900, top: 400, bottom: 436,
      width: 36, height: 36, toJSON: () => ({}),
    });
    await user.click(moreButton);
    expect(document.querySelector(".dropdown.open")).not.toBeNull();
    expect(screen.getByRole("menuitem", { name: "归档" })).toBeInTheDocument();
    expect(screen.getByRole("menu")).toHaveStyle({
      position: "fixed",
      left: "auto",
      right: `${window.innerWidth - 900}px`,
      top: "442px",
    });
  });

  it("hides actions filtered out by when()", () => {
    const disabledRow = { ...row, status: "disabled" };
    renderCell(disabledRow, [{ ...disableAction, when: (item) => item.status === "active" }]);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("hides mutation actions when the row lacks a revision", () => {
    renderCell({ id: "user-1", name: "张三" }, [disableAction]);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("does not call the API when the confirm dialog is cancelled", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    renderCell(row, [disableAction]);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "禁用" }));
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("sends the lifecycle request with reason and If-Match after confirming, then invalidates and toasts", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(okResponse());
    renderCell(row, [disableAction]);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "禁用" }));
    const dialog = screen.getByRole("alertdialog", { name: "确认禁用" });
    expect(dialog).toHaveTextContent("张三");
    await user.type(screen.getByLabelText("操作原因"), "违规处理");
    await user.click(screen.getByRole("button", { name: "确认" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe("/admin/v1/users/user-1:disable");
    expect(init?.method).toBe("POST");
    expect(new Headers(init?.headers).get("If-Match")).toBe('"rev-3"');
    expect(JSON.parse(String(init?.body))).toEqual({ reason: "违规处理", expected_revision: 3 });
    expect(await screen.findByText("操作成功", { selector: ".toast-text" })).toBeInTheDocument();
  });

  it("reports failures as an error toast", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ error: { code: "conflict", message: "conflict" } }), { status: 409, headers: { "content-type": "application/json" } }));
    renderCell(row, [disableAction]);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "禁用" }));
    await user.type(screen.getByLabelText("操作原因"), "违规处理");
    await user.click(screen.getByRole("button", { name: "确认" }));

    expect(await screen.findByText("当前状态不允许执行该操作。", { selector: ".toast-text" })).toBeInTheDocument();
  });

  it("closes the overflow menu on Escape and on outside click", async () => {
    renderCell(row, [disableAction, { ...disableAction, key: "archive", labelKey: "rowaction.archive", icon: "package", primary: false }]);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "更多操作" }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(document.querySelector(".dropdown.open")).toBeNull();

    await user.click(screen.getByRole("button", { name: "更多操作" }));
    expect(document.querySelector(".dropdown.open")).not.toBeNull();
    await user.click(document.body);
    expect(document.querySelector(".dropdown.open")).toBeNull();
  });
});
