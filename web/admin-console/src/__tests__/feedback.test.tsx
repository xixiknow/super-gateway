import { cleanup, fireEvent, render, screen, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FeedbackProvider, useConfirm, useToast } from "../feedback";
import { I18nProvider } from "../i18n";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function ToastTrigger({ texts }: { texts: string[] }) {
  const toast = useToast();
  return <button type="button" onClick={() => texts.forEach((text) => toast.success(text))}>fire</button>;
}

function ConfirmTrigger({ withReason = false, danger = false, onResult }: { withReason?: boolean; danger?: boolean; onResult(ok: boolean, reason: string): void }) {
  const confirm = useConfirm();
  return <button type="button" onClick={() => void confirm({ titleKey: "key.action.disable.title", bodyKey: "key.revoke.warningBody", danger, withReason }).then((result) => onResult(result.ok, result.ok ? result.reason : ""))}>ask</button>;
}

function renderFeedback(children: React.ReactNode) {
  return render(<I18nProvider initialLocale="zh-CN"><FeedbackProvider>{children}</FeedbackProvider></I18nProvider>);
}

describe("toast", () => {
  it("shows a toast in the bottom-right stack and dismisses it after the duration", () => {
    vi.useFakeTimers();
    renderFeedback(<ToastTrigger texts={["操作成功"]} />);
    fireEvent.click(screen.getByRole("button", { name: "fire" }));

    const toast = screen.getByRole("status");
    expect(toast).toHaveTextContent("操作成功");
    expect(toast.parentElement).toHaveClass("toast-stack");
    expect(toast.querySelector(".toast-bar")).toHaveStyle({ animationDuration: "3500ms" });

    act(() => vi.advanceTimersByTime(3_500));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("uses role=alert and a longer duration for errors", () => {
    vi.useFakeTimers();
    function ErrorTrigger() {
      const toast = useToast();
      return <button type="button" onClick={() => toast.error("操作失败")}>fire</button>;
    }
    renderFeedback(<ErrorTrigger />);
    fireEvent.click(screen.getByRole("button", { name: "fire" }));

    expect(screen.getByRole("alert")).toHaveTextContent("操作失败");
    act(() => vi.advanceTimersByTime(3_500));
    expect(screen.getByRole("alert")).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(1_500));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("dismisses immediately via the close button", async () => {
    renderFeedback(<ToastTrigger texts={["操作成功"]} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "fire" }));
    expect(screen.getByRole("status")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "关闭" }));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("drops the oldest toast beyond the stack limit", async () => {
    renderFeedback(<ToastTrigger texts={["第一条", "第二条", "第三条", "第四条", "第五条"]} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "fire" }));

    expect(screen.getAllByRole("status")).toHaveLength(4);
    expect(screen.queryByText("第一条")).not.toBeInTheDocument();
    expect(screen.getByText("第五条")).toBeInTheDocument();
  });
});

describe("confirm", () => {
  it("resolves ok=true with the reason when confirmed", async () => {
    const onResult = vi.fn();
    renderFeedback(<ConfirmTrigger withReason onResult={onResult} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "ask" }));

    const dialog = screen.getByRole("alertdialog", { name: "禁用平台密钥" });
    await user.type(screen.getByLabelText("操作原因"), "例行维护");
    await user.click(screen.getByRole("button", { name: "确认" }));

    expect(onResult).toHaveBeenCalledWith(true, "例行维护");
    expect(dialog).not.toBeInTheDocument();
  });

  it("treats the reason as an optional note and confirms with an empty reason", async () => {
    const onResult = vi.fn();
    renderFeedback(<ConfirmTrigger withReason onResult={onResult} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "ask" }));
    await user.click(screen.getByRole("button", { name: "确认" }));

    expect(onResult).toHaveBeenCalledWith(true, "");
  });

  it("resolves ok=false via cancel, Escape, and the backdrop", async () => {
    const onResult = vi.fn();
    renderFeedback(<ConfirmTrigger onResult={onResult} />);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "ask" }));
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(onResult).toHaveBeenLastCalledWith(false, "");

    await user.click(screen.getByRole("button", { name: "ask" }));
    await user.keyboard("{Escape}");
    expect(onResult).toHaveBeenLastCalledWith(false, "");

    await user.click(screen.getByRole("button", { name: "ask" }));
    const overlay = screen.getByRole("alertdialog").parentElement!;
    await user.click(overlay);
    expect(onResult).toHaveBeenLastCalledWith(false, "");
    expect(onResult).toHaveBeenCalledTimes(3);
  });

  it("focuses the cancel button by default and marks danger actions", async () => {
    renderFeedback(<ConfirmTrigger danger onResult={() => undefined} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "ask" }));

    expect(screen.getByRole("button", { name: "取消" })).toHaveFocus();
    expect(screen.getByRole("button", { name: "确认" })).toHaveClass("btn-danger");
  });
});
