import { FormEvent, ReactNode, createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { MessageKey, useI18n } from "./i18n";

/* ============================================================
   Toast 轻提示：右下角堆叠，进度条暗示剩余时间，悬停暂停
   ============================================================ */

const MAX_TOASTS = 4;
const SUCCESS_DURATION = 3_500;
const ERROR_DURATION = 5_000;

type ToastTone = "ok" | "err";

interface ToastItem {
  id: number;
  tone: ToastTone;
  text: string;
  duration: number;
}

interface ToastApi {
  success(text: string): void;
  error(text: string): void;
}

const ToastContext = createContext<ToastApi | null>(null);

export function useToast(): ToastApi {
  const value = useContext(ToastContext);
  if (!value) throw new Error("FeedbackProvider is missing");
  return value;
}

let nextToastId = 1;
let nextConfirmId = 1;

function ToastView({ item, onDismiss }: { item: ToastItem; onDismiss(id: number): void }) {
  const { t } = useI18n();
  const remainingRef = useRef(item.duration);
  const startedAtRef = useRef(Date.now());
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    timerRef.current = window.setTimeout(() => onDismiss(item.id), remainingRef.current);
    return () => { if (timerRef.current !== null) window.clearTimeout(timerRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [item.id]);

  function pause() {
    if (timerRef.current !== null) window.clearTimeout(timerRef.current);
    timerRef.current = null;
    remainingRef.current = Math.max(0, remainingRef.current - (Date.now() - startedAtRef.current));
  }
  function resume() {
    if (timerRef.current !== null || remainingRef.current <= 0) return;
    startedAtRef.current = Date.now();
    timerRef.current = window.setTimeout(() => onDismiss(item.id), remainingRef.current);
  }

  return (
    <div
      className={`toast show ${item.tone}`}
      role={item.tone === "err" ? "alert" : "status"}
      onMouseEnter={pause}
      onMouseLeave={resume}
    >
      <svg className="icon" aria-hidden="true"><use href={item.tone === "err" ? "#i-error" : "#i-success"} /></svg>
      <span className="toast-text">{item.text}</span>
      <button type="button" className="toast-close" aria-label={t("common.close")} onClick={() => onDismiss(item.id)}>×</button>
      <span className="toast-bar" style={{ animationDuration: `${item.duration}ms` }} aria-hidden="true" />
    </div>
  );
}

/* ============================================================
   Confirm 确认框：Promise 化，可选操作原因输入
   ============================================================ */

export interface ConfirmOptions {
  titleKey: MessageKey;
  bodyKey?: MessageKey;
  bodyVars?: Record<string, string | number>;
  confirmKey?: MessageKey;
  danger?: boolean;
  withReason?: boolean;
  /** 要求输入当前密码(用于 step-up 高风险操作,如审批批准/拒绝) */
  withPassword?: boolean;
  /** 要求输入已批准的审批单 ID(高风险变更的双人审批联动) */
  withApprovalCase?: boolean;
}

export type ConfirmResult = { ok: true; reason: string; password: string; approvalCaseId: string } | { ok: false };

interface ConfirmRequest extends ConfirmOptions {
  id: number;
  resolve(result: ConfirmResult): void;
}

const ConfirmContext = createContext<((options: ConfirmOptions) => Promise<ConfirmResult>) | null>(null);

export function useConfirm(): (options: ConfirmOptions) => Promise<ConfirmResult> {
  const value = useContext(ConfirmContext);
  if (!value) throw new Error("FeedbackProvider is missing");
  return value;
}

function ConfirmDialog({ request, onResolve }: { request: ConfirmRequest; onResolve(result: ConfirmResult): void }) {
  const { t } = useI18n();
  const titleId = useId();
  const [passwordError, setPasswordError] = useState(false);
  const [approvalError, setApprovalError] = useState(false);

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") onResolve({ ok: false }); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [onResolve]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const reason = request.withReason ? String(form.get("reason") ?? "").trim() : "";
    const password = request.withPassword ? String(form.get("current_password") ?? "") : "";
    const approvalCaseId = request.withApprovalCase ? String(form.get("approval_case_id") ?? "").trim() : "";
    if (request.withPassword && !password) { setPasswordError(true); return; }
    if (request.withApprovalCase && !approvalCaseId) { setApprovalError(true); return; }
    onResolve({ ok: true, reason, password, approvalCaseId });
  }

  return createPortal(
    <div className="overlay show" onMouseDown={(event) => { if (event.target === event.currentTarget) onResolve({ ok: false }); }}>
      <section className="modal confirm-modal" role="alertdialog" aria-modal="true" aria-labelledby={titleId}>
        <form onSubmit={submit}>
          <div className="modal-body confirm-body">
            <span className={`confirm-icon ${request.danger ? "danger" : ""}`} aria-hidden="true">
              <svg className="icon"><use href={request.danger ? "#i-alert" : "#i-info"} /></svg>
            </span>
            <div className="confirm-content">
              <h3 id={titleId}>{t(request.titleKey)}</h3>
              {request.bodyKey && <p className="confirm-text">{t(request.bodyKey, request.bodyVars)}</p>}
              {request.withPassword && (
                <div className="field confirm-reason">
                  <label htmlFor={`${titleId}-password`}>{t("confirm.currentPassword")}</label>
                  <input
                    id={`${titleId}-password`}
                    name="current_password"
                    type="password"
                    className="inp"
                    autoComplete="current-password"
                    onChange={() => setPasswordError(false)}
                  />
                  {passwordError && <small className="field-error" role="alert">{t("confirm.passwordRequired")}</small>}
                </div>
              )}
              {request.withApprovalCase && (
                <div className="field confirm-reason">
                  <label htmlFor={`${titleId}-approval`}>{t("confirm.approvalCase")}<span className="hint">{t("confirm.approvalCaseHint")}</span></label>
                  <input
                    id={`${titleId}-approval`}
                    name="approval_case_id"
                    className="inp mono"
                    autoComplete="off"
                    placeholder="00000000-0000-0000-0000-000000000000"
                    onChange={() => setApprovalError(false)}
                  />
                  {approvalError && <small className="field-error" role="alert">{t("confirm.approvalCaseRequired")}</small>}
                </div>
              )}
              {request.withReason && (
                <div className="field confirm-reason">
                  <label htmlFor={`${titleId}-reason`}>{t("rowaction.reason")}</label>
                  <textarea
                    id={`${titleId}-reason`}
                    name="reason"
                    className="inp"
                    rows={2}
                    maxLength={2048}
                  />
                </div>
              )}
            </div>
          </div>
          <div className="modal-foot">
            <button type="button" className="btn btn-ghost" autoFocus onClick={() => onResolve({ ok: false })}>{t("common.cancel")}</button>
            <button type="submit" className={`btn ${request.danger ? "btn-danger" : "btn-primary"}`}>{t(request.confirmKey ?? "common.confirm")}</button>
          </div>
        </form>
      </section>
    </div>,
    document.body,
  );
}

/* ============================================================
   Provider：同时提供 toast 与 confirm
   ============================================================ */

export function FeedbackProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [confirmQueue, setConfirmQueue] = useState<ConfirmRequest[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((item) => item.id !== id));
  }, []);

  const push = useCallback((tone: ToastTone, text: string) => {
    const item: ToastItem = { id: nextToastId++, tone, text, duration: tone === "err" ? ERROR_DURATION : SUCCESS_DURATION };
    setToasts((current) => [...current.slice(-(MAX_TOASTS - 1)), item]);
  }, []);

  const toastApi = useMemo<ToastApi>(() => ({
    success: (text) => push("ok", text),
    error: (text) => push("err", text),
  }), [push]);

  const confirm = useCallback((options: ConfirmOptions) => new Promise<ConfirmResult>((resolve) => {
    setConfirmQueue((current) => [...current, { ...options, id: nextConfirmId++, resolve }]);
  }), []);

  const activeConfirm = confirmQueue[0];
  const resolveConfirm = useCallback((result: ConfirmResult) => {
    setConfirmQueue((current) => {
      const [head, ...rest] = current;
      head?.resolve(result);
      return rest;
    });
  }, []);

  return (
    <ToastContext.Provider value={toastApi}>
      <ConfirmContext.Provider value={confirm}>
        {children}
        {toasts.length > 0 && createPortal(
          <div className="toast-stack">
            {toasts.map((item) => <ToastView key={item.id} item={item} onDismiss={dismiss} />)}
          </div>,
          document.body,
        )}
        {activeConfirm && <ConfirmDialog key={activeConfirm.id} request={activeConfirm} onResolve={resolveConfirm} />}
      </ConfirmContext.Provider>
    </ToastContext.Provider>
  );
}
