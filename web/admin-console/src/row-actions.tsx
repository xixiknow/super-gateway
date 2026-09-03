import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "./api";
import { useConfirm, useToast } from "./feedback";
import { Locale, MessageKey, useI18n } from "./i18n";

/* ============================================================
   行级操作框架:图标按钮(≤2 个外露)+ ⋯ 菜单,确认 → 执行 → toast
   ============================================================ */

export interface RowActionConfirm {
  titleKey: MessageKey;
  bodyKey?: MessageKey;
  confirmKey?: MessageKey;
  withReason?: boolean;
  /** 同时收集当前密码(审批批准/拒绝等需要 step-up 授权的操作) */
  withPassword?: boolean;
}

export interface RowActionDef<Row = Record<string, unknown>> {
  key: string;
  labelKey: MessageKey;
  icon: string;
  danger?: boolean;
  primary?: boolean;
  /** false 表示该操作不依赖乐观锁(如纯 DELETE),行数据无需 revision 字段 */
  requiresRevision?: boolean;
  when?(row: Row): boolean;
  confirm?: RowActionConfirm;
  run?(row: Row, reason: string, password?: string): Promise<unknown>;
  invalidate?: string;
  nameOf?(row: Row): string;
  /** 完全自定义的点击行为(如打开专属编辑/详情弹窗),设置后跳过 confirm+run 流程 */
  custom?(row: Row): void;
}

/** 生命周期动作:POST {endpoint}/{id}:{suffix},携带 If-Match 乐观锁与操作原因 */
export function postLifecycle(endpoint: string, row: Record<string, unknown>, suffix: string, reason: string): Promise<unknown> {
  const id = String(row.id);
  const revision = row.revision;
  return api(`${endpoint}/${encodeURIComponent(id)}:${suffix}`, {
    method: "POST",
    headers: typeof revision === "number" ? { "If-Match": `"rev-${revision}"` } : undefined,
    body: JSON.stringify({ reason, ...(typeof revision === "number" ? { expected_revision: revision } : {}) }),
  });
}

/** 统一的行操作错误文案(401/403/409/412 有专门解释) */
export function rowActionError(error: unknown, locale: Locale): string {
  if (error instanceof ApiError) {
    if (locale === "zh-CN") {
      if (error.status === 401) return "当前密码不正确，请重新输入。";
      if (error.status === 412) return "数据已发生变化，请关闭窗口并刷新后重试。";
      if (error.status === 409) return "当前状态不允许执行该操作。";
      if (error.status === 403) return "当前账号没有执行该操作的权限。";
      return `请求失败（状态码 ${error.status}）：${error.message}`;
    }
    return `Request failed (${error.status}): ${error.message}`;
  }
  return error instanceof Error ? error.message : locale === "zh-CN" ? "操作未完成，请稍后重试。" : "The operation did not complete. Try again.";
}

export function RowActionsCell<Row extends Record<string, unknown>>({ row, actions }: { row: Row; actions: RowActionDef<Row>[] }) {
  const { locale, t } = useI18n();
  const toast = useToast();
  const confirm = useConfirm();
  const queryClient = useQueryClient();
  const [menuOpen, setMenuOpen] = useState(false);
  const [menuPos, setMenuPos] = useState<{ top: number; right: number } | null>(null);
  const [pending, setPending] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);

  const hasId = typeof row.id === "string" && row.id.length > 0;
  const hasRevision = typeof row.revision === "number";
  const visible = actions.filter((def) => hasId && (def.requiresRevision === false || hasRevision || def.custom !== undefined) && (!def.when || def.when(row)));
  const exposed = visible.filter((def) => def.primary).slice(0, 2);
  const overflow = visible.filter((def) => !exposed.includes(def));

  // 菜单经 portal 固定定位,避免被表格滚动容器裁剪;贴近底部时向上展开
  function anchorMenu() {
    const rect = menuButtonRef.current?.getBoundingClientRect();
    if (!rect) return false;
    const estimatedHeight = overflow.length * 36 + 12;
    const openUp = rect.bottom + 6 + estimatedHeight > window.innerHeight && rect.top - 6 - estimatedHeight > 0;
    setMenuPos({ top: openUp ? Math.max(8, rect.top - 6 - estimatedHeight) : rect.bottom + 6, right: Math.max(8, window.innerWidth - rect.right) });
    return true;
  }

  function toggleMenu() {
    if (menuOpen) {
      setMenuOpen(false);
      return;
    }
    anchorMenu();
    setMenuOpen(true);
  }

  useEffect(() => {
    if (!menuOpen) return;
    const closeOnOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      if (rootRef.current?.contains(target) || menuRef.current?.contains(target)) return;
      setMenuOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setMenuOpen(false);
        menuButtonRef.current?.focus();
      }
    };
    // 滚动/缩放时重新锚定而不是直接关闭:点击 ⋯ 后焦点滚动(scroll-into-view)属于误关的高发场景
    const reanchor = () => { anchorMenu(); };
    document.addEventListener("mousedown", closeOnOutside);
    document.addEventListener("keydown", closeOnEscape);
    window.addEventListener("scroll", reanchor, true);
    window.addEventListener("resize", reanchor);
    return () => {
      document.removeEventListener("mousedown", closeOnOutside);
      document.removeEventListener("keydown", closeOnEscape);
      window.removeEventListener("scroll", reanchor, true);
      window.removeEventListener("resize", reanchor);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [menuOpen]);

  async function execute(def: RowActionDef<Row>) {
    setMenuOpen(false);
    if (def.custom) {
      def.custom(row);
      return;
    }
    if (!def.confirm || !def.run) return;
    const name = def.nameOf?.(row) ?? String(row.name ?? row.username ?? row.display_name ?? row.id ?? "");
    const result = await confirm({
      titleKey: def.confirm.titleKey,
      bodyKey: def.confirm.bodyKey,
      bodyVars: { name },
      confirmKey: def.confirm.confirmKey,
      danger: def.danger,
      withReason: def.confirm.withReason,
      withPassword: def.confirm.withPassword,
    });
    if (!result.ok) return;
    setPending(true);
    try {
      await def.run(row, result.reason, result.password);
      toast.success(t("action.success"));
      if (def.invalidate) await queryClient.invalidateQueries({ queryKey: [def.invalidate] });
    } catch (error) {
      toast.error(rowActionError(error, locale));
    } finally {
      setPending(false);
    }
  }

  if (visible.length === 0) return null;
  return (
    <div className="row-actions" ref={rootRef}>
      {exposed.map((def) => (
        <button key={def.key} type="button" className={`ibtn outline sm${def.danger ? " danger" : ""}`} data-tip={t(def.labelKey)} aria-label={t(def.labelKey)} disabled={pending} onClick={() => void execute(def)}>
          <svg className="icon" aria-hidden="true"><use href={`#i-${def.icon}`} /></svg>
        </button>
      ))}
      {overflow.length > 0 && (
        <div className={`dropdown${menuOpen ? " open" : ""}`}>
          <button ref={menuButtonRef} type="button" className="ibtn outline sm" data-tip={t("rowaction.more")} aria-label={t("rowaction.more")} aria-haspopup="menu" aria-expanded={menuOpen} disabled={pending} onClick={toggleMenu}>
            <svg className="icon" aria-hidden="true"><use href="#i-more-h" /></svg>
          </button>
          {menuOpen && menuPos && createPortal(
            <div ref={menuRef} className="dd-menu row-action-menu" role="menu" style={{ position: "fixed", top: menuPos.top, right: menuPos.right, left: "auto", display: "block" }}>
              {overflow.map((def) => (
                <button key={def.key} type="button" role="menuitem" className={`dd-item${def.danger ? " danger" : ""}`} disabled={pending} onClick={() => void execute(def)}>
                  <svg className="icon" aria-hidden="true"><use href={`#i-${def.icon}`} /></svg>
                  {t(def.labelKey)}
                </button>
              ))}
            </div>,
            document.body,
          )}
        </div>
      )}
    </div>
  );
}
