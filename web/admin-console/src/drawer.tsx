import { ReactNode, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useI18n } from "./i18n";

/* ============================================================
   通用右侧抽屉外壳,支持推移式级联:
   - 上层抽屉打开时,下层抽屉向左推移保持可见;上层关闭后回归原位
   - 焦点陷阱与 Esc 仅对栈顶抽屉生效,确认框(alertdialog)优先
   - body 滚动锁引用计数,最后一层关闭时恢复
   - 关闭后焦点自动还原到打开时的触发元素
   ============================================================ */

interface StackEntry {
  token: symbol;
  el: HTMLElement | null;
}

const drawerStack: StackEntry[] = [];
const stackListeners = new Set<() => void>();
let originalBodyOverflow = "";

function notifyStackChange() {
  for (const listener of stackListeners) listener();
}

// 抽屉宽度含 vw,窗口尺寸变化时重算各层推开位移
if (typeof window !== "undefined") window.addEventListener("resize", notifyStackChange);

interface DrawerProps {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  /** 级联第二层:更窄宽度 + 更浅遮罩,露出下层左缘 */
  cascade?: boolean;
  className?: string;
  onRequestClose(): void;
  children: ReactNode;
  foot?: ReactNode;
}

export function Drawer({ eyebrow, title, subtitle, cascade = false, className = "", onRequestClose, children, foot }: DrawerProps) {
  const { t } = useI18n();
  const titleId = useId();
  const drawerRef = useRef<HTMLElement | null>(null);
  const closeRef = useRef<HTMLButtonElement | null>(null);
  const onCloseRef = useRef(onRequestClose);
  // 上方有其它抽屉时自己被向左推开
  const [pushed, setPushed] = useState(false);
  useEffect(() => { onCloseRef.current = onRequestClose; }, [onRequestClose]);
  useEffect(() => {
    const token = Symbol("drawer");
    drawerStack.push({ token, el: drawerRef.current });
    if (drawerStack.length === 1) originalBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    // 自己之上每多一层抽屉,就被向左推开:位移 = 上层宽度之和 + 每层 12px 缝隙
    const updatePushed = () => {
      const index = drawerStack.findIndex((entry) => entry.token === token);
      if (index < 0) return;
      let offset = 0;
      for (let i = index + 1; i < drawerStack.length; i++) {
        offset += (drawerStack[i].el?.getBoundingClientRect().width ?? 0) + 12;
      }
      setPushed(offset > 0);
      drawerRef.current?.style.setProperty("--push-offset", `${offset}px`);
    };
    stackListeners.add(updatePushed);
    notifyStackChange();
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeRef.current?.focus();
    function handleKeyDown(event: KeyboardEvent) {
      if (drawerStack[drawerStack.length - 1]?.token !== token) return;
      if (document.querySelector('[role="alertdialog"]')) return;
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab" || !drawerRef.current) return;
      const focusable = Array.from(drawerRef.current.querySelectorAll<HTMLElement>('button:not([disabled]), summary, [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      const index = drawerStack.findIndex((entry) => entry.token === token);
      if (index >= 0) drawerStack.splice(index, 1);
      stackListeners.delete(updatePushed);
      notifyStackChange();
      if (drawerStack.length === 0) document.body.style.overflow = originalBodyOverflow;
      document.removeEventListener("keydown", handleKeyDown);
      if (opener?.isConnected) opener.focus();
    };
  }, []);
  return createPortal(<>
    <div className={`drawer-mask show${cascade ? " cascade" : ""}`} onMouseDown={(event) => { if (event.target === event.currentTarget) onRequestClose(); }} />
    <section ref={drawerRef} className={`drawer show${pushed ? " pushed" : ""}${cascade ? " cascade" : ""}${className ? ` ${className}` : ""}`} role="dialog" aria-modal="true" aria-labelledby={titleId}>
      <div className="drawer-head">
        <div>
          {eyebrow && <p className="eyebrow mono">{eyebrow}</p>}
          <h3 id={titleId}>{title}</h3>
          {subtitle && <p className="dsub mono">{subtitle}</p>}
        </div>
        <button ref={closeRef} type="button" className="ibtn outline" aria-label={t("common.close")} onClick={onRequestClose}>×</button>
      </div>
      <div className="drawer-body">{children}</div>
      {foot && <div className="drawer-foot">{foot}</div>}
    </section>
  </>, document.body);
}
