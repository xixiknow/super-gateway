import { KeyboardEvent as ReactKeyboardEvent, FocusEvent as ReactFocusEvent, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";

/* ============================================================
   应用内渲染的下拉选择器,替代原生 <select>。
   原生 select 的选项弹层是浏览器独立绘制的弹出文档,深色主题下
   首帧常出现"先弹空面板、后画文字"的空白闪烁;此组件将选项列表
   渲染在页面 DOM 内(与行操作菜单同一套 dd-menu 视觉),随页面
   一次成帧,不再依赖原生弹层。
   表单兼容:内部保留一个不可见的原生 select 镜像,name/required
   照常参与 FormData 收集与浏览器必填校验。
   ============================================================ */

export interface SelectFieldOption {
  value: string;
  label: string;
  disabled?: boolean;
}

interface MenuPosition {
  top: number;
  left: number;
  width: number;
}

const MENU_GAP = 6;
const MENU_MAX_HEIGHT = 340;
const OPTION_HEIGHT = 37;

export function SelectField({
  id, name, value, defaultValue, onChange, options, placeholder,
  required = false, disabled = false, autoFocus = false, className = "",
}: {
  id?: string;
  name?: string;
  /** 传入即为受控模式;不传则内部维护(defaultValue 起始) */
  value?: string;
  defaultValue?: string;
  onChange?(value: string): void;
  options: SelectFieldOption[];
  /** 当前值匹配不到任何选项时显示的占位文案(如"请选择"/"加载中…") */
  placeholder?: string;
  required?: boolean;
  disabled?: boolean;
  autoFocus?: boolean;
  className?: string;
}) {
  const controlled = value !== undefined;
  const [inner, setInner] = useState(defaultValue ?? "");
  const current = controlled ? value : inner;
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const [position, setPosition] = useState<MenuPosition | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const listboxId = useId();

  const selectedIndex = options.findIndex((option) => option.value === current);
  const selected = selectedIndex >= 0 ? options[selectedIndex] : undefined;

  function anchorMenu() {
    const rect = triggerRef.current?.getBoundingClientRect();
    if (!rect) return;
    const estimated = Math.min(options.length * OPTION_HEIGHT + 12, MENU_MAX_HEIGHT);
    const openUp = rect.bottom + MENU_GAP + estimated > window.innerHeight && rect.top - MENU_GAP - estimated > 0;
    setPosition({
      top: openUp ? Math.max(8, rect.top - MENU_GAP - estimated) : rect.bottom + MENU_GAP,
      left: rect.left,
      width: rect.width,
    });
  }

  function openMenu() {
    if (disabled || options.length === 0) return;
    anchorMenu();
    setActive(selectedIndex >= 0 ? selectedIndex : options.findIndex((option) => !option.disabled));
    setOpen(true);
  }

  function closeMenu() {
    setOpen(false);
    setActive(-1);
  }

  function choose(option: SelectFieldOption) {
    if (option.disabled) return;
    if (!controlled) setInner(option.value);
    onChange?.(option.value);
    closeMenu();
    triggerRef.current?.focus();
  }

  function moveActive(delta: number) {
    if (options.length === 0) return;
    let index = active;
    for (let step = 0; step < options.length; step += 1) {
      index = (index + delta + options.length) % options.length;
      if (!options[index].disabled) break;
    }
    setActive(index);
  }

  function onTriggerKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>) {
    if (disabled) return;
    if (!open) {
      if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
        event.preventDefault();
        openMenu();
      }
      return;
    }
    switch (event.key) {
      case "ArrowDown": event.preventDefault(); moveActive(1); break;
      case "ArrowUp": event.preventDefault(); moveActive(-1); break;
      case "Home": event.preventDefault(); setActive(options.findIndex((option) => !option.disabled)); break;
      case "End": {
        event.preventDefault();
        const last = [...options].reverse().findIndex((option) => !option.disabled);
        if (last >= 0) setActive(options.length - 1 - last);
        break;
      }
      case "Enter":
      case " ":
        event.preventDefault();
        if (active >= 0) choose(options[active]);
        else closeMenu();
        break;
      case "Escape":
        // 仅关闭下拉,阻止冒泡以免所在弹窗一并关闭
        event.preventDefault();
        event.stopPropagation();
        closeMenu();
        break;
      case "Tab":
        closeMenu();
        break;
      default:
        break;
    }
  }

  function onTriggerBlur(event: ReactFocusEvent<HTMLButtonElement>) {
    const next = event.relatedTarget as Node | null;
    if (next && (rootRef.current?.contains(next) || menuRef.current?.contains(next))) return;
    closeMenu();
  }

  useEffect(() => {
    if (!open) return;
    // 捕获阶段吞掉菜单外的按下事件:首次外部点击只用于收起菜单,
    // 不落到底下的控件或弹窗遮罩上(与原生 select 弹层的行为一致)
    const dismissOnOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      if (rootRef.current?.contains(target) || menuRef.current?.contains(target)) return;
      event.preventDefault();
      event.stopPropagation();
      closeMenu();
    };
    const reanchor = () => anchorMenu();
    document.addEventListener("mousedown", dismissOnOutside, true);
    window.addEventListener("scroll", reanchor, true);
    window.addEventListener("resize", reanchor);
    return () => {
      document.removeEventListener("mousedown", dismissOnOutside, true);
      window.removeEventListener("scroll", reanchor, true);
      window.removeEventListener("resize", reanchor);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open || active < 0) return;
    const item = menuRef.current?.querySelector(`[data-index="${active}"]`);
    if (item instanceof HTMLElement && typeof item.scrollIntoView === "function") item.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  const activeOptionId = open && active >= 0 ? `${listboxId}-option-${active}` : undefined;

  return (
    <div ref={rootRef} className="select-field">
      <button
        ref={triggerRef}
        type="button"
        id={id}
        className={`inp select-trigger ${className}`.trim()}
        role="combobox"
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-controls={open ? listboxId : undefined}
        aria-activedescendant={activeOptionId}
        aria-required={required || undefined}
        disabled={disabled}
        autoFocus={autoFocus}
        onClick={() => (open ? closeMenu() : openMenu())}
        onKeyDown={onTriggerKeyDown}
        onBlur={onTriggerBlur}
      >
        <span className={`select-value${selected ? "" : " select-placeholder"}`}>{selected?.label ?? placeholder ?? "\u00A0"}</span>
      </button>
      {/* 表单镜像:随组件值同步,承担 FormData 提交与 required 校验 */}
      <select
        className="select-native"
        name={name}
        required={required}
        disabled={disabled}
        value={current}
        tabIndex={-1}
        aria-hidden="true"
        onChange={(event) => {
          const option = options.find((item) => item.value === event.target.value);
          if (option) choose(option);
        }}
      >
        <option value="" />
        {current !== "" && selectedIndex < 0 && <option value={current} />}
        {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
      </select>
      {open && position && createPortal(
        <div
          ref={menuRef}
          id={listboxId}
          className="dd-menu select-menu"
          role="listbox"
          aria-labelledby={id}
          style={{ position: "fixed", top: position.top, left: position.left, width: position.width, display: "block", zIndex: 200 }}
        >
          {options.map((option, index) => (
            <button
              key={option.value}
              type="button"
              role="option"
              id={`${listboxId}-option-${index}`}
              data-index={index}
              className={`dd-item select-option${index === active ? " active" : ""}`}
              aria-selected={option.value === current}
              disabled={option.disabled}
              tabIndex={-1}
              onMouseDown={(event) => event.preventDefault()}
              onMouseEnter={() => setActive(index)}
              onClick={() => choose(option)}
            >
              <span className="select-option-label">{option.label}</span>
              {option.value === current && <svg className="icon sm" aria-hidden="true"><use href="#i-check" /></svg>}
            </button>
          ))}
        </div>,
        document.body,
      )}
    </div>
  );
}
