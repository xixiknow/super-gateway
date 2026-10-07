import { useEffect, useState } from "react";

/* 与 app.css 的 ≤760px 断点保持一致:小屏时数据表格切换为卡片列表 */
export function useCompactLayout(breakpoint = "(max-width: 760px)"): boolean {
  const [compact, setCompact] = useState(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
    return window.matchMedia(breakpoint).matches;
  });
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const query = window.matchMedia(breakpoint);
    const sync = () => setCompact(query.matches);
    sync();
    query.addEventListener?.("change", sync);
    return () => query.removeEventListener?.("change", sync);
  }, [breakpoint]);
  return compact;
}
