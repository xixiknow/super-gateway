import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

export type Theme = "light" | "dark";

const THEME_KEY = "super-gateway.admin.theme";

const THEME_COLOR: Record<Theme, string> = { light: "#f4f6f2", dark: "#05060f" };

export function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEME_COLOR[theme]);
}

function currentDomTheme(): Theme {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

type ThemeContextValue = {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggle: () => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  // theme-boot.js 已在首帧前写入 <html data-theme>,这里直接以 DOM 为准
  const [theme, setThemeState] = useState<Theme>(currentDomTheme);

  useEffect(() => {
    applyTheme(theme);
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* storage 不可用时仅对当前会话生效 */
    }
  }, [theme]);

  const setTheme = useCallback((next: Theme) => setThemeState(next), []);
  const toggle = useCallback(() => setThemeState((current) => (current === "dark" ? "light" : "dark")), []);
  const value = useMemo(() => ({ theme, setTheme, toggle }), [theme, setTheme, toggle]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

// Provider 外(如单元测试)回退为直接改 DOM:不触发重渲染,仅保证 API 可用
export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (context) return context;
  return {
    theme: currentDomTheme(),
    setTheme: (next: Theme) => applyTheme(next),
    toggle: () => applyTheme(currentDomTheme() === "dark" ? "light" : "dark"),
  };
}
