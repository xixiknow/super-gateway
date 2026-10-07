/* ============================================================
   主题引导:首帧渲染前同步设置 <html data-theme>,避免主题闪烁。
   CSP 禁止内联脚本(script-src 'self'),因此必须是外部文件。
   未手动选择过主题时默认浅色。
   ============================================================ */
(function () {
  var stored = null;
  try {
    stored = window.localStorage.getItem("super-gateway.admin.theme");
  } catch (error) {
    /* storage 不可用时使用默认值 */
  }
  var theme = stored === "dark" || stored === "light" ? stored : "light";
  var root = document.documentElement;
  root.dataset.theme = theme;
  var meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", theme === "dark" ? "#05060f" : "#f4f6f2");
})();
