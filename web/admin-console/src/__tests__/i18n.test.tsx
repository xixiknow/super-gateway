import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { I18nProvider, LanguageSwitch, resolveInitialLocale, useI18n } from "../i18n";

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function Fixture() {
  const { t } = useI18n();
  return <><LanguageSwitch /><p>{t("auth.loginTitle")}</p><ul><li>{t("nav.groups")}</li><li>{t("nav.credentials")}</li><li>{t("nav.platformKeys")}</li><li>{t("nav.egress")}</li><li>{t("nav.bundles")}</li></ul></>;
}

describe("admin console i18n", () => {
  it("resolves stored and browser language preferences", () => {
    expect(resolveInitialLocale("en-US", ["zh-CN"])).toBe("en-US");
    expect(resolveInitialLocale(null, ["zh-Hans-CN"])).toBe("zh-CN");
    expect(resolveInitialLocale("invalid", ["en-GB"])).toBe("en-US");
  });

  it("switches content, document language, title, and persisted preference", async () => {
    const storage = { getItem: vi.fn(() => null), setItem: vi.fn(), removeItem: vi.fn(), clear: vi.fn(), key: vi.fn(), length: 0 };
    Object.defineProperty(window, "localStorage", { configurable: true, value: storage });
    const user = userEvent.setup();
    render(<I18nProvider initialLocale="zh-CN"><Fixture /></I18nProvider>);
    expect(screen.getByText("登录控制塔")).toBeInTheDocument();
    for (const label of ["凭据分组", "凭据", "平台密钥", "代理 / 出口", "环境原型 / 传输包"]) expect(screen.getByText(label)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "EN" }));
    expect(screen.getByText("Sign in to Control Tower")).toBeInTheDocument();
    for (const label of ["Credential Groups", "Credentials", "Platform Keys", "Proxy / Egress", "Archetype / Bundle"]) expect(screen.getByText(label)).toBeInTheDocument();
    expect(document.documentElement.lang).toBe("en-US");
    expect(document.title).toBe("Super Gateway · Control Tower");
    expect(storage.setItem).toHaveBeenLastCalledWith("super-gateway.admin.locale", "en-US");
  });
});
