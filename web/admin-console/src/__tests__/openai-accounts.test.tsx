import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { OpenAiAccountForms, useOpenAiAccountActions } from "../openai-account-panel";
import { I18nProvider } from "../i18n";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function Harness() {
  const actions = useOpenAiAccountActions();
  return <OpenAiAccountForms actions={actions} />;
}

it("limits imports to OpenAI groups and clears API key after success", async () => {
  let submitted: Record<string, unknown> | undefined;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    if (init?.method === "POST") {
      submitted = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ data: { id: "account", enabled: false } }), { status: 201 });
    }
    const data = String(input).endsWith("/groups") ? [{ id: "legacy", name: "Claude", provider: "anthropic" }, { id: "openai", name: "OpenAI group", provider: "openai" }] : [];
    return new Response(JSON.stringify({ data }), { status: 200 });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<I18nProvider initialLocale="en-US"><QueryClientProvider client={client}><Harness /></QueryClientProvider></I18nProvider>);
  expect(await screen.findByRole("option", { name: "OpenAI group" })).toBeInTheDocument();
  expect(screen.queryByRole("option", { name: "Claude" })).not.toBeInTheDocument();
  const user = userEvent.setup();
  const form = document.querySelector("form")!;
  await user.type(form.querySelector<HTMLInputElement>('[name="name"]')!, "SDK account");
  await user.selectOptions(form.querySelector<HTMLSelectElement>('[name="group_id"]')!, "openai");
  await user.type(screen.getByLabelText("API Key"), "fixture-key");
  await user.click(screen.getByRole("button", { name: "Import account" }));
  expect(await screen.findByRole("status")).toHaveTextContent("Imported");
  expect(submitted).toEqual({ name: "SDK account", group_id: "openai", auth_kind: "api_key", api_key: "fixture-key", proxy_id: null });
  expect(screen.getByLabelText("API Key")).toHaveValue("");
});
