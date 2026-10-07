import { FormEvent, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useI18n } from "./i18n";

/** OpenAI account row as projected by `GET /admin/v1/openai/accounts`. */
export interface OpenAiAccount {
  group_id: string; proxy_id?: string | null; refreshable?: boolean; plan?: string | null;
  quota?: unknown; quota_observed_at?: string | null; id: string; name: string; auth_kind: string;
  auth_state: string; enabled: boolean; verified_at: string | null; revision: number;
  max_concurrency: number; priority: number; websocket_enabled: boolean; models: string[];
  cooldown_until?: string | null; last_error_code?: string | null; last_error_message?: string | null;
  last_error_at?: string | null;
}

interface Group { id: string; name: string; provider?: string }

/**
 * OpenAI account mutations and the state driving the import / replace / OAuth
 * / edit forms. Shared by the accounts page cards.
 */
export function useOpenAiAccountActions() {
  const { t } = useI18n();
  const cache = useQueryClient();
  const form = useRef<HTMLFormElement>(null);
  const [kind, setKind] = useState("api_key");
  const [editing, setEditing] = useState<OpenAiAccount | null>(null);
  const [replace, setReplace] = useState<OpenAiAccount | null>(null);
  const [oauth, setOauth] = useState<{ id: string; authorization_url: string } | null>(null);
  const [invalid, setInvalid] = useState(false);
  const invalidate = () => { void cache.invalidateQueries({ queryKey: ["/admin/v1/openai/accounts"] }); void cache.invalidateQueries({ queryKey: ["/admin/v1/groups"] }); };
  const accountAction = useMutation({ mutationFn: ({ account, test }: { account: OpenAiAccount; test: boolean }) => api(`/admin/v1/openai/accounts/${encodeURIComponent(account.id)}${test ? ":test" : ""}`, {
    method: test ? "POST" : "PATCH", headers: { "If-Match": `"rev-${account.revision}"` }, body: JSON.stringify(test ? {} : {
      name: account.name, enabled: !account.enabled, max_concurrency: account.max_concurrency, priority: account.priority, websocket_enabled: account.websocket_enabled, models: account.models,
    }),
  }), onSettled: invalidate });
  const mutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api("/admin/v1/openai/accounts", { method: "POST", headers: replace ? { "If-Match": `"rev-${replace.revision}"` } : {}, body: JSON.stringify(body) }),
    onSuccess: () => { form.current?.reset(); setKind("api_key"); setReplace(null); invalidate(); },
  });
  const begin = useMutation({ mutationFn: (body: Record<string, unknown>) => api<{ id: string; authorization_url: string }>("/admin/v1/openai/oauth-sessions", { method: "POST", headers: replace ? { "If-Match": `"rev-${replace.revision}"` } : {}, body: JSON.stringify(body) }), onSuccess: (result) => setOauth(result) });
  const complete = useMutation({ mutationFn: (callback: string) => { const url = new URL(callback); const code = url.searchParams.get("code"); const state = url.searchParams.get("state"); if (!code || !state) throw new Error("Invalid callback"); return api(`/admin/v1/openai/oauth-sessions/${oauth?.id}:complete`, { method: "POST", body: JSON.stringify({ code, state }) }); }, onSuccess: () => { setOauth(null); setReplace(null); form.current?.reset(); invalidate(); } });
  const refresh = useMutation({ mutationFn: (account: OpenAiAccount) => api(`/admin/v1/openai/accounts/${account.id}:refresh`, { method: "POST", headers: { "If-Match": `"rev-${account.revision}"` }, body: "{}" }), onSettled: invalidate });
  const save = useMutation({ mutationFn: (body: Record<string, unknown>) => api(`/admin/v1/openai/accounts/${editing?.id}`, { method: "PATCH", headers: { "If-Match": `"rev-${editing?.revision}"` }, body: JSON.stringify(body) }), onSuccess: () => { setEditing(null); invalidate(); } });
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setInvalid(false);
    const data = new FormData(event.currentTarget);
    const body: Record<string, unknown> = { name: replace?.name ?? String(data.get("name")).trim(), group_id: replace?.group_id ?? data.get("group_id"), auth_kind: kind, proxy_id: String(data.get("proxy_id") ?? "").trim() || null, ...(replace ? { replace_account_id: replace.id } : {}) };
    if (kind === "browser") { const { auth_kind: _auth, ...start } = body; begin.mutate(start); return; }
    if (kind === "api_key") body.api_key = String(data.get("api_key")).trim();
    else {
      try { body.credentials = JSON.parse(String(data.get("credentials"))); }
      catch { setInvalid(true); return; }
    }
    mutation.mutate(body);
  }
  return {
    t, form, kind, setKind, editing, setEditing, replace, setReplace, oauth, invalid,
    groups: useQuery({ queryKey: ["/admin/v1/groups"], queryFn: () => api<Group[]>("/admin/v1/groups"), retry: false }),
    accountAction, mutation, begin, complete, refresh, save, submit,
    error: accountAction.isError || mutation.isError || begin.isError || complete.isError || refresh.isError || save.isError,
  };
}

export type OpenAiAccountActions = ReturnType<typeof useOpenAiAccountActions>;

/** Import / replace / OAuth / edit forms for OpenAI accounts. */
export function OpenAiAccountForms({ actions }: { actions: OpenAiAccountActions }) {
  const { t } = useI18n();
  const { form, kind, setKind, editing, replace, setReplace, oauth, invalid } = actions;
  const eligible = (actions.groups.data ?? []).filter((group) => group.provider === "openai");
  return <>
    {replace && <p role="status">{t("openai.replace")} · {replace.name} <button type="button" className="btn btn-outline" onClick={() => setReplace(null)}>{t("common.cancel")}</button></p>}
    {oauth && <div className="card pad"><p>{t("openai.callbackNote")}</p><a href={oauth.authorization_url} target="_blank" rel="noreferrer">{t("openai.authorize")}</a><form onSubmit={(event) => { event.preventDefault(); actions.complete.mutate(String(new FormData(event.currentTarget).get("callback"))); }}><label className="field"><span>{t("openai.callback")}</span><input className="inp" name="callback" type="url" required autoComplete="off" /></label><button className="btn btn-primary" disabled={actions.complete.isPending}>{t("common.save")}</button></form></div>}
    <form key={replace?.id ?? "new"} ref={form} className="settings-grid" onSubmit={actions.submit} autoComplete="off">
      <label className="field"><span>{t("action.group.name")}</span><input className="inp" name="name" defaultValue={replace?.name ?? ""} required maxLength={128} /></label>
      <label className="field"><span>{t("action.group.select")}</span><select className="inp" name="group_id" required defaultValue={replace?.group_id ?? ""}><option value="" disabled>{t("common.select")}</option>{eligible.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>
      <label className="field"><span>{t("action.authMethod")}</span><select className="inp" value={kind} onChange={(event) => { setKind(event.target.value); actions.mutation.reset(); }}><option value="api_key">OpenAI API Key</option><option value="oauth">ChatGPT / Codex JSON</option><option value="browser">{t("openai.authorize")}</option></select></label>
      {kind === "api_key" ? <label className="field"><span>API Key</span><input className="inp" name="api_key" type="password" required maxLength={65536} autoComplete="new-password" /></label> : kind === "oauth" ? <label className="field"><span>{t("openai.material")}</span><textarea className="inp" name="credentials" required rows={5} maxLength={1048576} spellCheck={false} /></label> : null}
      <label className="field"><span>{t("openai.proxy")}</span><input className="inp" name="proxy_id" defaultValue={replace?.proxy_id ?? ""} /></label>
      <button className="btn btn-primary" type="submit" disabled={actions.mutation.isPending || actions.begin.isPending || eligible.length === 0}>{t(actions.mutation.isPending ? "common.submitting" : "openai.import")}</button>
    </form>
    {invalid && <p role="alert">{t("common.jsonInvalid", { field: t("openai.material") })}</p>}
    {actions.mutation.isSuccess && <p role="status">{t("openai.imported")}</p>}
    {editing && <form className="card pad settings-grid" onSubmit={(event) => { event.preventDefault(); const data = new FormData(event.currentTarget); actions.save.mutate({ group_id: data.get("group_id"), proxy_id: String(data.get("proxy_id") ?? "").trim() || null, name: String(data.get("name")), enabled: editing.enabled, max_concurrency: Number(data.get("max_concurrency")), priority: Number(data.get("priority")), websocket_enabled: data.get("websocket_enabled") === "on", models: String(data.get("models")).split(/[,\n]/).map((value) => value.trim()).filter(Boolean) }); }} key={editing.id}>
      <label className="field"><span>{t("action.group.name")}</span><input className="inp" name="name" defaultValue={editing.name} required maxLength={128} /></label>
      <label className="field"><span>{t("action.group.select")}</span><select className="inp" name="group_id" defaultValue={editing.group_id}>{eligible.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>
      <label className="field"><span>{t("openai.proxy")}</span><input className="inp" name="proxy_id" defaultValue={editing.proxy_id ?? ""} /></label>
      <label className="field"><span>{t("openai.concurrency")}</span><input className="inp" name="max_concurrency" type="number" min={1} max={1000} defaultValue={editing.max_concurrency} required /></label>
      <label className="field"><span>{t("openai.priority")}</span><input className="inp" name="priority" type="number" defaultValue={editing.priority} required /></label>
      <label className="field"><span>{t("openai.models")}</span><textarea className="inp" name="models" defaultValue={editing.models.join("\n")} /></label>
      <label className="check-row"><input type="checkbox" name="websocket_enabled" defaultChecked={editing.websocket_enabled} />{t("openai.websocket")}</label>
      <button className="btn btn-primary" disabled={actions.save.isPending}>{t("common.save")}</button><button className="btn btn-outline" type="button" onClick={() => actions.setEditing(null)}>{t("common.cancel")}</button>
    </form>}
  </>;
}
