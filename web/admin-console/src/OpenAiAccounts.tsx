import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { useI18n, type MessageKey } from "./i18n";

interface Group { id: string; name: string; provider?: string }

export function OpenAiSettings() {
  const { t } = useI18n();
  const query = useQuery({ queryKey: ["/admin/v1/settings/openai"], queryFn: () => api<Record<string, number | boolean>>("/admin/v1/settings/openai"), retry: false });
  const mutation = useMutation({ mutationFn: (body: Record<string, number | boolean>) => api("/admin/v1/settings/openai", {
    method: "PUT", headers: { "If-Match": `"rev-${query.data?.revision}"` }, body: JSON.stringify(body),
  }), onSuccess: () => { void query.refetch(); } });
  const fields: { name: string; label: MessageKey; min: number; max: number }[] = [
    { name: "connect_timeout_seconds", label: "openai.connectTimeout", min: 1, max: 120 },
    { name: "response_timeout_seconds", label: "openai.responseTimeout", min: 1, max: 3600 },
    { name: "websocket_idle_seconds", label: "openai.idleTimeout", min: 1, max: 3600 },
    { name: "refresh_interval_seconds", label: "openai.refreshInterval", min: 10, max: 3600 },
  ];
  return <section className="card pad"><div className="section-head"><div><h2>{t("openai.settings")}</h2><p>{t("openai.settingsNote")}</p></div></div>
    {query.isLoading ? <p>{t("common.loading")}</p> : query.data && <form key={query.dataUpdatedAt} className="settings-grid" onSubmit={e => {
      e.preventDefault(); const data = new FormData(e.currentTarget);
      mutation.mutate({ enabled: data.get("enabled") === "on", websocket_enabled: data.get("websocket_enabled") === "on", ...Object.fromEntries(fields.map(f => [f.name, Number(data.get(f.name))])) });
    }}><label className="check-row"><input name="enabled" type="checkbox" defaultChecked={query.data.enabled === true} /><span>{t("openai.enabled")}</span></label>
      <label className="check-row"><input name="websocket_enabled" type="checkbox" defaultChecked={query.data.websocket_enabled === true} /><span>{t("openai.websocket")}</span></label>
      {fields.map(f => <label className="field" key={f.name}><span>{t(f.label)}</span><input className="inp" name={f.name} type="number" min={f.min} max={f.max} required defaultValue={Number(query.data?.[f.name])} /></label>)}
      <button className="btn btn-primary" disabled={mutation.isPending} type="submit">{t("common.save")}</button></form>}
    {(query.isError || mutation.isError) && <p role="alert">{t("common.operationFailed")}</p>}
    {mutation.isSuccess && <p role="status">{t("openai.saved")}</p>}
    <OpenAiGroupPolicy />
  </section>;
}

function OpenAiGroupPolicy() {
  const { t } = useI18n();
  const [group,setGroup]=useState("");
  const groups=useQuery({queryKey:["/admin/v1/groups"],queryFn:()=>api<Group[]>("/admin/v1/groups")});
  const url=`/admin/v1/groups/${group}/openai-policy`;
  const policy=useQuery({queryKey:[url],queryFn:()=>api<{revision:number;max_reasoning_effort:string|null;reasoning_over_limit:string}>(url),enabled:!!group});
  const save=useMutation({mutationFn:(body:unknown)=>api(url,{method:"PUT",headers:{"If-Match":`"rev-${policy.data?.revision}"`},body:JSON.stringify(body)}),onSuccess:()=>{void policy.refetch();}});
  return <div><h3>{t("openai.groupPolicy")}</h3><select className="inp" aria-label={t("action.group.select")} value={group} onChange={e=>setGroup(e.target.value)}><option value="">{t("common.select")}</option>{groups.data?.filter(g=>g.provider==="openai").map(g=><option key={g.id} value={g.id}>{g.name}</option>)}</select>
  {policy.data && <form key={`${group}-${policy.data.revision}`} className="settings-grid" onSubmit={e=>{e.preventDefault();const data=new FormData(e.currentTarget);save.mutate({max_reasoning_effort:data.get("maximum")||null,reasoning_over_limit:data.get("action")});}}><label className="field"><span>{t("openai.maximum")}</span><select className="inp" name="maximum" defaultValue={policy.data.max_reasoning_effort??""}><option value="">{t("openai.inherit")}</option>{["none","minimal","low","medium","high","xhigh"].map(v=><option key={v}>{v}</option>)}</select></label><label className="field"><span>{t("openai.overLimit")}</span><select className="inp" name="action" defaultValue={policy.data.reasoning_over_limit}><option value="reject">{t("openai.reject")}</option><option value="downgrade">{t("openai.downgrade")}</option></select></label><button className="btn btn-primary" disabled={save.isPending}>{t("common.save")}</button></form>}
  {(save.isError||policy.isError)&&<p role="alert">{t("common.operationFailed")}</p>}</div>;
}
