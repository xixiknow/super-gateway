import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Principal, api } from "./api";
import { displayCell } from "./display";
import { GroupDetailDialog } from "./group-detail";
import { Locale, useI18n } from "./i18n";
import { ResourceActionButton } from "./ResourceAction";
import { useResourceRowActions } from "./resource-actions";
import { ErrorState, ResourceTable } from "./resource-table";
import { SelectField } from "./select-field";

/* ============================================================
   凭据管理(合并原「凭据」与「凭据分组」两个页面):
   分组是凭据的组织维度 —— 顶部筛选 + 表格分组列;
   分组的新建/重命名/生命周期/治理配置收敛到分组详情弹窗。
   后端 API 不变,筛选视图复用 GET /admin/v1/groups/{id}/credentials。
   ============================================================ */

const credentialColumns = ["account_uuid", "group_name", "purpose", "auth_kind", "lifecycle_state", "scheduling_state", "updated_at"];

interface GroupSummary {
  id?: unknown;
  name?: unknown;
  status?: unknown;
}

function groupLabel(group: GroupSummary, locale: Locale): string {
  const name = String(group.name || group.id || "");
  const status = String(group.status ?? "");
  return status === "active" || !status ? name : `${name} · ${displayCell(status, locale)}`;
}

export function CredentialsPage({ principal }: { principal: Principal }) {
  const { locale, t } = useI18n();
  const [groupId, setGroupId] = useState("");
  const [includeArchived, setIncludeArchived] = useState(false);
  const [detailId, setDetailId] = useState<string | null>(null);

  const groups = useQuery({ queryKey: ["/admin/v1/groups"], queryFn: () => api<GroupSummary[]>("/admin/v1/groups"), retry: false });
  const credentials = useQuery({
    // 选中分组时改走组内凭据端点;以 /admin/v1/credentials 为前缀的 key
    // 使「新建凭据」等动作的失效通知能同时命中两种视图
    queryKey: ["/admin/v1/credentials", groupId],
    queryFn: () => api<Record<string, unknown>[]>(groupId
      ? `/admin/v1/groups/${encodeURIComponent(groupId)}/credentials`
      : "/admin/v1/credentials"),
    retry: false,
  });

  // 凭据投影只携带 group_id,名称用分组列表在客户端映射
  const groupNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const group of groups.data ?? []) {
      const id = String(group.id ?? "");
      if (id) map.set(id, String(group.name || id));
    }
    return map;
  }, [groups.data]);

  const { rowActions, rowDialogs } = useResourceRowActions("/credentials", principal);

  // 后端列表暂无生命周期过滤参数,已归档凭据默认在客户端隐藏,可切换查看
  const rows = (credentials.data ?? [])
    .map((record): Record<string, unknown> & { group_name: string | null } =>
      ({ ...record, group_name: groupNames.get(String(record.group_id ?? "")) ?? null }))
    .filter((record) => includeArchived || record.lifecycle_state !== "archived");

  const groupOptions = [
    { value: "", label: t("credentials.filter.all") },
    ...(groups.data ?? [])
      .map((group) => ({ value: String(group.id ?? ""), label: groupLabel(group, locale) }))
      .filter((option) => option.value),
  ];

  const toolbar = <>
    <div className="segmented" role="group" aria-label={t("table.filter")}>
      <button type="button" className={!includeArchived ? "active" : ""} onClick={() => setIncludeArchived(false)}>{t("table.activeOnly")}</button>
      <button type="button" className={includeArchived ? "active" : ""} onClick={() => setIncludeArchived(true)}>{t("table.includeArchived")}</button>
    </div>
    <ResourceActionButton action="group" className="btn btn-outline btn-sm" />
    <ResourceActionButton action="credential" className="btn btn-primary btn-sm" />
  </>;

  return <div className="page-stack">
    <header className="page-heading"><div><p className="eyebrow mono">{t("credentials.eyebrow")}</p><h1>{t("nav.credentials")}</h1><p>{t("credentials.description")}</p></div></header>
    <div className="filter-rail single">
      <div className="field">
        <label htmlFor="credentials-group-filter">{t("credentials.filter.group")}</label>
        <SelectField id="credentials-group-filter" value={groupId} onChange={setGroupId}
          options={groupOptions}
          disabled={groups.isLoading || groups.isError}
          placeholder={groups.isLoading ? t("common.loading") : undefined} />
        {groups.isError && <small className="field-error" role="alert">{t("action.optionLoadFailed")}</small>}
      </div>
    </div>
    {credentials.isError && <ErrorState error={credentials.error} />}
    <ResourceTable
      loading={credentials.isLoading}
      items={rows}
      title={t("nav.credentials")}
      rowActions={rowActions}
      columnKeys={credentialColumns}
      renderCell={(column, record) => {
        if (column === "group_name" && typeof record.group_id === "string" && record.group_id) {
          return <button type="button" className="tbtn" onClick={() => setDetailId(record.group_id as string)}>{displayCell(record.group_name, locale)}</button>;
        }
        return displayCell(record[column], locale);
      }}
      onRefresh={() => { void credentials.refetch(); void groups.refetch(); }}
      refreshing={credentials.isFetching || groups.isFetching}
      toolbar={toolbar}
    />
    {rowDialogs}
    {detailId && <GroupDetailDialog row={{ id: detailId }} onClose={() => setDetailId(null)} />}
  </div>;
}
