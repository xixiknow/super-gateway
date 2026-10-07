import { useIsMutating, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useToast } from "./feedback";
import { useI18n } from "./i18n";

const terminalStates = new Set(["succeeded", "dead_letter", "cancelled", "failed", "partially_succeeded"]);
const mutationKey = ["model-catalog-and-price-sync"];
const progressKey = ["model-catalog-and-price-progress"];
type Progress = { phase: "catalog" | "price" | "refresh"; result: string | null };
const initialProgress: Progress = { phase: "catalog", result: null };

export function ModelSyncButton({ className = "btn btn-primary" }: { className?: string }) {
  const { t } = useI18n();
  const toast = useToast();
  const client = useQueryClient();
  const progress = useQuery<Progress>({ queryKey: progressKey, queryFn: () => client.getQueryData<Progress>(progressKey) ?? initialProgress, enabled: false, initialData: initialProgress, gcTime: Infinity });
  const { phase, result } = progress.data;
  function setPhase(phase: Progress["phase"]) { client.setQueryData<Progress>(progressKey, (previous) => ({ ...(previous ?? initialProgress), phase })); }
  function setResult(result: string | null) { client.setQueryData<Progress>(progressKey, (previous) => ({ ...(previous ?? initialProgress), result })); }
  const running = useIsMutating({ mutationKey }) > 0;
  async function syncStage(endpoint: string, body: unknown): Promise<string | null> {
    try {
      const submitted = await api<{ id?: string }>(endpoint, { method: "POST", body: JSON.stringify(body) });
      if (!submitted.id || typeof submitted.id !== "string") throw new Error(t("common.requestFailed"));
      for (;;) {
        const job = await api<{ state: string; last_error?: string | null }>(`/admin/v1/operations/jobs/${encodeURIComponent(submitted.id)}`);
        if (terminalStates.has(job.state)) return job.state === "succeeded" ? null : job.last_error || job.state;
        await new Promise<void>((resolve) => window.setTimeout(resolve, 1000));
      }
    } catch (error) {
      return error instanceof Error ? error.message : t("common.requestFailed");
    }
  }
  const sync = useMutation({
    mutationKey,
    mutationFn: async () => {
      setResult(null);
      setPhase("catalog");
      const catalog = await syncStage("/admin/v1/models:refresh", { reason: "admin_console_public_catalog_sync" });
      setPhase("price");
      const prices = await syncStage("/admin/v1/price-sync:run", {});
      setPhase("refresh");
      await Promise.all([
        client.invalidateQueries({ queryKey: ["/admin/v1/models"] }),
        client.invalidateQueries({ queryKey: ["/admin/v1/capability-versions"] }),
        client.invalidateQueries({ queryKey: ["/admin/v1/price-sync/status"] }),
      ]);
      return { catalog, prices };
    },
    onSuccess: ({ catalog, prices }) => {
      const summary = t("action.model.combinedResult", { catalog: catalog ?? t("action.model.stageSucceeded"), prices: prices ?? t("action.model.stageSucceeded") });
      setResult(summary);
      if (catalog === null && prices === null) toast.success(t("action.model.allCompleted"));
      else toast.error(summary);
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : t("common.requestFailed")),
  });
  const busy = running || sync.isPending;
  const label = busy ? t(phase === "catalog" ? "action.model.catalogStage" : phase === "price" ? "action.model.priceStage" : "action.model.refreshStage") : t("action.model.button");
  return <div className="model-sync-control">
    <button type="button" className={`${className}${busy ? " loading" : ""}`} aria-busy={busy} disabled={busy} onClick={() => sync.mutate()}><svg className="icon sm" aria-hidden="true"><use href="#i-globe" /></svg>{label}</button>
    {result && <span className="model-sync-result" role="status" title={result}>{result}</span>}
  </div>;
}
