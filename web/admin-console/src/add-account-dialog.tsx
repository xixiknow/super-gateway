import { MouseEvent, useEffect, useId, useState } from "react";
import { createPortal } from "react-dom";
import { CredentialEnrollmentBody } from "./ResourceAction";
import { OpenAiAccountForms, type OpenAiAccountActions } from "./openai-account-panel";
import { useI18n } from "./i18n";

interface Group { id: string; name: string; provider?: string; status?: string }

/**
 * 统一「添加账号」向导:先选平台,Anthropic 进入标准凭据录入流程,
 * OpenAI 展开导入表单;无 Anthropic 分组时给出先建分组的引导。
 */
export function AddAccountDialog({ open, onClose, groups, openai, initialPlatform = "pick" }: {
  open: boolean; onClose(): void; groups: Group[] | undefined; openai: OpenAiAccountActions;
  initialPlatform?: "pick" | "openai";
}) {
  const { t } = useI18n();
  const titleId = useId();
  const [platform, setPlatform] = useState<"anthropic" | "openai" | null>(null);
  useEffect(() => { if (open) setPlatform(initialPlatform === "openai" ? "openai" : null); }, [open, initialPlatform]);
  useEffect(() => {
    if (!open || platform === "anthropic") return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [open, platform, onClose]);
  if (!open) return null;
  const anthropicGroupCount = (groups ?? []).filter((group) => (group.provider ?? "anthropic") === "anthropic").length;
  function overlayClose(event: MouseEvent<HTMLDivElement>) {
    // Anthropic 录入步骤的创建请求进行中不允许误关,其余步骤点遮罩即关
    if (event.target === event.currentTarget && platform !== "anthropic") onClose();
  }
  const head = (title: string) => <div className="modal-head"><div><p className="eyebrow mono">ACCOUNTS</p><h3 id={titleId}>{title}</h3></div><button type="button" className="ibtn outline" aria-label={t("common.close")} onClick={onClose}>×</button></div>;
  return createPortal(<div className="overlay show" onMouseDown={overlayClose}>
    <section className="modal account-add-modal" role="dialog" aria-modal="true" aria-labelledby={titleId}>
      {platform === null && <>
        {head(t("accounts.add.title"))}
        <div className="modal-body">
          <p className="muted">{t("accounts.add.pickPlatform")}</p>
          <div className="account-pick-grid">
            <button type="button" className="account-pick-card" onClick={() => setPlatform("anthropic")}>
              <b>{t("accounts.add.anthropic")}</b>
              <small>{t("action.credential.description")}</small>
            </button>
            <button type="button" className="account-pick-card" onClick={() => setPlatform("openai")}>
              <b>{t("accounts.add.openai")}</b>
              <small>{t("openai.note")}</small>
            </button>
          </div>
          {anthropicGroupCount === 0 && <div className="alert alert-warn" role="status"><div><div className="at">{t("accounts.add.noGroup")}</div><div className="ad"><a className="tbtn" href="/admin/groups" onClick={onClose}>{t("accounts.add.goGroups")}</a></div></div></div>}
        </div>
        <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>{t("common.cancel")}</button></div>
      </>}
      {platform === "anthropic" && <CredentialEnrollmentBody onClose={onClose} titleId={titleId} />}
      {platform === "openai" && <>
        {head(t("accounts.add.openai"))}
        <div className="modal-body"><OpenAiAccountForms actions={openai} /></div>
        <div className="modal-foot"><button type="button" className="btn btn-ghost" onClick={onClose}>{t("common.close")}</button></div>
      </>}
    </section>
  </div>, document.body);
}
