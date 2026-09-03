-- 退役 Enforcement 独立工件与测活/后台目录(参见 planning/simplified-blueprint.md §3.2 B1/B2)。
-- System 净化改由 gateway.group_config 的 system_prompt_* 列直读;所有 /v1/messages 一律按普通业务处理。
-- 说明:保留 gateway.group_config.enforcement_artifact_id 列(置空,不再写入),避免大范围位置参数改写;后续可另行清理该列。

-- 1) 解除分组配置对 enforcement 工件的外键引用(catalog.versioned_artifact ON DELETE RESTRICT,需先置空)。
UPDATE gateway.group_config
   SET enforcement_artifact_id = NULL
 WHERE enforcement_artifact_id IS NOT NULL;

-- 2) 删除 enforcement 与 background_catalog 两类工件的激活指针、灰度证据与工件本体。
DELETE FROM catalog.active_artifact_pointer
 WHERE artifact_kind_code IN ('enforcement', 'background_catalog');

DELETE FROM catalog.artifact_rollout_evidence
 WHERE artifact_id IN (
   SELECT id
     FROM catalog.versioned_artifact
    WHERE artifact_kind_code IN ('enforcement', 'background_catalog')
 );

DELETE FROM catalog.versioned_artifact
 WHERE artifact_kind_code IN ('enforcement', 'background_catalog');

-- 3) 删除仅服务 enforcement 工件绑定校验的触发器与函数;System 策略已改由 group_config 列承载。
DROP TRIGGER IF EXISTS group_config_enforcement_matches ON gateway.group_config;
DROP FUNCTION IF EXISTS gateway.validate_group_config_enforcement();
