-- R5 Credential lifecycle, auth maintenance, Profile/Device, fixed Egress and PLAN contracts.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE security.encrypted_secret DROP CONSTRAINT encrypted_secret_secret_kind_code_check;
ALTER TABLE security.encrypted_secret ADD CONSTRAINT encrypted_secret_secret_kind_code_check CHECK (
  secret_kind_code IN (
    'platform_key','oauth_access_token','oauth_refresh_token','setup_token','console_api_key',
    'pkce_verifier','oauth_callback_material','proxy_password','device_identity','session_hmac',
    'managed_browser','browser_cookie','browser_storage','browser_profile',
    'notification_destination','totp_seed'
  )
);

ALTER TABLE gateway.group_config DROP CONSTRAINT group_config_proxy_policy_code_check;
UPDATE gateway.group_config SET proxy_policy_code = CASE proxy_policy_code
  WHEN 'optional' THEN 'auto' WHEN 'required' THEN 'proxy_required' WHEN 'disabled' THEN 'direct'
  ELSE proxy_policy_code END;
ALTER TABLE gateway.group_config ADD CONSTRAINT group_config_proxy_policy_code_check
  CHECK (proxy_policy_code IN ('auto','proxy_required','direct'));
ALTER TABLE gateway.group_config
  ADD COLUMN fully_managed_required boolean NOT NULL DEFAULT false,
  ADD COLUMN console_business_fallback_enabled boolean NOT NULL DEFAULT false;

ALTER TABLE gateway.anthropic_credential
  DROP CONSTRAINT anthropic_credential_purpose_code_check,
  DROP CONSTRAINT anthropic_credential_auth_kind_code_check,
  DROP CONSTRAINT anthropic_credential_lifecycle_state_code_check,
  DROP CONSTRAINT anthropic_credential_auth_state_code_check,
  DROP CONSTRAINT anthropic_credential_scheduling_state_code_check,
  DROP CONSTRAINT anthropic_credential_transport_state_code_check,
  DROP CONSTRAINT anthropic_credential_management_class_code_check;
UPDATE gateway.anthropic_credential SET
  purpose_code = CASE purpose_code WHEN 'claude_subscription' THEN 'business' WHEN 'console_api' THEN 'business' ELSE purpose_code END,
  auth_kind_code = CASE auth_kind_code WHEN 'oauth' THEN 'oauth_subscription' WHEN 'setup_token' THEN 'setup_token_subscription' ELSE auth_kind_code END,
  lifecycle_state_code = CASE lifecycle_state_code WHEN 'manual_recovery_required' THEN 'disabled' ELSE lifecycle_state_code END,
  auth_state_code = CASE auth_state_code WHEN 'pending' THEN 'needs_admin_reauth' WHEN 'invalid' THEN 'auth_broken' ELSE auth_state_code END,
  transport_state_code = CASE transport_state_code WHEN 'ready' THEN 'ready' ELSE 'transport_unavailable' END,
  management_class_code = CASE WHEN lifecycle_state_code = 'manual_recovery_required' THEN 'manual_recovery_required' ELSE management_class_code END;
ALTER TABLE gateway.anthropic_credential
  ADD COLUMN attachment_state_code text NOT NULL DEFAULT 'attached',
  ADD COLUMN capacity_state_code text NOT NULL DEFAULT 'available',
  ADD COLUMN auth_next_at timestamptz,
  ADD COLUMN capacity_reason_code text,
  ADD COLUMN consecutive_cooldown_count integer NOT NULL DEFAULT 0,
  ADD COLUMN half_open_budget integer NOT NULL DEFAULT 0,
  ADD COLUMN purpose_compatible boolean NOT NULL DEFAULT true,
  ADD CONSTRAINT anthropic_credential_purpose_code_check CHECK (purpose_code IN ('business','count_tokens')),
  ADD CONSTRAINT anthropic_credential_auth_kind_code_check CHECK (auth_kind_code IN ('oauth_subscription','setup_token_subscription','console_api_key')),
  ADD CONSTRAINT anthropic_credential_lifecycle_state_code_check CHECK (lifecycle_state_code IN ('pending_verify','pending_profile','pending_egress','pending_reauth_strategy','active','disabled','revoked','archived')),
  ADD CONSTRAINT anthropic_credential_attachment_state_code_check CHECK (attachment_state_code IN ('attached','draining','detached','attaching')),
  ADD CONSTRAINT anthropic_credential_auth_state_code_check CHECK (auth_state_code IN ('healthy','expiring','refreshing','reauth_retrying','reauth_waiting_egress','manual_recovery_required','needs_admin_reauth','auth_broken')),
  ADD CONSTRAINT anthropic_credential_capacity_state_code_check CHECK (capacity_state_code IN ('available','limited','cooldown','half_open')),
  ADD CONSTRAINT anthropic_credential_scheduling_state_code_check CHECK (scheduling_state_code IN ('eligible','cooldown','blocked','transport_unavailable')),
  ADD CONSTRAINT anthropic_credential_transport_state_code_check CHECK (transport_state_code IN ('ready','transport_unavailable')),
  ADD CONSTRAINT anthropic_credential_management_class_code_check CHECK (management_class_code IN ('fully_managed','non_managed','pending_reauth_strategy','manual_recovery_required')),
  ADD CONSTRAINT anthropic_credential_cooldown_count_check CHECK (consecutive_cooldown_count >= 0),
  ADD CONSTRAINT anthropic_credential_half_open_budget_check CHECK (half_open_budget >= 0);

ALTER TABLE gateway.credential_auth_version
  DROP CONSTRAINT credential_auth_version_auth_kind_code_check,
  DROP CONSTRAINT credential_auth_version_check;
UPDATE gateway.credential_auth_version SET auth_kind_code = CASE auth_kind_code
  WHEN 'oauth' THEN 'oauth_subscription' WHEN 'setup_token' THEN 'setup_token_subscription' ELSE auth_kind_code END;
ALTER TABLE gateway.credential_auth_version
  ADD COLUMN material_state_code text NOT NULL DEFAULT 'candidate',
  ADD COLUMN adapter_code text,
  ADD COLUMN adapter_version text,
  ADD COLUMN activated_at timestamptz,
  ADD CONSTRAINT credential_auth_version_auth_kind_code_check CHECK (auth_kind_code IN ('oauth_subscription','setup_token_subscription','console_api_key')),
  ADD CONSTRAINT credential_auth_version_material_state_code_check CHECK (material_state_code IN ('candidate','active','superseded','destroyed')),
  ADD CONSTRAINT credential_auth_version_material_shape_check CHECK (
    (auth_kind_code = 'oauth_subscription' AND access_secret_id IS NOT NULL AND setup_secret_id IS NULL AND console_secret_id IS NULL)
    OR (auth_kind_code = 'setup_token_subscription' AND console_secret_id IS NULL AND ((access_secret_id IS NOT NULL AND setup_secret_id IS NULL) OR (access_secret_id IS NULL AND setup_secret_id IS NOT NULL)))
    OR (auth_kind_code = 'console_api_key' AND console_secret_id IS NOT NULL AND access_secret_id IS NULL AND refresh_secret_id IS NULL AND setup_secret_id IS NULL)
  );

ALTER TABLE gateway.credential_enrollment
  DROP CONSTRAINT credential_enrollment_state_code_check,
  DROP CONSTRAINT credential_enrollment_next_action_code_check,
  DROP CONSTRAINT credential_enrollment_check,
  DROP CONSTRAINT credential_enrollment_check1,
  DROP CONSTRAINT credential_enrollment_check2,
  DROP CONSTRAINT credential_enrollment_check3;
UPDATE gateway.credential_enrollment SET
  state_code = CASE state_code
    WHEN 'awaiting_callback' THEN 'awaiting_user_action' WHEN 'exchanging' THEN 'exchanging_material'
    WHEN 'verifying' THEN 'verifying_account' WHEN 'committing' THEN 'activation_check'
    WHEN 'completed' THEN 'succeeded' ELSE state_code END,
  next_action_code = CASE next_action_code
    WHEN 'open_authorization' THEN 'open_authorization_url' WHEN 'submit_callback' THEN 'complete_oauth_callback'
    WHEN 'wait' THEN 'retry' ELSE next_action_code END;
ALTER TABLE gateway.credential_enrollment
  ADD COLUMN auth_method_code text NOT NULL DEFAULT 'oauth_pkce',
  ADD COLUMN pending_credential_id uuid REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  ADD COLUMN egress_binding_id uuid REFERENCES gateway.credential_egress_binding(id) ON DELETE RESTRICT,
  ADD COLUMN egress_epoch bigint,
  ADD COLUMN pkce_verifier_secret_id uuid REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  ADD COLUMN callback_nonce_digest bytea,
  ADD COLUMN identified_account_uuid uuid,
  ADD COLUMN material_secret_refs uuid[] NOT NULL DEFAULT '{}',
  ADD COLUMN attempt_count integer NOT NULL DEFAULT 0,
  ADD COLUMN callback_claimed_at timestamptz,
  ADD COLUMN operation_checkpoint_code text,
  ADD CONSTRAINT credential_enrollment_state_code_check CHECK (state_code IN ('created','resolving_egress','awaiting_user_action','exchanging_material','verifying_account','deduplicating','recovering_existing','provisioning_identity','configuring_reauth','activation_check','succeeded','failed','cancelled','expired')),
  ADD CONSTRAINT credential_enrollment_next_action_code_check CHECK (next_action_code IN ('wait_for_egress','open_authorization_url','submit_setup_material','submit_existing_oauth_material','complete_oauth_callback','complete_browser_login','retry','manual_recovery','none')),
  ADD CONSTRAINT credential_enrollment_auth_method_code_check CHECK (auth_method_code IN ('oauth_pkce','setup_token','existing_oauth','browser_session_import','console_api_key')),
  ADD CONSTRAINT credential_enrollment_egress_epoch_check CHECK (egress_epoch IS NULL OR egress_epoch >= 1),
  ADD CONSTRAINT credential_enrollment_attempt_count_check CHECK (attempt_count >= 0),
  ADD CONSTRAINT credential_enrollment_terminal_action_check CHECK (state_code NOT IN ('succeeded','failed','cancelled','expired') OR next_action_code = 'none'),
  ADD CONSTRAINT credential_enrollment_mode_shape_check CHECK (
    (kind_code = 'create' AND requested_group_id IS NOT NULL AND recover_credential_id IS NULL)
    OR (kind_code = 'recover' AND recover_credential_id IS NOT NULL AND expected_credential_revision IS NOT NULL)
  );
CREATE UNIQUE INDEX credential_enrollment_pending_credential_uq
  ON gateway.credential_enrollment (pending_credential_id) WHERE pending_credential_id IS NOT NULL;

ALTER TABLE catalog.environment_archetype
  ADD COLUMN os_build text,
  ADD COLUMN client_family_code text NOT NULL DEFAULT 'claude_code_cli';
ALTER TABLE catalog.environment_archetype_version
  ADD COLUMN os_build text,
  ADD COLUMN architecture_code text,
  ADD COLUMN client_family_code text NOT NULL DEFAULT 'claude_code_cli',
  ADD COLUMN capture_cohort text,
  ADD COLUMN profile_schema_version integer NOT NULL DEFAULT 1 CHECK (profile_schema_version >= 1);
ALTER TABLE catalog.archetype_capacity_policy
  ADD COLUMN allocation_weight integer NOT NULL DEFAULT 1 CHECK (allocation_weight >= 1),
  ADD COLUMN allocation_cohort text NOT NULL DEFAULT 'default';

ALTER TABLE gateway.proxy_endpoint
  DROP CONSTRAINT proxy_endpoint_proxy_type_code_check,
  DROP CONSTRAINT proxy_endpoint_lifecycle_code_check,
  DROP CONSTRAINT proxy_endpoint_health_code_check,
  DROP CONSTRAINT proxy_endpoint_stability_code_check,
  DROP CONSTRAINT proxy_endpoint_max_active_bindings_check;
UPDATE gateway.proxy_endpoint SET
  proxy_type_code = CASE proxy_type_code WHEN 'connect' THEN 'http_connect' ELSE proxy_type_code END,
  stability_code = CASE stability_code WHEN 'stable' THEN 'static' WHEN 'drifted' THEN 'static' ELSE 'dynamic' END;
ALTER TABLE gateway.proxy_endpoint
  ADD COLUMN consecutive_failures integer NOT NULL DEFAULT 0,
  ADD COLUMN consecutive_successes integer NOT NULL DEFAULT 0,
  ADD COLUMN circuit_open_until timestamptz,
  ADD COLUMN drained_at timestamptz,
  ADD CONSTRAINT proxy_endpoint_proxy_type_code_check CHECK (proxy_type_code IN ('http_connect','socks5')),
  ADD CONSTRAINT proxy_endpoint_lifecycle_code_check CHECK (lifecycle_code IN ('active','draining','disabled','archived')),
  ADD CONSTRAINT proxy_endpoint_health_code_check CHECK (health_code IN ('unknown','healthy','connect_failed','auth_failed','tls_intercepted','egress_mismatch','unhealthy')),
  ADD CONSTRAINT proxy_endpoint_stability_code_check CHECK (stability_code IN ('static','dynamic')),
  ADD CONSTRAINT proxy_endpoint_max_active_bindings_check CHECK (max_active_bindings BETWEEN 1 AND 1000),
  ADD CONSTRAINT proxy_endpoint_probe_streak_check CHECK (consecutive_failures >= 0 AND consecutive_successes >= 0);

ALTER TABLE gateway.credential_egress_binding
  DROP CONSTRAINT credential_egress_binding_lifecycle_code_check;
ALTER TABLE gateway.credential_egress_binding
  ADD COLUMN observed_at timestamptz,
  ADD COLUMN rebound_at timestamptz,
  ADD COLUMN rebind_reason_code text,
  ADD CONSTRAINT credential_egress_binding_lifecycle_code_check CHECK (lifecycle_code IN ('pending','active','transport_unavailable','rebinding','disabled'));
DROP INDEX gateway.egress_binding_proxy_active_idx;
CREATE INDEX egress_binding_proxy_capacity_idx ON gateway.credential_egress_binding (proxy_id)
  WHERE lifecycle_code IN ('pending','active','transport_unavailable','rebinding') AND proxy_id IS NOT NULL;

ALTER TABLE gateway.device_identity ADD COLUMN rebuilt_at timestamptz;
ALTER TABLE gateway.credential_profile
  ADD COLUMN session_derivation_version integer NOT NULL DEFAULT 1 CHECK (session_derivation_version >= 1),
  ADD COLUMN allocation_evidence jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE gateway.credential_profile_change
  ADD COLUMN credential_id uuid REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  ADD COLUMN change_kind_code text NOT NULL DEFAULT 'cohort',
  ADD COLUMN from_device_epoch bigint,
  ADD COLUMN to_device_epoch bigint,
  ADD COLUMN from_egress_epoch bigint,
  ADD COLUMN to_egress_epoch bigint,
  ADD COLUMN audit_event_id uuid,
  ADD COLUMN outbox_message_id uuid,
  ADD CONSTRAINT credential_profile_change_kind_check CHECK (change_kind_code IN ('cohort','egress_rebind','device_rebuild')),
  ADD CONSTRAINT credential_profile_change_device_epoch_check CHECK (from_device_epoch IS NULL OR from_device_epoch >= 1),
  ADD CONSTRAINT credential_profile_change_to_device_epoch_check CHECK (to_device_epoch IS NULL OR to_device_epoch >= 1),
  ADD CONSTRAINT credential_profile_change_egress_epoch_check CHECK (from_egress_epoch IS NULL OR from_egress_epoch >= 1),
  ADD CONSTRAINT credential_profile_change_to_egress_epoch_check CHECK (to_egress_epoch IS NULL OR to_egress_epoch >= 1);

DROP INDEX gateway.maintenance_operation_active_conflict_uq;
ALTER TABLE gateway.maintenance_operation
  DROP CONSTRAINT maintenance_operation_kind_code_check,
  DROP CONSTRAINT maintenance_operation_trigger_code_check,
  DROP CONSTRAINT maintenance_operation_conflict_class_code_check,
  DROP CONSTRAINT maintenance_operation_state_code_check;
UPDATE gateway.maintenance_operation SET
  kind_code = CASE kind_code
    WHEN 'reauth' THEN 'reauthenticate' WHEN 'recover' THEN 'manual_recovery'
    WHEN 'plan_refresh' THEN 'plan_collect' WHEN 'profile_upgrade' THEN 'verify'
    WHEN 'egress_rebind' THEN 'verify' ELSE kind_code END,
  trigger_code = CASE trigger_code
    WHEN 'system' THEN 'scheduled' WHEN 'administrator' THEN 'admin'
    WHEN 'scheduler' THEN 'scheduled' WHEN 'startup' THEN 'scheduled' ELSE trigger_code END,
  conflict_class_code = CASE conflict_class_code
    WHEN 'auth' THEN 'auth_material_write' WHEN 'observation' THEN 'plan_collect'
    WHEN 'profile' THEN 'auth_material_write' WHEN 'egress' THEN 'auth_material_write' ELSE conflict_class_code END,
  state_code = CASE state_code
    WHEN 'scheduled' THEN 'planned' WHEN 'waiting_external' THEN 'running' ELSE state_code END;
ALTER TABLE gateway.maintenance_operation
  ADD COLUMN egress_binding_id uuid REFERENCES gateway.credential_egress_binding(id) ON DELETE RESTRICT,
  ADD COLUMN adapter_version text,
  ADD COLUMN started_at timestamptz,
  ADD COLUMN heartbeat_at timestamptz,
  ADD COLUMN result_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN error_category_code text,
  ADD CONSTRAINT maintenance_operation_kind_code_check CHECK (kind_code IN ('verify','refresh','reauthenticate','manual_recovery','auth_method_migration','plan_collect','browser_health')),
  ADD CONSTRAINT maintenance_operation_trigger_code_check CHECK (trigger_code IN ('enrollment','scheduled','expiry_guard','upstream_401','admin','manual_recovery','strategy_health')),
  ADD CONSTRAINT maintenance_operation_conflict_class_code_check CHECK (conflict_class_code IN ('auth_material_write','plan_collect','browser_health')),
  ADD CONSTRAINT maintenance_operation_state_code_check CHECK (state_code IN ('planned','leased','running','verifying_account','committing','waiting_backoff','waiting_egress','needs_attention','succeeded','failed','cancelled','expired'));
CREATE UNIQUE INDEX maintenance_operation_active_conflict_uq
  ON gateway.maintenance_operation (credential_id, conflict_class_code)
  WHERE state_code IN ('planned','leased','running','verifying_account','committing','waiting_backoff','waiting_egress','needs_attention');
ALTER TABLE gateway.credential_auth_version ADD CONSTRAINT credential_auth_version_operation_fk
  FOREIGN KEY (operation_id) REFERENCES gateway.maintenance_operation(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION gateway.validate_active_auth_version() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE auth_credential uuid;
BEGIN
  IF NEW.active_auth_version_id IS NULL THEN RETURN NEW; END IF;
  SELECT credential_id INTO auth_credential FROM gateway.credential_auth_version WHERE id=NEW.active_auth_version_id;
  IF auth_credential IS DISTINCT FROM NEW.id THEN
    RAISE EXCEPTION 'active auth version must belong to credential' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER credential_active_auth_version_matches
  AFTER INSERT OR UPDATE OF active_auth_version_id ON gateway.anthropic_credential
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gateway.validate_active_auth_version();

ALTER TABLE gateway.auto_reauth_strategy DROP CONSTRAINT auto_reauth_strategy_pkey;
ALTER TABLE gateway.auto_reauth_strategy
  ADD COLUMN id uuid,
  ADD COLUMN strategy_kind_code text NOT NULL DEFAULT 'managed_browser_session',
  ADD COLUMN priority integer NOT NULL DEFAULT 100,
  ADD COLUMN active_material_version_id uuid,
  ADD COLUMN adapter_version text,
  ADD COLUMN next_health_at timestamptz;
UPDATE gateway.auto_reauth_strategy SET id = md5(credential_id::text || ':managed-browser-strategy')::uuid WHERE id IS NULL;
ALTER TABLE gateway.auto_reauth_strategy
  ALTER COLUMN id SET NOT NULL,
  ADD CONSTRAINT auto_reauth_strategy_pkey PRIMARY KEY (id),
  ADD CONSTRAINT auto_reauth_strategy_kind_check CHECK (strategy_kind_code = 'managed_browser_session'),
  ADD CONSTRAINT auto_reauth_strategy_priority_check CHECK (priority >= 0);
CREATE UNIQUE INDEX auto_reauth_strategy_active_kind_uq
  ON gateway.auto_reauth_strategy (credential_id, strategy_kind_code)
  WHERE state_code IN ('pending','healthy','degraded');

ALTER TABLE gateway.managed_browser_material_version
  DROP CONSTRAINT managed_browser_material_version_state_code_check;
ALTER TABLE gateway.managed_browser_material_version
  ADD COLUMN strategy_id uuid,
  ADD COLUMN cookie_secret_id uuid REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  ADD COLUMN storage_secret_id uuid REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  ADD COLUMN profile_secret_id uuid REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  ADD COLUMN verified_account_uuid uuid,
  ADD COLUMN adapter_version text,
  ADD COLUMN expires_at timestamptz,
  ADD COLUMN activated_at timestamptz,
  ADD CONSTRAINT managed_browser_material_version_state_code_check
    CHECK (state_code IN ('candidate','active','superseded','invalid','destroyed'));
UPDATE gateway.managed_browser_material_version material SET
  strategy_id = strategy.id,
  cookie_secret_id = material.secret_id
FROM gateway.auto_reauth_strategy strategy WHERE strategy.credential_id = material.credential_id;
ALTER TABLE gateway.managed_browser_material_version
  ADD CONSTRAINT managed_browser_strategy_fk FOREIGN KEY (strategy_id) REFERENCES gateway.auto_reauth_strategy(id) ON DELETE RESTRICT;
ALTER TABLE gateway.auto_reauth_strategy ADD CONSTRAINT auto_reauth_active_material_fk
  FOREIGN KEY (active_material_version_id) REFERENCES gateway.managed_browser_material_version(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION gateway.validate_browser_material_strategy() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE strategy_credential uuid;
BEGIN
  IF NEW.strategy_id IS NULL THEN RETURN NEW; END IF;
  SELECT credential_id INTO strategy_credential FROM gateway.auto_reauth_strategy WHERE id=NEW.strategy_id;
  IF strategy_credential IS DISTINCT FROM NEW.credential_id THEN
    RAISE EXCEPTION 'browser material and strategy must share credential' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER managed_browser_material_strategy_matches
  AFTER INSERT OR UPDATE OF strategy_id,credential_id ON gateway.managed_browser_material_version
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gateway.validate_browser_material_strategy();

ALTER TABLE telemetry.credential_quota_observation
  DROP CONSTRAINT credential_quota_observation_window_kind_code_check;
ALTER TABLE telemetry.credential_quota_observation
  ADD COLUMN rate_limited_until timestamptz,
  ADD COLUMN confidence_code text NOT NULL DEFAULT 'observed',
  ADD COLUMN header_digest bytea,
  ADD COLUMN parser_version text,
  ADD CONSTRAINT credential_quota_observation_window_kind_code_check CHECK (window_kind_code IN ('five_hour','seven_day','model_specific')),
  ADD CONSTRAINT credential_quota_observation_confidence_code_check CHECK (confidence_code IN ('observed','inferred','unknown'));
ALTER TABLE telemetry.credential_quota_current
  DROP CONSTRAINT credential_quota_current_window_kind_code_check;
ALTER TABLE telemetry.credential_quota_current
  ADD COLUMN rate_limited_until timestamptz,
  ADD COLUMN confidence_code text NOT NULL DEFAULT 'observed',
  ADD CONSTRAINT credential_quota_current_window_kind_code_check CHECK (window_kind_code IN ('five_hour','seven_day','model_specific'));

ALTER TABLE telemetry.subscription_plan_observation
  ADD COLUMN raw_digest bytea,
  ADD COLUMN temporary_display_name text,
  ADD COLUMN normalized_at timestamptz,
  ADD COLUMN attempt_outcome_code text NOT NULL DEFAULT 'success',
  ADD COLUMN failure_category_code text,
  ADD COLUMN failure_summary text,
  ADD COLUMN attempted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ADD COLUMN mapping_version bigint,
  ADD COLUMN adapter_version text,
  ADD CONSTRAINT subscription_plan_attempt_outcome_check CHECK (attempt_outcome_code IN ('success','failed','not_applicable'));
ALTER TABLE telemetry.subscription_plan_current
  ADD COLUMN last_attempted_at timestamptz,
  ADD COLUMN last_refresh_failed boolean NOT NULL DEFAULT false,
  ADD COLUMN last_failure_at timestamptz,
  ADD COLUMN last_failure_category_code text,
  ADD COLUMN temporary_display_name text,
  ADD COLUMN billing_mode_code text,
  ADD CONSTRAINT subscription_plan_billing_mode_check CHECK (billing_mode_code IS NULL OR billing_mode_code IN ('subscription','api_payg'));

CREATE TABLE gateway.credential_lifecycle_event (
  id uuid PRIMARY KEY,
  credential_id uuid REFERENCES gateway.anthropic_credential(id) ON DELETE SET NULL,
  enrollment_id uuid REFERENCES gateway.credential_enrollment(id) ON DELETE RESTRICT,
  operation_id uuid REFERENCES gateway.maintenance_operation(id) ON DELETE RESTRICT,
  event_kind_code text NOT NULL,
  aggregate_revision bigint NOT NULL CHECK (aggregate_revision >= 1),
  token_version bigint CHECK (token_version >= 1),
  profile_epoch bigint CHECK (profile_epoch >= 1),
  device_epoch bigint CHECK (device_epoch >= 1),
  egress_epoch bigint CHECK (egress_epoch >= 1),
  redacted_detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL
);
CREATE INDEX credential_lifecycle_event_aggregate_idx
  ON gateway.credential_lifecycle_event (credential_id, occurred_at, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA gateway, catalog, telemetry TO gateway_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA gateway, catalog, telemetry TO gateway_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA gateway, catalog, telemetry TO gateway_backup;

RESET ROLE;
