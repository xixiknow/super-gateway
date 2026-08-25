#![forbid(unsafe_code)]
//! Real `PostgreSQL` R7 request/commit/usage contract.

use gateway_domain::{
    CostEstimate, DeliveryOutcome, PriceSnapshot, ResponseMode, SecretValue, TokenCounts, UsageCompleteness,
    UsageObservation, UsageSource,
};
use gateway_storage::{
    CancelEstimateEvidencePersist, CostPersist, DeliveryComplete, DeliveryStart, PgStorage, QuotaObservationPersist,
    RequestCreate, RuntimeRolePolicy, StorageError, SubmissionIntentArm, UsagePersist, embedded_migration_count,
};
use uuid::Uuid;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn telemetry_r7_commit_usage_and_single_terminal_contract() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let Ok(database_url) = std::env::var("TEST_R7_DATABASE_ADMIN_URL") else {
        return Ok(());
    };
    let database_url = SecretValue::new(database_url);
    let report = PgStorage::migrate(&database_url).await?;
    assert_eq!(report.applied_count, embedded_migration_count());
    let storage = PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?;
    storage.ensure_database_business_key().await?;

    let user_id = Uuid::now_v7();
    let group_id = Uuid::now_v7();
    let secret_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    let credential_id = Uuid::now_v7();
    let bundle_id = Uuid::now_v7();
    let model_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO iam.user_account \
         (id,username,username_normalized,role_code,status_code,revision,created_at,updated_at) \
         VALUES ($1,$2,$2,'key_owner','active',1,clock_timestamp(),clock_timestamp())",
    )
    .bind(user_id)
    .bind(format!("r7-owner-{user_id}"))
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO catalog.model_definition \
         (id,upstream_model_id,display_name,lifecycle_code,first_seen_at,last_seen_at,revision) \
         VALUES ($1,$2,$3,'published',clock_timestamp(),clock_timestamp(),1)",
    )
    .bind(model_id)
    .bind(format!("claude-r7-{model_id}"))
    .bind("Claude R7 fixture")
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO gateway.credential_group \
         (id,owner_executor_id,owner_generation,name,status_code,revision,created_by,created_at,updated_at) \
         VALUES ($1,'r7-executor',1,$2,'active',1,$3,clock_timestamp(),clock_timestamp())",
    )
    .bind(group_id)
    .bind(format!("r7-group-{group_id}"))
    .bind(user_id)
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO security.encrypted_secret \
         (id,secret_kind_code,provider_role_code,ciphertext,nonce,wrapped_dek,key_version,aad_schema_version, \
          owner_type_code,owner_id,purpose_code,created_at) \
         VALUES ($1,'platform_key','business',$2,$3,$4,1,1,'platform_key',$5,'authentication',clock_timestamp())",
    )
    .bind(secret_id)
    .bind(vec![1_u8; 32])
    .bind(vec![2_u8; 12])
    .bind(vec![3_u8; 32])
    .bind(key_id.to_string())
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO iam.platform_key \
         (id,owner_user_id,group_id,name,secret_id,status_code,revision,created_at,updated_at) \
         VALUES ($1,$2,$3,$4,$5,'active',1,clock_timestamp(),clock_timestamp())",
    )
    .bind(key_id)
    .bind(user_id)
    .bind(group_id)
    .bind(format!("r7-key-{key_id}"))
    .bind(secret_id)
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO gateway.anthropic_credential \
         (id,group_id,purpose_code,auth_kind_code,lifecycle_state_code,auth_state_code,scheduling_state_code, \
          quota_state_code,transport_state_code,management_class_code,token_version,revision,created_at,updated_at) \
         VALUES ($1,$2,'business','oauth_subscription','pending_profile','healthy','blocked','unknown','transport_unavailable', \
                 'non_managed',1,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(credential_id)
    .bind(group_id)
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO catalog.transport_bundle \
         (id,artifact_version,engine_abi_version,lifecycle_code,manifest,manifest_hash,signature,signing_key_id,object_uri,created_at) \
         VALUES ($1,7001,'r6-v1','draft','{}'::jsonb,$2,$3,'r7-fixture','fixture://r7',clock_timestamp())",
    )
    .bind(bundle_id)
    .bind(Uuid::now_v7().as_bytes().to_vec())
    .bind(vec![4_u8; 64])
    .execute(&storage.pool())
    .await?;

    let reset_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .saturating_add(3_600);
    let quota = storage
        .persist_credential_quota_observations(
            credential_id,
            &[
                QuotaObservationPersist {
                    observation_id: Uuid::now_v7(),
                    window_kind_code: "five_hour".into(),
                    utilization_nanos: 950_000_000,
                    reset_epoch_seconds: reset_epoch,
                    header_digest: vec![6_u8; 32],
                    parser_version: "fixture-v1".into(),
                },
                QuotaObservationPersist {
                    observation_id: Uuid::now_v7(),
                    window_kind_code: "seven_day".into(),
                    utilization_nanos: 500_000_000,
                    reset_epoch_seconds: reset_epoch.saturating_add(3_600),
                    header_digest: vec![7_u8; 32],
                    parser_version: "fixture-v1".into(),
                },
            ],
        )
        .await?
        .ok_or("quota projection")?;
    assert_eq!(quota.used_basis_points, 9_500);
    let stale_projection = storage
        .persist_credential_quota_observations(
            credential_id,
            &[QuotaObservationPersist {
                observation_id: Uuid::nil(),
                window_kind_code: "five_hour".into(),
                utilization_nanos: 100_000_000,
                reset_epoch_seconds: reset_epoch,
                header_digest: vec![8_u8; 32],
                parser_version: "fixture-v1".into(),
            }],
        )
        .await?
        .ok_or("stale quota projection")?;
    assert_eq!(stale_projection.used_basis_points, 9_500);
    let quota_counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM telemetry.credential_quota_observation WHERE credential_id=$1), \
                (SELECT COUNT(*) FROM telemetry.credential_quota_current WHERE credential_id=$1)",
    )
    .bind(credential_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(quota_counts, (3, 2));

    let request_id = Uuid::now_v7();
    storage
        .create_request_after_auth(&RequestCreate {
            request_id,
            platform_key_id: key_id,
            group_id,
            owner_executor_id: "r7-executor".into(),
            owner_generation: 1,
            endpoint_code: "messages".into(),
            client_class_code: "claude_code_cli".into(),
            model_id: Some(model_id),
            request_body_bytes: 123,
            response_mode: ResponseMode::NonStreaming,
        })
        .await?;
    storage
        .advance_request_phase(request_id, "accepted", "validated")
        .await?;
    assert!(matches!(
        storage.advance_request_phase(request_id, "accepted", "queued").await,
        Err(StorageError::RevisionConflict)
    ));

    let intent_id = Uuid::now_v7();
    storage
        .arm_submission_intent(&SubmissionIntentArm {
            intent_id,
            request_id,
            ordinal: 1,
            credential_id,
            token_version: 1,
            profile_epoch: 1,
            egress_epoch: 1,
            transport_bundle_id: bundle_id,
            generic_adjusted_request_hash: vec![5_u8; 32],
        })
        .await?;
    storage.promote_submission_intent(intent_id, 1).await?;
    assert!(matches!(
        storage.promote_submission_intent(intent_id, 2).await,
        Err(StorageError::RevisionConflict)
    ));
    let attempt_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO telemetry.attempt_record \
         (id,request_month,request_id,ordinal,submission_intent_id,credential_id,token_version,profile_epoch, \
          egress_epoch,transport_bundle_id,reason_code,state_code,is_final,submitted_at,http_status) \
         SELECT $1,request_month,request_id,1,$3,$4,1,1,1,$5,'initial','receiving',false,clock_timestamp(),200 \
         FROM telemetry.request_record WHERE request_id=$2",
    )
    .bind(attempt_id)
    .bind(request_id)
    .bind(intent_id)
    .bind(credential_id)
    .bind(bundle_id)
    .execute(&storage.pool())
    .await?;

    let delivery_id = Uuid::now_v7();
    storage
        .start_response_delivery(&DeliveryStart {
            delivery_id,
            request_id,
            attempt_id: None,
            streaming: false,
            buffer_tier_code: Some("memory".into()),
            client_write_idle_ms: 120_000,
        })
        .await?;
    storage
        .observe_delivery_upstream_bytes(request_id, delivery_id, 777)
        .await?;
    storage.commit_client_response(request_id, delivery_id).await?;
    assert!(matches!(
        storage.commit_client_response(request_id, delivery_id).await,
        Err(StorageError::RevisionConflict)
    ));
    storage
        .complete_response_delivery(&DeliveryComplete {
            delivery_id,
            outcome: DeliveryOutcome::Complete,
            response_committed: true,
            upstream_bytes_received: 321,
            bytes_delivered: 321,
            peak_backpressure_bytes: 0,
            spill_bytes: 0,
        })
        .await?;
    let upstream_bytes: i64 =
        sqlx::query_scalar("SELECT upstream_bytes_received FROM telemetry.response_delivery_record WHERE id=$1")
            .bind(delivery_id)
            .fetch_one(&storage.pool())
            .await?;
    assert_eq!(upstream_bytes, 777);

    let observation_id = Uuid::now_v7();
    let observation = UsageObservation::new(
        UsageSource::Official,
        UsageCompleteness::Partial,
        TokenCounts {
            input_tokens: Some(100),
            output_tokens: None,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        None,
    )?;
    storage
        .append_usage(
            &UsagePersist {
                observation_id,
                request_id,
                attempt_id: Some(attempt_id),
                model_id: Some(model_id),
                observation,
                select_as_final: true,
                selection_reason_code: Some("official_partial".into()),
                cancel_evidence: None,
            },
            Some(&CostPersist {
                cost_id: Uuid::now_v7(),
                usage_observation_id: observation_id,
                price_entry_id: None,
                price_snapshot: PriceSnapshot {
                    input_per_million_pico_usd: 3_000_000_000_000,
                    output_per_million_pico_usd: 15_000_000_000_000,
                    cache_creation_per_million_pico_usd: 0,
                    cache_read_per_million_pico_usd: 0,
                },
                estimate: CostEstimate {
                    amount_usd: Some("0.000300000000".into()),
                    usage_completeness: UsageCompleteness::Partial,
                    algorithm_version: "price-v1".into(),
                },
                amount_pico_usd: Some("300000000".into()),
                known_field_mask: 1,
            }),
        )
        .await?;

    let initial_aggregate: (i64, Option<i64>, Option<i64>, Option<String>, String, i64) = sqlx::query_as(
        "SELECT h.request_count,h.input_tokens,h.output_tokens,h.estimated_amount::text,h.completeness_code, \
                (SELECT COUNT(*) FROM telemetry.usage_aggregate_contribution WHERE request_id=$1) \
         FROM telemetry.usage_hourly h WHERE h.platform_key_id=$2 AND h.group_id=$3 \
          AND h.credential_id=$4 AND h.model_id=$5",
    )
    .bind(request_id)
    .bind(key_id)
    .bind(group_id)
    .bind(credential_id)
    .bind(model_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(
        initial_aggregate,
        (
            1,
            Some(100),
            None,
            Some("0.000300000000".to_owned()),
            "partial".to_owned(),
            1
        )
    );

    let cancel_observation_id = Uuid::now_v7();
    let cancel_record = UsagePersist {
        observation_id: cancel_observation_id,
        request_id,
        attempt_id: Some(attempt_id),
        model_id: Some(model_id),
        observation: UsageObservation::new(
            UsageSource::CancelEstimate,
            UsageCompleteness::Partial,
            TokenCounts {
                input_tokens: Some(110),
                output_tokens: Some(5),
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            Some("cancel-boundary-v1".into()),
        )?,
        select_as_final: true,
        selection_reason_code: Some("cancel_estimate".into()),
        cancel_evidence: Some(CancelEstimateEvidencePersist {
            input_basis_digest: [0x33; 32],
            sse_complete_event_ordinal: Some(4),
            sse_content_event_ordinal: Some(2),
            sse_decoded_end_offset: Some(512),
            sse_last_event_type: Some("content_block_delta".into()),
            sse_gap: Some(false),
        }),
    };
    storage
        .append_usage(
            &cancel_record,
            Some(&CostPersist {
                cost_id: Uuid::now_v7(),
                usage_observation_id: cancel_observation_id,
                price_entry_id: None,
                price_snapshot: PriceSnapshot {
                    input_per_million_pico_usd: 3_000_000_000_000,
                    output_per_million_pico_usd: 15_000_000_000_000,
                    cache_creation_per_million_pico_usd: 0,
                    cache_read_per_million_pico_usd: 0,
                },
                estimate: CostEstimate {
                    amount_usd: Some("0.000405000000".into()),
                    usage_completeness: UsageCompleteness::Partial,
                    algorithm_version: "estimated-api-value-v1".into(),
                },
                amount_pico_usd: Some("405000000".into()),
                known_field_mask: 3,
            }),
        )
        .await?;
    let cancel_cost: (bool, String, i64, bool) = sqlx::query_as(
        "SELECT c.is_current,c.amount::text,u.sse_complete_event_ordinal,u.sse_gap \
         FROM telemetry.usage_observation u JOIN telemetry.cost_estimate c ON c.usage_observation_id=u.id \
         WHERE u.id=$1",
    )
    .bind(cancel_observation_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(cancel_cost, (false, "0.000405000000".to_owned(), 4, false));

    let mut duplicate_cancel = cancel_record.clone();
    duplicate_cancel.observation_id = Uuid::now_v7();
    storage.append_usage(&duplicate_cancel, None).await?;
    let cancel_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM telemetry.usage_observation WHERE request_id=$1 \
         AND source_code='cancel_estimate' AND algorithm_version='cancel-boundary-v1'",
    )
    .bind(request_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(cancel_count, 1);

    let mut conflicting_cancel = duplicate_cancel.clone();
    conflicting_cancel.observation.counts.output_tokens = Some(6);
    assert!(matches!(
        storage.append_usage(&conflicting_cancel, None).await,
        Err(StorageError::RevisionConflict)
    ));
    let preserved_output_tokens: Option<i64> = sqlx::query_scalar(
        "SELECT output_tokens FROM telemetry.usage_observation WHERE request_id=$1 \
         AND source_code='cancel_estimate' AND algorithm_version='cancel-boundary-v1'",
    )
    .bind(request_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(preserved_output_tokens, Some(5));

    storage
        .append_usage(
            &UsagePersist {
                observation_id: Uuid::now_v7(),
                request_id,
                attempt_id: Some(attempt_id),
                model_id: Some(model_id),
                observation: UsageObservation::new(
                    UsageSource::Official,
                    UsageCompleteness::Partial,
                    TokenCounts {
                        input_tokens: Some(777),
                        output_tokens: None,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    },
                    None,
                )?,
                select_as_final: true,
                selection_reason_code: Some("same_rank_not_stronger".into()),
                cancel_evidence: None,
            },
            None,
        )
        .await?;

    storage
        .append_usage(
            &UsagePersist {
                observation_id: Uuid::now_v7(),
                request_id,
                attempt_id: Some(attempt_id),
                model_id: Some(model_id),
                observation: UsageObservation::new(
                    UsageSource::LocalEstimate,
                    UsageCompleteness::Complete,
                    TokenCounts {
                        input_tokens: Some(999),
                        output_tokens: Some(999),
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    },
                    Some("local-v1".into()),
                )?,
                select_as_final: true,
                selection_reason_code: Some("local_estimate".into()),
                cancel_evidence: None,
            },
            None,
        )
        .await?;

    let unchanged_aggregate: (i64, Option<i64>, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT request_count,input_tokens,output_tokens,estimated_amount::text \
         FROM telemetry.usage_hourly WHERE platform_key_id=$1 AND group_id=$2 AND credential_id=$3 AND model_id=$4",
    )
    .bind(key_id)
    .bind(group_id)
    .bind(credential_id)
    .bind(model_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(
        unchanged_aggregate,
        (1, Some(100), None, Some("0.000300000000".to_owned()))
    );

    let stronger_observation_id = Uuid::now_v7();
    storage
        .append_usage(
            &UsagePersist {
                observation_id: stronger_observation_id,
                request_id,
                attempt_id: Some(attempt_id),
                model_id: Some(model_id),
                observation: UsageObservation::new(
                    UsageSource::Official,
                    UsageCompleteness::Partial,
                    TokenCounts {
                        input_tokens: Some(100),
                        output_tokens: Some(20),
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    },
                    None,
                )?,
                select_as_final: true,
                selection_reason_code: Some("official_partial".into()),
                cancel_evidence: None,
            },
            Some(&CostPersist {
                cost_id: Uuid::now_v7(),
                usage_observation_id: stronger_observation_id,
                price_entry_id: None,
                price_snapshot: PriceSnapshot {
                    input_per_million_pico_usd: 3_000_000_000_000,
                    output_per_million_pico_usd: 15_000_000_000_000,
                    cache_creation_per_million_pico_usd: 0,
                    cache_read_per_million_pico_usd: 0,
                },
                estimate: CostEstimate {
                    amount_usd: Some("0.000600000000".into()),
                    usage_completeness: UsageCompleteness::Partial,
                    algorithm_version: "price-v1".into(),
                },
                amount_pico_usd: Some("600000000".into()),
                known_field_mask: 3,
            }),
        )
        .await?;

    let replaced_aggregate: (i64, Option<i64>, Option<i64>, Option<String>, i64, i64) = sqlx::query_as(
        "SELECT h.request_count,h.input_tokens,h.output_tokens,h.estimated_amount::text, \
                (SELECT COUNT(*) FROM telemetry.usage_daily d WHERE d.platform_key_id=$1 AND d.group_id=$2 \
                  AND d.credential_id=$3 AND d.model_id=$4), \
                (SELECT COUNT(*) FROM telemetry.usage_aggregate_contribution c WHERE c.request_id=$5) \
         FROM telemetry.usage_hourly h WHERE h.platform_key_id=$1 AND h.group_id=$2 \
          AND h.credential_id=$3 AND h.model_id=$4",
    )
    .bind(key_id)
    .bind(group_id)
    .bind(credential_id)
    .bind(model_id)
    .bind(request_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(
        replaced_aggregate,
        (1, Some(100), Some(20), Some("0.000600000000".to_owned()), 1, 1)
    );

    let row: (String, String, String, i64, bool, Option<String>, bool, bool) = sqlx::query_as(
        "SELECT r.client_commit_state_code,d.outcome_code,u.completeness_code,d.bytes_delivered,u.is_final_basis, \
                r.usage_completeness_code,d.usage_observation_complete,c.is_current \
         FROM telemetry.request_record r \
         JOIN telemetry.response_delivery_record d ON d.request_id=r.request_id \
         JOIN telemetry.usage_observation u ON u.request_id=r.request_id AND u.is_final_basis \
         JOIN telemetry.cost_estimate c ON c.request_id=r.request_id AND c.is_current \
         WHERE r.request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(
        row,
        (
            "committed".to_owned(),
            "complete".to_owned(),
            "partial".to_owned(),
            321,
            true,
            Some("partial".to_owned()),
            false,
            true
        )
    );
    Ok(())
}
