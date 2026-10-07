//! `LiteLLM` price catalogue parsing and durable price-version commits.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};

use gateway_domain::{EgressBindingId, EgressBindingSnapshot, EgressMode, ProxyEndpointId, SecretBytes};
use gateway_services::credential_provider::{ProviderHttpHeader, ProviderHttpPort, ProviderHttpRequest};
use gateway_storage::PgStorage;
use http::{Method, Uri};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use uuid::Uuid;

pub const PRICE_SOURCE_URI: &str =
    "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json";
const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCE_ENTRIES: usize = 20_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourcePrice {
    pub model_id: String,
    pub input_per_million: String,
    pub output_per_million: String,
    pub cache_write_per_million: String,
    pub cache_read_per_million: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedPrice {
    pub model_id: Uuid,
    pub source_model_id: String,
    pub input_per_million: String,
    pub output_per_million: String,
    pub cache_write_per_million: String,
    pub cache_read_per_million: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PriceSyncError {
    #[error("price source is too large")]
    TooLarge,
    #[error("price source JSON is invalid")]
    InvalidJson,
    #[error("price source entry is invalid")]
    InvalidEntry,
    #[error("normalized model id is ambiguous: {0}")]
    AmbiguousModel(String),
    #[error("database error")]
    Database,
}

/// Parse only the bounded top-level `LiteLLM` object and retain Anthropic entries.
#[cfg(test)]
pub fn parse_litellm_prices(bytes: &[u8]) -> Result<Vec<SourcePrice>, PriceSyncError> {
    let prices = parse_provider_prices(bytes, "anthropic")?;
    if prices.is_empty() {
        return Err(PriceSyncError::InvalidEntry);
    }
    Ok(prices)
}

fn parse_provider_prices(bytes: &[u8], provider: &str) -> Result<Vec<SourcePrice>, PriceSyncError> {
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
        return Err(PriceSyncError::TooLarge);
    }
    let root: Value = serde_json::from_slice(bytes).map_err(|_| PriceSyncError::InvalidJson)?;
    let object = root.as_object().ok_or(PriceSyncError::InvalidJson)?;
    if object.len() > MAX_SOURCE_ENTRIES {
        return Err(PriceSyncError::TooLarge);
    }
    let mut output = Vec::new();
    for (model_id, value) in object {
        let Some(entry) = value.as_object() else { continue };
        if entry.get("litellm_provider").and_then(Value::as_str) != Some(provider) {
            continue;
        }
        let input = scaled_cost(entry.get("input_cost_per_token").ok_or(PriceSyncError::InvalidEntry)?)?;
        let output_cost = scaled_cost(entry.get("output_cost_per_token").ok_or(PriceSyncError::InvalidEntry)?)?;
        let cache_write = scaled_cost(entry.get("cache_creation_input_token_cost").unwrap_or(&Value::from(0)))?;
        let cache_read = if provider == "openai" && !entry.contains_key("cache_read_input_token_cost") {
            input.clone()
        } else {
            scaled_cost(entry.get("cache_read_input_token_cost").unwrap_or(&Value::from(0)))?
        };
        output.push(SourcePrice {
            model_id: model_id.clone(),
            input_per_million: input,
            output_per_million: output_cost,
            cache_write_per_million: cache_write,
            cache_read_per_million: cache_read,
        });
    }
    Ok(output)
}

/// Convert a JSON decimal/scientific token cost to exact USD per million tokens.
pub fn scaled_cost(value: &Value) -> Result<String, PriceSyncError> {
    let text = match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        _ => return Err(PriceSyncError::InvalidEntry),
    };
    let text = text.trim();
    if text.is_empty() || text.len() > 128 {
        return Err(PriceSyncError::InvalidEntry);
    }
    let exponent_index = text.find(['e', 'E']);
    let (mantissa, exponent) = exponent_index.map_or((text, 0_i32), |index| {
        (&text[..index], text[index + 1..].parse::<i32>().unwrap_or(i32::MIN))
    });
    if exponent == i32::MIN {
        return Err(PriceSyncError::InvalidEntry);
    }
    let (sign, unsigned) = mantissa.strip_prefix('-').map_or(("", mantissa), |value| ("-", value));
    if unsigned.is_empty() || unsigned.starts_with('+') {
        return Err(PriceSyncError::InvalidEntry);
    }
    let mut parts = unsigned.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || whole.is_empty() && fraction.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PriceSyncError::InvalidEntry);
    }
    let digits = format!("{whole}{fraction}");
    let decimal_pos = i32::try_from(whole.len()).unwrap_or(i32::MAX) + exponent + 6;
    let mut result = if decimal_pos <= 0 {
        format!(
            "0.{}{}",
            "0".repeat(usize::try_from(-decimal_pos).unwrap_or(128)),
            digits
        )
    } else if usize::try_from(decimal_pos).unwrap_or(usize::MAX) >= digits.len() {
        format!(
            "{}{}",
            digits,
            "0".repeat(usize::try_from(decimal_pos).unwrap_or(128).saturating_sub(digits.len()))
        )
    } else {
        let point = usize::try_from(decimal_pos).map_err(|_| PriceSyncError::InvalidEntry)?;
        format!("{}.{}", &digits[..point], &digits[point..])
    };
    if let Some((whole, fraction)) = result.split_once('.') {
        result = format!(
            "{}.{}",
            whole.trim_start_matches('0').if_empty_then("0"),
            fraction.trim_end_matches('0')
        );
        if result.ends_with('.') {
            result.pop();
        }
    } else {
        result = result.trim_start_matches('0').if_empty_then("0").to_owned();
    }
    if sign == "-" && result != "0" {
        return Err(PriceSyncError::InvalidEntry);
    }
    Ok(result)
}

trait EmptyThen {
    fn if_empty_then<'a>(&'a self, fallback: &'a str) -> &'a str;
}
impl EmptyThen for str {
    fn if_empty_then<'a>(&'a self, fallback: &'a str) -> &'a str {
        if self.is_empty() { fallback } else { self }
    }
}

fn candidates(id: &str) -> BTreeSet<String> {
    let stripped = id.trim().strip_prefix("anthropic/").unwrap_or(id.trim());
    let base = stripped.to_ascii_lowercase().replace('_', "-");
    let mut values = BTreeSet::from([base.clone()]);
    if let Some((prefix, suffix)) = base.rsplit_once('-')
        && ((suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_digit()))
            || (suffix.len() == 10
                && suffix.as_bytes().get(4) == Some(&b'-')
                && suffix.as_bytes().get(7) == Some(&b'-')))
    {
        values.insert(prefix.to_owned());
    }
    values
}

/// Map source IDs to catalog IDs, rejecting normalized collisions.
pub fn map_prices(
    source: &[SourcePrice],
    catalog: &[(Uuid, String)],
) -> Result<(Vec<MappedPrice>, Vec<String>), PriceSyncError> {
    let mut index = BTreeMap::<String, (Uuid, String)>::new();
    for (id, name) in catalog {
        for candidate in candidates(name) {
            if let Some(previous) = index.insert(candidate.clone(), (*id, name.clone()))
                && previous.0 != *id
            {
                return Err(PriceSyncError::AmbiguousModel(candidate));
            }
        }
    }
    let mut mapped = Vec::new();
    let mut seen = BTreeSet::new();
    for price in source {
        let found = candidates(&price.model_id)
            .into_iter()
            .find_map(|key| index.get(&key).cloned());
        if let Some((model_id, _)) = found
            && seen.insert(model_id)
        {
            mapped.push(MappedPrice {
                model_id,
                source_model_id: price.model_id.clone(),
                input_per_million: price.input_per_million.clone(),
                output_per_million: price.output_per_million.clone(),
                cache_write_per_million: price.cache_write_per_million.clone(),
                cache_read_per_million: price.cache_read_per_million.clone(),
            });
        }
    }
    let missing = catalog
        .iter()
        .filter(|(id, _)| !seen.contains(id))
        .map(|(_, name)| name.clone())
        .collect();
    Ok((mapped, missing))
}

pub async fn commit_prices(
    storage: &PgStorage,
    source_bytes: &[u8],
    source_uri: &str,
) -> Result<(i64, usize, Vec<String>, String), PriceSyncError> {
    let source = parse_provider_prices(source_bytes, "anthropic")?;
    let catalog_rows = sqlx::query(
        "SELECT id,upstream_model_id FROM catalog.model_definition WHERE provider_code='anthropic' AND lifecycle_code IN ('published','deprecated')",
    )
    .fetch_all(&storage.pool())
    .await
    .map_err(|_| PriceSyncError::Database)?;
    let catalog = catalog_rows
        .iter()
        .map(|row| {
            (
                row.try_get("id").unwrap_or_else(|_| Uuid::nil()),
                row.try_get("upstream_model_id").unwrap_or_default(),
            )
        })
        .collect::<Vec<(Uuid, String)>>();
    let (mut mapped, mut missing) = map_prices(&source, &catalog)?;
    let openai_prices = parse_provider_prices(source_bytes, "openai")?;
    let openai_models=sqlx::query("SELECT id,upstream_model_id FROM catalog.model_definition WHERE provider_code='openai' AND lifecycle_code IN ('published','deprecated')").fetch_all(&storage.pool()).await.map_err(|_|PriceSyncError::Database)?;
    for row in openai_models {
        let id: Uuid = row.try_get("id").map_err(|_| PriceSyncError::Database)?;
        let name: String = row.try_get("upstream_model_id").map_err(|_| PriceSyncError::Database)?;
        if let Some(price) = openai_prices
            .iter()
            .find(|p| p.model_id.strip_prefix("openai/").unwrap_or(&p.model_id) == name)
        {
            mapped.push(MappedPrice {
                model_id: id,
                source_model_id: price.model_id.clone(),
                input_per_million: price.input_per_million.clone(),
                output_per_million: price.output_per_million.clone(),
                cache_write_per_million: price.cache_write_per_million.clone(),
                cache_read_per_million: price.cache_read_per_million.clone(),
            });
        } else {
            missing.push(name);
        }
    }
    if mapped.is_empty() {
        return Err(PriceSyncError::InvalidEntry);
    }
    let hash = Sha256::digest(source_bytes);
    let hash_hex = format!("{hash:x}");
    let hash = hash.to_vec();
    let mut tx = storage.pool().begin().await.map_err(|_| PriceSyncError::Database)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('catalog:price-version'))")
        .execute(&mut *tx)
        .await
        .map_err(|_| PriceSyncError::Database)?;
    let prior: Option<Vec<u8>> = sqlx::query_scalar("SELECT source_hash FROM ops.price_sync_state WHERE id=true")
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PriceSyncError::Database)?;
    if prior.as_deref() == Some(hash.as_slice()) {
        let version =
            sqlx::query_scalar("SELECT COALESCE(created_price_version,0) FROM ops.price_sync_state WHERE id=true")
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| PriceSyncError::Database)?;
        tx.commit().await.map_err(|_| PriceSyncError::Database)?;
        return Ok((version, 0, missing, hash_hex));
    }
    sqlx::query(
        "UPDATE catalog.price_entry SET effective_to=clock_timestamp() WHERE model_id=ANY($1) AND effective_to IS NULL",
    )
    .bind(mapped.iter().map(|entry| entry.model_id).collect::<Vec<_>>())
    .execute(&mut *tx)
    .await
    .map_err(|_| PriceSyncError::Database)?;
    let version: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(price_version),0)+1 FROM catalog.price_version")
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| PriceSyncError::Database)?;
    sqlx::query("INSERT INTO catalog.price_version (price_version,currency_code,effective_from,effective_to,source_uri,content_hash,created_by,created_at) VALUES ($1,'USD',clock_timestamp(),NULL,$2,$3,NULL,clock_timestamp())")
        .bind(version).bind(source_uri).bind(&hash).execute(&mut *tx).await.map_err(|_| PriceSyncError::Database)?;
    for entry in &mapped {
        sqlx::query("INSERT INTO catalog.price_entry (id,model_id,price_version,currency_code,input_per_million,output_per_million,cache_write_per_million,cache_read_per_million,effective_from,effective_to,source_uri,content_hash,created_at) VALUES ($1,$2,$3,'USD',$4,$5,$6,$7,clock_timestamp(),NULL,$8,$9,clock_timestamp())")
            .bind(Uuid::now_v7()).bind(entry.model_id).bind(version).bind(&entry.input_per_million).bind(&entry.output_per_million).bind(&entry.cache_write_per_million).bind(&entry.cache_read_per_million).bind(source_uri).bind(&hash).execute(&mut *tx).await.map_err(|_| PriceSyncError::Database)?;
    }
    sqlx::query("UPDATE ops.price_sync_state SET last_completed_at=clock_timestamp(),state_code='succeeded',result_code='updated',source_hash=$1,created_price_version=$2,mapped_count=$3,missing_models=$4,updated_at=clock_timestamp() WHERE id=true")
        .bind(&hash).bind(version).bind(i32::try_from(mapped.len()).unwrap_or(i32::MAX)).bind(json!(missing)).execute(&mut *tx).await.map_err(|_| PriceSyncError::Database)?;
    tx.commit().await.map_err(|_| PriceSyncError::Database)?;
    Ok((version, mapped.len(), missing, hash_hex))
}

pub async fn enqueue_job(storage: &PgStorage, trigger: &str) -> Result<(Uuid, bool), sqlx::Error> {
    if let Some(id) = sqlx::query_scalar("SELECT id FROM ops.durable_job WHERE kind_code='price_sync' AND state_code IN ('scheduled','leased','retry_wait') ORDER BY created_at LIMIT 1").fetch_optional(&storage.pool()).await? { return Ok((id, false)); }
    let id = Uuid::now_v7();
    let bucket = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() / 60);
    let mut transaction = storage.pool().begin().await?;
    let inserted = sqlx::query("INSERT INTO ops.durable_job (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) VALUES ($1,'price_sync',$2,'scheduled',1,$3,clock_timestamp(),0,0,6,clock_timestamp(),clock_timestamp()) ON CONFLICT (kind_code,idempotency_key) DO NOTHING")
        .bind(id).bind(format!("price-sync-{trigger}-{bucket}")).bind(json!({"trigger":trigger,"source_uri":PRICE_SOURCE_URI})).execute(&mut *transaction).await?;
    if inserted.rows_affected() == 0 {
        let existing: Uuid = sqlx::query_scalar("SELECT id FROM ops.durable_job WHERE kind_code='price_sync' AND state_code IN ('scheduled','leased','retry_wait') ORDER BY created_at LIMIT 1").fetch_one(&mut *transaction).await?;
        transaction.commit().await?;
        return Ok((existing, false));
    }
    sqlx::query("INSERT INTO ops.durable_job_history (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) VALUES ($1,$2,NULL,'scheduled',0,'price_sync_scheduled',jsonb_build_object('trigger',$3),clock_timestamp())")
        .bind(Uuid::now_v7()).bind(id).bind(trigger).execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok((id, true))
}

pub async fn fetch_and_commit(
    storage: &PgStorage,
    http: &dyn ProviderHttpPort,
) -> Result<(i64, usize, Vec<String>, String), PriceSyncError> {
    let row = sqlx::query(
        "SELECT id,mode_code,proxy_id,egress_epoch FROM gateway.credential_egress_binding \
         WHERE lifecycle_code='active' AND stability_code='stable' ORDER BY updated_at DESC LIMIT 1",
    )
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| PriceSyncError::Database)?
    .ok_or(PriceSyncError::Database)?;
    let binding_id: Uuid = row.try_get("id").map_err(|_| PriceSyncError::Database)?;
    let mode: String = row.try_get("mode_code").map_err(|_| PriceSyncError::Database)?;
    let proxy_id: Option<Uuid> = row.try_get("proxy_id").map_err(|_| PriceSyncError::Database)?;
    let egress_epoch: i64 = row.try_get("egress_epoch").map_err(|_| PriceSyncError::Database)?;
    let snapshot = EgressBindingSnapshot {
        binding_id: EgressBindingId::new(binding_id.to_string()).map_err(|_| PriceSyncError::Database)?,
        mode: if mode == "direct" {
            EgressMode::Direct
        } else {
            EgressMode::Proxy
        },
        proxy_id: proxy_id
            .map(|id| ProxyEndpointId::new(id.to_string()))
            .transpose()
            .map_err(|_| PriceSyncError::Database)?,
        egress_epoch: u64::try_from(egress_epoch).map_err(|_| PriceSyncError::Database)?,
    };
    let response = http
        .execute(ProviderHttpRequest {
            method: Method::GET,
            endpoint: PRICE_SOURCE_URI
                .parse::<Uri>()
                .map_err(|_| PriceSyncError::InvalidEntry)?,
            headers: vec![ProviderHttpHeader {
                name: "accept",
                value: SecretBytes::new(b"application/json".to_vec()),
            }],
            body: SecretBytes::new(Vec::new()),
            response_limit: MAX_SOURCE_BYTES,
            egress: snapshot,
        })
        .await
        .map_err(|_| PriceSyncError::Database)?;
    if !(200..300).contains(&response.status) {
        return Err(PriceSyncError::Database);
    }
    commit_prices(storage, response.body.expose(), PRICE_SOURCE_URI).await
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "price fixtures must parse successfully")]
mod tests {
    use super::{PriceSyncError, map_prices, parse_litellm_prices, scaled_cost};
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn scaled_cost_converts_token_prices_without_float_rounding() {
        assert_eq!(scaled_cost(&json!(0.000_001)).expect("cost"), "1");
        assert_eq!(scaled_cost(&json!("1.25e-6")).expect("cost"), "1.25");
        assert_eq!(scaled_cost(&json!("0.000000000001")).expect("cost"), "0.000001");
        assert!(matches!(scaled_cost(&json!(-1)), Err(PriceSyncError::InvalidEntry)));
        assert!(matches!(scaled_cost(&json!(null)), Err(PriceSyncError::InvalidEntry)));
    }

    #[test]
    fn parser_filters_non_anthropic_and_reads_cache_fields() {
        let source = json!({
            "anthropic/claude-3-20240229": {
                "litellm_provider": "anthropic",
                "input_cost_per_token": 0.000_003,
                "output_cost_per_token": "0.000015",
                "cache_creation_input_token_cost": 0.000_003_75,
                "cache_read_input_token_cost": 0.000_000_3
            },
            "openai/gpt-4o": {
                "litellm_provider": "openai",
                "input_cost_per_token": 1
            }
        });
        let prices = parse_litellm_prices(source.to_string().as_bytes()).expect("prices");
        assert_eq!(prices.len(), 1);
        assert_eq!(prices[0].model_id, "anthropic/claude-3-20240229");
        assert_eq!(prices[0].input_per_million, "3");
        assert_eq!(prices[0].output_per_million, "15");
        assert_eq!(prices[0].cache_write_per_million, "3.75");
        assert_eq!(prices[0].cache_read_per_million, "0.3");
    }

    #[test]
    fn mapping_handles_provider_prefix_and_date_aliases_and_reports_missing() {
        let id = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        let source = vec![super::SourcePrice {
            model_id: "anthropic/claude-3-20240229".into(),
            input_per_million: "1".into(),
            output_per_million: "2".into(),
            cache_write_per_million: "0".into(),
            cache_read_per_million: "0".into(),
        }];
        let (mapped, missing) =
            map_prices(&source, &[(id, "claude-3".into()), (other, "claude-2".into())]).expect("mapping");
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].model_id, id);
        assert_eq!(missing, vec!["claude-2".to_owned()]);
    }

    #[test]
    fn ambiguous_catalog_alias_is_rejected() {
        let source = vec![];
        let result = map_prices(
            &source,
            &[
                (Uuid::from_u128(1), "claude-3".into()),
                (Uuid::from_u128(2), "anthropic/claude-3".into()),
            ],
        );
        assert!(matches!(result, Err(PriceSyncError::AmbiguousModel(_))));
    }
}
