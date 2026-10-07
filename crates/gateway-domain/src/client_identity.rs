//! Display-only identity from the incoming client, independent of authentication.

/// Client product and version advertised by the caller, not the upstream profile.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientIdentity {
    /// Product name, when present in User-Agent.
    pub name: Option<String>,
    /// Advertised product version, never inferred from request content.
    pub version: Option<String>,
}

impl ClientIdentity {
    /// Extract a bounded product/version pair without retaining the full User-Agent.
    #[must_use]
    pub fn from_user_agent(user_agent: Option<&str>) -> Self {
        let Some(ua) = user_agent else {
            return Self::default();
        };
        let products: Vec<_> = ua
            .split_ascii_whitespace()
            .filter_map(|word| {
                let (name, version) = word.split_once('/')?;
                if name.is_empty()
                    || name.len() > 80
                    || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                {
                    return None;
                }
                let version = version.trim_end_matches([';', ')', ',']);
                let version = (!version.is_empty()
                    && version.len() <= 80
                    && version
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b)))
                .then(|| version.to_owned());
                Some((name, version))
            })
            .collect();
        let known = |name: &str| match name.to_ascii_lowercase().as_str() {
            "claude-cli" | "claude-code" => Some("Claude Code"),
            "codex_cli_rs" | "codex-cli" | "codex" => Some("Codex"),
            _ => None,
        };
        let Some((name, version)) = products
            .iter()
            .find(|(name, _)| known(name).is_some())
            .or(products.first())
        else {
            return Self::default();
        };
        Self {
            name: Some(known(name).unwrap_or(name).to_owned()),
            version: version.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incoming_versions_are_preserved_without_profile_inference() {
        for ua in ["claude-cli/2.1.245 (external, cli)", "claude-code/2.1.245"] {
            assert_eq!(
                ClientIdentity::from_user_agent(Some(ua)),
                ClientIdentity {
                    name: Some("Claude Code".into()),
                    version: Some("2.1.245".into())
                }
            );
        }
        assert_eq!(
            ClientIdentity::from_user_agent(Some("codex_cli_rs/0.120.0 (Windows)"))
                .name
                .as_deref(),
            Some("Codex")
        );
        assert_eq!(
            ClientIdentity::from_user_agent(Some("custom/1.2.3")).version.as_deref(),
            Some("1.2.3")
        );
        assert_eq!(ClientIdentity::from_user_agent(None), ClientIdentity::default());
        assert_eq!(
            ClientIdentity::from_user_agent(Some("not-a-product")),
            ClientIdentity::default()
        );
    }
}
