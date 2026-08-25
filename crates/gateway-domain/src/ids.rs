//! Typed identifiers prevent cross-domain identifier mixups.

use std::{fmt, marker::PhantomData, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::{DomainError, DomainResult};

const MAX_ID_BYTES: usize = 128;

/// An opaque, bounded identifier tagged with its domain type.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypedId<Tag> {
    value: Box<str>,
    marker: PhantomData<fn() -> Tag>,
}

impl<Tag> TypedId<Tag> {
    /// Validate and construct an identifier.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidIdentifier`] when the value is empty,
    /// non-ASCII, or exceeds the bounded wire representation.
    pub fn new(value: impl Into<Box<str>>) -> DomainResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_ID_BYTES || !value.is_ascii() {
            return Err(DomainError::InvalidIdentifier);
        }
        Ok(Self {
            value,
            marker: PhantomData,
        })
    }

    /// Return the wire/storage representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl<Tag> fmt::Debug for TypedId<Tag> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("TypedId").field(&self.value).finish()
    }
}

impl<Tag> fmt::Display for TypedId<Tag> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl<Tag> FromStr for TypedId<Tag> {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<Tag> Serialize for TypedId<Tag> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.value)
    }
}

impl<'de, Tag> Deserialize<'de> for TypedId<Tag> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Box::<str>::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

macro_rules! id_tag {
    ($tag:ident, $alias:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[doc = concat!(stringify!($alias), " type marker.")]
        pub enum $tag {}
        #[doc = concat!("Typed ", stringify!($alias), ".")]
        pub type $alias = TypedId<$tag>;
    };
}

id_tag!(RequestTag, RequestId);
id_tag!(UserTag, UserId);
id_tag!(GroupTag, GroupId);
id_tag!(PlatformKeyTag, PlatformKeyId);
id_tag!(CredentialTag, CredentialId);
id_tag!(SessionTag, SessionId);
id_tag!(AgentTag, AgentId);
id_tag!(EgressBindingTag, EgressBindingId);
id_tag!(TicketTag, TicketId);
id_tag!(LeaseTag, LeaseId);
id_tag!(EnrollmentTag, EnrollmentId);
id_tag!(CredentialProfileTag, CredentialProfileId);
id_tag!(DeviceIdentityTag, DeviceIdentityId);
id_tag!(ProxyEndpointTag, ProxyEndpointId);
id_tag!(ArchetypeVersionTag, ArchetypeVersionId);
id_tag!(MaintenanceOperationTag, MaintenanceOperationId);
id_tag!(AuthVersionTag, AuthVersionId);
id_tag!(AutoReauthStrategyTag, AutoReauthStrategyId);
id_tag!(BrowserMaterialVersionTag, BrowserMaterialVersionId);
id_tag!(SecretTag, SecretId);
id_tag!(TransportBundleTag, TransportBundleId);
id_tag!(ConnectionAttemptTag, ConnectionAttemptId);
id_tag!(AttemptPlanTag, AttemptPlanId);

#[cfg(test)]
mod tests {
    use super::RequestId;

    #[test]
    fn rejects_empty_and_non_ascii_identifiers() {
        assert!(RequestId::new("").is_err());
        assert!(RequestId::new("请求").is_err());
        assert!(RequestId::new("req_01").is_ok());
    }
}
