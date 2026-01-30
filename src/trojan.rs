//! Trojan protocol parser
//!
//! Link format: `trojan://[password]@[host]:[port][?query][#fragment]`
//!
//! **Required**: `password`, `host`, `port` (1–65535). Password must be URL-encoded if it contains special characters.
//!
//! **Query parameters** (optional, `application/x-www-form-urlencoded`): `security` (tls/xtls), `sni`, `flow` (e.g. `xtls-rprx-origin`), `type` (tcp/ws), `host`, `path`, `fp`.
//!
//! **Fragment**: Decoded as remark; must be URL-encoded.
//!
//! ## Parsing rules
//!
//! 1. Prefix `trojan://` is case-insensitive.
//! 2. Main part must contain `@` and `:` (`password@address:port`); otherwise `InvalidFormat`.
//! 3. Port must parse as u16; otherwise `InvalidField`.
//! 4. Query and fragment are parsed as above.

use crate::ProtocolParser;
use crate::constants::{error_msg, scheme};
use crate::error::{ProtocolError, Result};
use serde::{Deserialize, Serialize};

/// Trojan configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrojanConfig {
    /// Password
    pub password: String,
    /// Server address
    pub address: String,
    /// Server port
    pub port: u16,
    /// Flow control (for XTLS)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// Security type (tls, xtls)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// SNI (Server Name Indication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Host header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Fingerprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    /// Transport type (tcp, ws, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Path (e.g. for WebSocket)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Remark/description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remark: Option<String>,
}

/// Trojan protocol parser
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trojan {
    /// Trojan configuration
    pub config: TrojanConfig,
}

impl ProtocolParser for Trojan {
    fn parse(link: &str) -> Result<Self> {
        if !link.to_lowercase().starts_with(scheme::TROJAN) {
            return Err(ProtocolError::InvalidFormat(format!(
                "{} {}",
                error_msg::MUST_START_WITH,
                scheme::TROJAN
            )));
        }

        let link_body = &link[scheme::TROJAN.len()..];

        // Split into parts: password@host:port[?query][#fragment]
        let (main_part, query_part, fragment) = {
            let hash_pos = link_body.find('#');
            let (before_hash, fragment) = if let Some(pos) = hash_pos {
                (&link_body[..pos], Some(&link_body[pos + 1..]))
            } else {
                (link_body, None)
            };

            let query_pos = before_hash.find('?');
            let (main, query) = if let Some(pos) = query_pos {
                (&before_hash[..pos], Some(&before_hash[pos + 1..]))
            } else {
                (before_hash, None)
            };

            (main, query, fragment)
        };

        // Parse main part: password@host:port
        let at_pos = main_part
            .find('@')
            .ok_or_else(|| ProtocolError::InvalidFormat(error_msg::MISSING_AT.to_string()))?;

        let password_raw = &main_part[..at_pos];
        let password = urlencoding::decode(password_raw)
            .map(|cow| cow.into_owned())
            .unwrap_or_else(|_| password_raw.to_string());
        let host_port = &main_part[at_pos + 1..];

        let colon_pos = host_port.find(':').ok_or_else(|| {
            ProtocolError::InvalidFormat(error_msg::MISSING_COLON_HOST_PORT.to_string())
        })?;

        let address = &host_port[..colon_pos];
        let port_str = &host_port[colon_pos + 1..];
        let port: u16 = port_str.parse().map_err(|e| {
            ProtocolError::InvalidField(format!("{}: {}", error_msg::INVALID_PORT, e))
        })?;

        // Parse query parameters
        let mut config = TrojanConfig {
            password,
            address: address.to_string(),
            port,
            flow: None,
            security: None,
            sni: None,
            host: None,
            fp: None,
            r#type: None,
            path: None,
            remark: fragment.map(|s| urlencoding::decode(s).unwrap_or_default().to_string()),
        };

        if let Some(query) = query_part {
            let params: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(query.as_bytes())
                    .into_owned()
                    .collect();

            config.flow = params.get("flow").cloned();
            config.security = params.get("security").cloned();
            config.sni = params.get("sni").cloned();
            config.host = params.get("host").cloned();
            config.fp = params.get("fp").cloned();
            config.r#type = params.get("type").cloned();
            config.path = params.get("path").cloned();
        }

        Ok(Trojan { config })
    }

    fn to_link(&self) -> Result<String> {
        let mut parts = vec![format!(
            "trojan://{}@{}:{}",
            urlencoding::encode(&self.config.password),
            self.config.address,
            self.config.port
        )];

        // Build query string
        let mut query_params = Vec::new();

        if let Some(ref flow) = self.config.flow {
            query_params.push(format!("flow={}", urlencoding::encode(flow)));
        }
        if let Some(ref security) = self.config.security {
            query_params.push(format!("security={}", urlencoding::encode(security)));
        }
        if let Some(ref sni) = self.config.sni {
            query_params.push(format!("sni={}", urlencoding::encode(sni)));
        }
        if let Some(ref host) = self.config.host {
            query_params.push(format!("host={}", urlencoding::encode(host)));
        }
        if let Some(ref fp) = self.config.fp {
            query_params.push(format!("fp={}", urlencoding::encode(fp)));
        }
        if let Some(ref r#type) = self.config.r#type {
            query_params.push(format!("type={}", urlencoding::encode(r#type)));
        }
        if let Some(ref path) = self.config.path {
            query_params.push(format!("path={}", urlencoding::encode(path)));
        }

        if !query_params.is_empty() {
            parts.push(query_params.join("&"));
        }

        // Add fragment (remark)
        if let Some(ref remark) = self.config.remark {
            parts.push(format!("#{}", urlencoding::encode(remark)));
        }

        Ok(parts.join("?"))
    }
}
