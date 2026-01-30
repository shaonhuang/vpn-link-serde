//! VLess protocol parser
//!
//! URI format (RFC 3986): `vless://<id>@<address>:<port>[?<query>][#<fragment>]`
//!
//! **Required**: `id` (user UUID), `address` (host or IP), `port` (1–65535).
//!
//! **Query parameters** (optional, `application/x-www-form-urlencoded`): `encryption`, `flow` (e.g. `xtls-rprx-vision`), `security` (none/tls/xtls/reality), `type` (tcp/ws/grpc/h2/httpupgrade), `host`, `path`, `sni`, `fp`, `pbk` (Reality public key), `sid` (Reality short ID), `seed`, `headerType`.
//!
//! **Fragment**: Decoded as remark; must be URL-encoded if it contains spaces or non-ASCII.
//!
//! ## Parsing rules
//!
//! 1. Prefix `vless://` is case-insensitive.
//! 2. Main part must contain exactly one `@` and a `:` for port (`id@address:port`); otherwise `InvalidFormat`.
//! 3. Port must parse as u16; otherwise `InvalidField`.

use crate::ProtocolParser;
use crate::constants::{error_msg, scheme};
use crate::error::{ProtocolError, Result};
use serde::{Deserialize, Serialize};

/// VLess configuration structure
///
/// Represents a complete VLess protocol configuration with all supported parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VLessConfig {
    /// User ID (UUID)
    pub id: String,
    /// Server address
    pub address: String,
    /// Server port
    pub port: u16,
    /// Encryption method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    /// Flow control (for XTLS)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// Security type (tls, xtls, reality, none)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// Network type (tcp, kcp, ws, h2, quic, grpc, multi)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Host header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Path (for ws/h2/grpc)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// SNI (Server Name Indication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Fingerprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    /// Public key (for Reality)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pbk: Option<String>,
    /// Short ID (for Reality)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Seed (for mKCP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    /// Header type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_type: Option<String>,
    /// Remark/description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remark: Option<String>,
}

/// VLess protocol parser
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VLess {
    /// VLess configuration
    pub config: VLessConfig,
}

impl ProtocolParser for VLess {
    fn parse(link: &str) -> Result<Self> {
        if !link.to_lowercase().starts_with(scheme::VLESS) {
            return Err(ProtocolError::InvalidFormat(format!(
                "{} {}",
                error_msg::MUST_START_WITH,
                scheme::VLESS
            )));
        }

        let link_body = &link[scheme::VLESS.len()..];

        // Split into parts: [userinfo@]host:port[?query][#fragment]
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

        // Parse main part: id@host:port
        let at_pos = main_part
            .find('@')
            .ok_or_else(|| ProtocolError::InvalidFormat(error_msg::MISSING_AT.to_string()))?;

        let id = &main_part[..at_pos];
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
        let mut config = VLessConfig {
            id: id.to_string(),
            address: address.to_string(),
            port,
            encryption: None,
            flow: None,
            security: None,
            r#type: None,
            host: None,
            path: None,
            sni: None,
            fp: None,
            pbk: None,
            sid: None,
            seed: None,
            header_type: None,
            remark: fragment.map(|s| urlencoding::decode(s).unwrap_or_default().to_string()),
        };

        if let Some(query) = query_part {
            let params: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(query.as_bytes())
                    .into_owned()
                    .collect();

            config.encryption = params.get("encryption").cloned();
            config.flow = params.get("flow").cloned();
            config.security = params.get("security").cloned();
            config.r#type = params.get("type").cloned();
            config.host = params.get("host").cloned();
            config.path = params.get("path").cloned();
            config.sni = params.get("sni").cloned();
            config.fp = params.get("fp").cloned();
            config.pbk = params.get("pbk").cloned();
            config.sid = params.get("sid").cloned();
            config.seed = params.get("seed").cloned();
            config.header_type = params.get("headerType").cloned();
        }

        Ok(VLess { config })
    }

    fn to_link(&self) -> Result<String> {
        let mut parts = vec![format!(
            "vless://{}@{}:{}",
            self.config.id, self.config.address, self.config.port
        )];

        // Build query string
        let mut query_params = Vec::new();

        if let Some(ref encryption) = self.config.encryption {
            query_params.push(format!("encryption={}", urlencoding::encode(encryption)));
        }
        if let Some(ref flow) = self.config.flow {
            query_params.push(format!("flow={}", urlencoding::encode(flow)));
        }
        if let Some(ref security) = self.config.security {
            query_params.push(format!("security={}", urlencoding::encode(security)));
        }
        if let Some(ref r#type) = self.config.r#type {
            query_params.push(format!("type={}", urlencoding::encode(r#type)));
        }
        if let Some(ref host) = self.config.host {
            query_params.push(format!("host={}", urlencoding::encode(host)));
        }
        if let Some(ref path) = self.config.path {
            query_params.push(format!("path={}", urlencoding::encode(path)));
        }
        if let Some(ref sni) = self.config.sni {
            query_params.push(format!("sni={}", urlencoding::encode(sni)));
        }
        if let Some(ref fp) = self.config.fp {
            query_params.push(format!("fp={}", urlencoding::encode(fp)));
        }
        if let Some(ref pbk) = self.config.pbk {
            query_params.push(format!("pbk={}", urlencoding::encode(pbk)));
        }
        if let Some(ref sid) = self.config.sid {
            query_params.push(format!("sid={}", urlencoding::encode(sid)));
        }
        if let Some(ref seed) = self.config.seed {
            query_params.push(format!("seed={}", urlencoding::encode(seed)));
        }
        if let Some(ref header_type) = self.config.header_type {
            query_params.push(format!("headerType={}", urlencoding::encode(header_type)));
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
