//! VMess protocol parser
//!
//! Supports both VMess **V1** and **V2** link formats; serialization always produces **V2**.
//!
//! ## Link formats
//!
//! | Format | Form | Description |
//! |--------|------|-------------|
//! | **V1** | `vmess://base64(security:uuid@host:port)?query` | Legacy; userinfo is base64-encoded `method:uuid@host:port`, then URL-encoded query (e.g. `remarks`, `network`, `wsPath`, `wsHost`, `aid`, `tls`) |
//! | **V2** | `vmess://base64(JSON)` | Main format; body is Base64(JSON). Standard or no-padding Base64; whitespace is stripped before decode. |
//!
//! ## V2 JSON fields
//!
//! **Required**: `add` (server address), `port` (1–65535), `id` (user UUID).
//!
//! **Optional**: `v` (version, usually `"2"`), `ps` (remark), `aid`, `net` (tcp/kcp/ws/h2/quic/grpc),
//! `type`, `host`, `path`, `tls`, `scy` (encryption), `alpn`, `fp`, `sni`.
//!
//! `port`, `aid`, and `v` are accepted as either number or string in JSON.
//!
//! ## Parsing rules
//!
//! 1. Prefix `vmess://` is case-insensitive.
//! 2. If the part before `?` decodes from Base64 to a string containing both `@` and `:`, it is treated as **V1**; otherwise **V2** (full body decoded as JSON).
//! 3. Base64 supports standard padding or no padding; whitespace (including newlines) is removed before decoding.
//!
//! ## Serialization
//!
//! [`to_link`](ProtocolParser::to_link) always emits V2: JSON with at least `add`, `port`, `id`, then UTF-8 Base64, prefixed with `vmess://`.

use crate::ProtocolParser;
use crate::constants::{error_msg, scheme};
use crate::error::{ProtocolError, Result};
use base64::Engine;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

/// Deserializes port from JSON as either number or string (e.g. "8080").
fn deserialize_port<'de, D>(d: D) -> std::result::Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Port {
        Num(u16),
        Str(String),
    }
    match Port::deserialize(d)? {
        Port::Num(n) => Ok(n),
        Port::Str(s) => s.parse().map_err(D::Error::custom),
    }
}

/// Deserializes optional aid from JSON as either number or string.
fn deserialize_aid_opt<'de, D>(d: D) -> std::result::Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Aid {
        Num(u16),
        Str(String),
    }
    match Option::<Aid>::deserialize(d)? {
        None => Ok(None),
        Some(Aid::Num(n)) => Ok(Some(n)),
        Some(Aid::Str(s)) => Ok(s.parse().ok()),
    }
}

/// Deserializes optional string from JSON (e.g. v) as either string or number.
fn deserialize_opt_string<'de, D>(d: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StrOrNum {
        Str(String),
        Num(i64),
    }
    match Option::<StrOrNum>::deserialize(d)? {
        None => Ok(None),
        Some(StrOrNum::Str(s)) => Ok(Some(s)),
        Some(StrOrNum::Num(n)) => Ok(Some(n.to_string())),
    }
}

/// VMess V2 configuration structure
///
/// This structure represents the VMess protocol configuration in V2 format.
/// All fields are optional except for `add`, `port`, and `id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VMessV2 {
    /// Protocol version (usually "2"; may be number or string in JSON)
    #[serde(
        default,
        deserialize_with = "deserialize_opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub v: Option<String>,
    /// Remarks/description (ps)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    /// Server address
    pub add: String,
    /// Server port (may be number or string in JSON)
    #[serde(deserialize_with = "deserialize_port")]
    pub port: u16,
    /// User ID (UUID)
    pub id: String,
    /// Alter ID (may be number or string in JSON)
    #[serde(default, deserialize_with = "deserialize_aid_opt")]
    pub aid: Option<u16>,
    /// Network type (tcp, kcp, ws, h2, quic, grpc)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net: Option<String>,
    /// Header type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Host header (for ws/h2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Path (for ws/h2/grpc)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// TLS setting (tls, none)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    /// Security/encryption method (scy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scy: Option<String>,
    /// ALPN setting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// Fingerprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    /// SNI (Server Name Indication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

/// VMess protocol parser
///
/// Parses VMess links in both V1 and V2 formats and can generate V2 format links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VMess {
    /// VMess configuration
    pub config: VMessV2,
}

impl ProtocolParser for VMess {
    fn parse(link: &str) -> Result<Self> {
        if !link.to_lowercase().starts_with(scheme::VMESS) {
            return Err(ProtocolError::InvalidFormat(format!(
                "{} {}",
                error_msg::MUST_START_WITH,
                scheme::VMESS
            )));
        }

        let link_body = link[scheme::VMESS.len()..].trim();

        // V1: vmess://base64(security:uuid@host:port)?query
        // V2: vmess://base64(json)
        let is_v1 = VMess::link_body_looks_like_v1(link_body);
        if is_v1 {
            VMess::parse_v1(link)
        } else {
            VMess::parse_v2(link)
        }
    }

    fn to_link(&self) -> Result<String> {
        // Always generate V2 format
        let mut config = self.config.clone();
        config.v = Some("2".to_string());

        let json = serde_json::to_string(&config)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        Ok(format!("vmess://{}", encoded))
    }
}

impl VMess {
    /// Returns true if body looks like V1: has `?` and the part before `?` decodes from base64
    /// to a string containing both `@` and `:` (e.g. security:uuid@host:port).
    fn link_body_looks_like_v1(link_body: &str) -> bool {
        let parts: Vec<&str> = link_body.splitn(2, '?').collect();
        let before_query = match parts.as_slice() {
            [before, _] => *before,
            _ => return false,
        };
        let decoded = match base64::engine::general_purpose::STANDARD.decode(before_query) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let decoded_str = match std::str::from_utf8(&decoded) {
            Ok(s) => s,
            Err(_) => return false,
        };
        decoded_str.contains('@') && decoded_str.contains(':')
    }

    /// Parses VMess V1 format link.
    fn parse_v1(link: &str) -> Result<Self> {
        let link_body: String = link[scheme::VMESS.len()..]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let parts: Vec<&str> = link_body.splitn(2, '?').collect();

        if parts.is_empty() {
            return Err(ProtocolError::InvalidFormat(
                "Invalid V1 format".to_string(),
            ));
        }

        let before_query = parts[0].trim();
        // Support base64 with or without padding (same as V2).
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(before_query)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(before_query))?;
        let decoded_str = String::from_utf8(decoded)
            .map_err(|e| ProtocolError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;

        // Parse main part: security:uuid@host:port
        let parts_main: Vec<&str> = decoded_str.split('@').collect();
        if parts_main.len() != 2 {
            return Err(ProtocolError::InvalidFormat(
                "Invalid main part format".to_string(),
            ));
        }

        let security_id = parts_main[0];
        let host_port = parts_main[1];

        let sec_parts: Vec<&str> = security_id.split(':').collect();
        if sec_parts.len() != 2 {
            return Err(ProtocolError::InvalidFormat(
                "Invalid security:id format".to_string(),
            ));
        }

        let security = sec_parts[0];
        let id = sec_parts[1];

        let hp_parts: Vec<&str> = host_port.split(':').collect();
        if hp_parts.len() != 2 {
            return Err(ProtocolError::InvalidFormat(
                "Invalid host:port format".to_string(),
            ));
        }

        let add = hp_parts[0].to_string();
        let port: u16 = hp_parts[1]
            .parse()
            .map_err(|e| ProtocolError::InvalidField(format!("Invalid port: {}", e)))?;

        // Parse query parameters
        let mut config = VMessV2 {
            v: Some("2".to_string()),
            ps: None,
            add,
            port,
            id: id.to_string(),
            aid: None,
            net: None,
            r#type: None,
            host: None,
            path: None,
            tls: None,
            scy: Some(security.to_string()),
            alpn: None,
            fp: None,
            sni: None,
        };

        if parts.len() > 1 {
            let query_str = parts[1];
            let params: HashMap<String, String> = url::form_urlencoded::parse(query_str.as_bytes())
                .into_owned()
                .collect();

            // Map V1 parameters to V2 format
            if let Some(remarks) = params.get("remarks") {
                config.ps = Some(remarks.clone());
            }
            if let Some(net) = params.get("network") {
                config.net = Some(net.clone());
            }
            if let Some(ws_path) = params.get("wsPath") {
                config.path = Some(ws_path.clone());
            }
            if let Some(ws_host) = params.get("wsHost") {
                config.host = Some(ws_host.clone());
            }
            if let Some(aid) = params.get("aid") {
                config.aid = aid.parse().ok();
            }
            if let Some(tls) = params.get("tls") {
                config.tls = if tls == "1" {
                    Some("tls".to_string())
                } else {
                    None
                };
            }
        }

        Ok(VMess { config })
    }

    /// Parses VMess V2 format link.
    fn parse_v2(link: &str) -> Result<Self> {
        // Strip scheme prefix and remove whitespace (including newlines) for pasted base64.
        let link_body: String = link[scheme::VMESS.len()..]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        // Decode base64 (supports no padding or non-standard padding).
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(link_body.trim())
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(link_body.trim()))?;
        let json_str = String::from_utf8(decoded)
            .map_err(|e| ProtocolError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;

        // Parse JSON
        let config: VMessV2 = serde_json::from_str(&json_str)?;

        Ok(VMess { config })
    }
}
