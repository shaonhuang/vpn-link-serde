//! Shadowsocks protocol parser (SIP002)
//!
//! Link format: `ss://[userinfo@]hostname:port[/][?plugin][#tag]`
//!
//! **userinfo**: Base64-encoded `method:password` (Stream/AEAD). Hostname and port are plain text.
//!
//! **plugin**: Optional; e.g. `plugin-name;opt=value`, URL-encoded. If present, SIP002 requires a `/` after port (e.g. `...port/?plugin=...`).
//!
//! **tag**: Optional; fragment used as remark; must be URL-encoded if it contains spaces or non-ASCII.
//!
//! ## Parsing rules
//!
//! 1. Prefix `ss://` is case-insensitive.
//! 2. Fragment (tag) is split by `#`; query (plugin) by `?`. Remainder is `[userinfo@]hostname:port`.
//! 3. If the part before `@` (or the whole body if no `@`) is valid Base64, decode to get `method:password`; hostname and port come from the part after `@` or the whole body. Port must parse as u16.

use crate::ProtocolParser;
use crate::constants::{error_msg, scheme};
use crate::error::{ProtocolError, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Shadowsocks configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowsocksConfig {
    /// Encryption method (aes-256-gcm, chacha20-poly1305, etc.)
    pub method: String,
    /// Password
    pub password: String,
    /// Server address
    pub address: String,
    /// Server port
    pub port: u16,
    /// Tag/remark
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Plugin information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
}

/// Shadowsocks protocol parser
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shadowsocks {
    /// Shadowsocks configuration
    pub config: ShadowsocksConfig,
}

impl ProtocolParser for Shadowsocks {
    fn parse(link: &str) -> Result<Self> {
        if !link.to_lowercase().starts_with(scheme::SHADOWSOCKS) {
            return Err(ProtocolError::InvalidFormat(format!(
                "{} {}",
                error_msg::MUST_START_WITH,
                scheme::SHADOWSOCKS
            )));
        }

        let link_body = &link[scheme::SHADOWSOCKS.len()..];

        // Extract fragment (tag) if present
        let (main_part, tag) = {
            if let Some(hash_pos) = link_body.find('#') {
                let tag_str = &link_body[hash_pos + 1..];
                let decoded_tag = urlencoding::decode(tag_str).map_err(|e| {
                    ProtocolError::UrlParseError(format!("Failed to decode tag: {}", e))
                })?;
                (&link_body[..hash_pos], Some(decoded_tag.to_string()))
            } else {
                (link_body, None)
            }
        };

        // Extract query parameters (for plugin)
        let (address_part, plugin) = {
            if let Some(query_pos) = main_part.find('?') {
                let query_str = &main_part[query_pos + 1..];
                let params: std::collections::HashMap<String, String> =
                    url::form_urlencoded::parse(query_str.as_bytes())
                        .into_owned()
                        .collect();
                let plugin = params.get("plugin").cloned();
                (&main_part[..query_pos], plugin)
            } else {
                (main_part, None)
            }
        };

        // Check if it's base64 encoded or SIP002 format
        let (method, password, address, port) = if address_part
            .chars()
            .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            // Base64 encoded format: base64(method:password)@host:port
            let decoded = base64::engine::general_purpose::STANDARD.decode(address_part)?;
            let decoded_str = String::from_utf8(decoded)
                .map_err(|e| ProtocolError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;

            let at_pos = decoded_str
                .rfind('@')
                .ok_or_else(|| ProtocolError::InvalidFormat(error_msg::MISSING_AT.to_string()))?;

            let method_password = &decoded_str[..at_pos];
            let host_port = &decoded_str[at_pos + 1..];

            let colon_pos = method_password.find(':').ok_or_else(|| {
                ProtocolError::InvalidFormat("Missing ':' in method:password".to_string())
            })?;

            let method = &method_password[..colon_pos];
            let password = &method_password[colon_pos + 1..];

            let hp_colon = host_port.find(':').ok_or_else(|| {
                ProtocolError::InvalidFormat(error_msg::MISSING_COLON_HOST_PORT.to_string())
            })?;

            let address = &host_port[..hp_colon];
            let port_str = host_port[hp_colon + 1..].trim_end_matches('/');
            let port: u16 = port_str.parse().map_err(|e| {
                ProtocolError::InvalidField(format!("{}: {}", error_msg::INVALID_PORT, e))
            })?;

            (
                method.to_string(),
                password.to_string(),
                address.to_string(),
                port,
            )
        } else {
            // SIP002 format: method:password@host:port (URL encoded)
            let at_pos = address_part
                .rfind('@')
                .ok_or_else(|| ProtocolError::InvalidFormat(error_msg::MISSING_AT.to_string()))?;

            let user_info = &address_part[..at_pos];
            let host_port = address_part[at_pos + 1..].trim_end_matches('/');

            let decoded_user = base64::engine::general_purpose::STANDARD.decode(user_info)?;
            let user_str = String::from_utf8(decoded_user)
                .map_err(|e| ProtocolError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;

            let colon_pos = user_str.find(':').ok_or_else(|| {
                ProtocolError::InvalidFormat("Missing ':' in method:password".to_string())
            })?;

            let method = &user_str[..colon_pos];
            let password = &user_str[colon_pos + 1..];

            let hp_colon = host_port.find(':').ok_or_else(|| {
                ProtocolError::InvalidFormat(error_msg::MISSING_COLON_HOST_PORT.to_string())
            })?;

            let address = &host_port[..hp_colon];
            let port_str = &host_port[hp_colon + 1..];
            let port: u16 = port_str.parse().map_err(|e| {
                ProtocolError::InvalidField(format!("{}: {}", error_msg::INVALID_PORT, e))
            })?;

            (
                method.to_string(),
                password.to_string(),
                address.to_string(),
                port,
            )
        };

        Ok(Shadowsocks {
            config: ShadowsocksConfig {
                method,
                password,
                address,
                port,
                tag,
                plugin,
            },
        })
    }

    fn to_link(&self) -> Result<String> {
        // Use SIP002 format: ss://base64(method:password)@host:port
        let user_info = format!("{}:{}", self.config.method, self.config.password);
        let encoded_user = base64::engine::general_purpose::STANDARD.encode(user_info.as_bytes());

        // SIP002: port 后应有 / 再接 ?plugin
        let mut link = format!(
            "ss://{}@{}:{}",
            encoded_user, self.config.address, self.config.port
        );
        if self.config.plugin.is_some() {
            link.push('/');
        }

        // Add plugin query parameter if present
        if let Some(ref plugin) = self.config.plugin {
            link.push_str(&format!("?plugin={}", urlencoding::encode(plugin)));
        }

        // Add tag (fragment) if present
        if let Some(ref tag) = self.config.tag {
            link.push_str(&format!("#{}", urlencoding::encode(tag)));
        }

        Ok(link)
    }
}
