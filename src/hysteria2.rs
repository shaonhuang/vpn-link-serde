//! Hysteria2 protocol parser
//!
//! Link format: `hysteria2://[auth@]hostname[:port]/?[key=value]&...[#fragment]`
//!
//! **Scheme**: This crate uses `hysteria2://` (not `hy2`).
//!
//! **auth**: Optional; if present, format is typically `username:password`; special characters must be URL-encoded.
//!
//! **hostname:port**: Port is required by this crate and must be a valid u16.
//!
//! **Query** (official): `obfs` (e.g. salamander), `obfs-password`, `sni`, `insecure` (1/0), `pinSHA256`.
//!
//! **Query** (extensions supported by this crate): `protocol` (udp/wechat-video/faketcp), `up_mbps`/`upmbps`, `down_mbps`/`downmbps`, `alpn`, `fast_open`/`fastopen`, `recv_window`, `recv_window_conn`, `hop_interval`. Query is parsed as `application/x-www-form-urlencoded`; `sni` alias `peer` is supported.
//!
//! **Fragment**: Decoded as remark (fragment field).
//!
//! ## Parsing rules
//!
//! 1. Prefix `hysteria2://` is case-insensitive.
//! 2. Fragment and query are split by `#` and `?`; main part is `[auth@]host:port`.
//! 3. If `@` is present, the part before it is the password (URL-decoded); otherwise no password.
//! 4. Port is required and must parse as u16; otherwise `InvalidField`.

use crate::ProtocolParser;
use crate::constants::{error_msg, scheme};
use crate::error::{ProtocolError, Result};
use serde::{Deserialize, Serialize};

/// Hysteria2 configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hysteria2Config {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Password (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Protocol (udp, wechat-video, faketcp, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Authentication string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// ALPN settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    /// SNI (Server Name Indication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Allow insecure connections
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// Upload speed in Mbps
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<f64>,
    /// Download speed in Mbps
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<f64>,
    /// Receive window per connection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recv_window_conn: Option<u64>,
    /// Receive window
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recv_window: Option<u64>,
    /// Obfuscation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    /// Disable MTU discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_mtu_discovery: Option<bool>,
    /// Fast open
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fast_open: Option<bool>,
    /// Hop interval
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_interval: Option<u64>,
    /// Fragment/remark
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<String>,
}

/// Hysteria2 protocol parser
#[derive(Debug, Clone, PartialEq)]
pub struct Hysteria2 {
    /// Hysteria2 configuration
    pub config: Hysteria2Config,
}

impl ProtocolParser for Hysteria2 {
    fn parse(link: &str) -> Result<Self> {
        if !link.to_lowercase().starts_with(scheme::HYSTERIA2) {
            return Err(ProtocolError::InvalidFormat(format!(
                "{} {}",
                error_msg::MUST_START_WITH,
                scheme::HYSTERIA2
            )));
        }

        let link_body = &link[scheme::HYSTERIA2.len()..];

        // Split into parts: [password@]host:port[?query][#fragment]
        let (main_part, query_part, fragment) = {
            let hash_pos = link_body.find('#');
            let (before_hash, fragment) = if let Some(pos) = hash_pos {
                let frag_str = &link_body[pos + 1..];
                let decoded_frag = urlencoding::decode(frag_str).map_err(|e| {
                    ProtocolError::UrlParseError(format!("Failed to decode fragment: {}", e))
                })?;
                (&link_body[..pos], Some(decoded_frag.to_string()))
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

        // Parse main part: [password@]host:port
        let (password, host_port) = if let Some(at_pos) = main_part.find('@') {
            let pass = &main_part[..at_pos];
            let decoded_pass = urlencoding::decode(pass).map_err(|e| {
                ProtocolError::UrlParseError(format!("Failed to decode password: {}", e))
            })?;
            (Some(decoded_pass.to_string()), &main_part[at_pos + 1..])
        } else {
            (None, main_part)
        };

        let colon_pos = host_port.find(':').ok_or_else(|| {
            ProtocolError::InvalidFormat(error_msg::MISSING_COLON_HOST_PORT.to_string())
        })?;

        let host = &host_port[..colon_pos];
        let port_str = &host_port[colon_pos + 1..];
        let port: u16 = port_str.parse().map_err(|e| {
            ProtocolError::InvalidField(format!("{}: {}", error_msg::INVALID_PORT, e))
        })?;

        // Parse query parameters
        let mut config = Hysteria2Config {
            host: host.to_string(),
            port,
            password: password.clone(),
            protocol: None,
            auth: password,
            alpn: None,
            sni: None,
            insecure: None,
            up_mbps: None,
            down_mbps: None,
            recv_window_conn: None,
            recv_window: None,
            obfs: None,
            disable_mtu_discovery: None,
            fast_open: None,
            hop_interval: None,
            fragment,
        };

        if let Some(query) = query_part {
            let params: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(query.as_bytes())
                    .into_owned()
                    .collect();

            // Helper to get parameter with fallback names
            let get_param = |primary: &str, fallbacks: &[&str]| -> Option<String> {
                params.get(primary).cloned().or_else(|| {
                    fallbacks
                        .iter()
                        .find_map(|&fallback| params.get(fallback).cloned())
                })
            };

            config.protocol = get_param("protocol", &[]);

            // Map 'peer' to 'sni' (peer is the SNI server name)
            config.sni = get_param("sni", &["peer"]);

            if let Some(alpn_str) = get_param("alpn", &[]) {
                config.alpn = Some(alpn_str.split(',').map(|s| s.to_string()).collect());
            }

            if let Some(insecure_str) = params.get("insecure") {
                config.insecure = Some(insecure_str == "1" || insecure_str == "true");
            }

            if let Some(up_str) = get_param("up_mbps", &["upmbps"]) {
                config.up_mbps = up_str.parse().ok();
            }

            if let Some(down_str) = get_param("down_mbps", &["downmbps"]) {
                config.down_mbps = down_str.parse().ok();
            }

            if let Some(recv_conn_str) = params.get("recv_window_conn") {
                config.recv_window_conn = recv_conn_str.parse().ok();
            }

            if let Some(recv_str) = params.get("recv_window") {
                config.recv_window = recv_str.parse().ok();
            }

            config.obfs = params.get("obfs").cloned();

            if let Some(disable_str) = params.get("disable_mtu_discovery") {
                config.disable_mtu_discovery = Some(disable_str == "1" || disable_str == "true");
            }

            if let Some(fast_open_str) = get_param("fast_open", &["fastopen"]) {
                config.fast_open = Some(fast_open_str == "1" || fast_open_str == "true");
            }

            if let Some(hop_str) = params.get("hop_interval") {
                config.hop_interval = hop_str.parse().ok();
            }

            // Use password as auth if available
            if config.auth.is_none() {
                config.auth = params.get("auth").cloned();
            }
        }

        Ok(Hysteria2 { config })
    }

    fn to_link(&self) -> Result<String> {
        let user_info = if let Some(ref password) = self.config.password {
            format!("{}@", urlencoding::encode(password))
        } else {
            String::new()
        };

        let mut link = format!(
            "hysteria2://{}{}:{}",
            user_info, self.config.host, self.config.port
        );

        // Build query string
        let mut query_params = Vec::new();

        if let Some(ref protocol) = self.config.protocol
            && protocol != "udp"
        {
            query_params.push(format!("protocol={}", urlencoding::encode(protocol)));
        }

        if let Some(ref alpn) = self.config.alpn
            && !alpn.is_empty()
        {
            query_params.push(format!("alpn={}", urlencoding::encode(&alpn.join(","))));
        }

        if let Some(ref sni) = self.config.sni {
            query_params.push(format!("sni={}", urlencoding::encode(sni)));
        }

        if let Some(insecure) = self.config.insecure
            && insecure
        {
            query_params.push("insecure=1".to_string());
        }

        if let Some(up) = self.config.up_mbps {
            query_params.push(format!("up_mbps={}", up));
        }

        if let Some(down) = self.config.down_mbps {
            query_params.push(format!("down_mbps={}", down));
        }

        if let Some(recv_conn) = self.config.recv_window_conn
            && recv_conn > 0
        {
            query_params.push(format!("recv_window_conn={}", recv_conn));
        }

        if let Some(recv) = self.config.recv_window
            && recv > 0
        {
            query_params.push(format!("recv_window={}", recv));
        }

        if let Some(ref obfs) = self.config.obfs {
            query_params.push(format!("obfs={}", urlencoding::encode(obfs)));
        }

        if let Some(disable) = self.config.disable_mtu_discovery
            && disable
        {
            query_params.push("disable_mtu_discovery=1".to_string());
        }

        if let Some(fast_open) = self.config.fast_open
            && fast_open
        {
            query_params.push("fast_open=1".to_string());
        }

        if let Some(hop) = self.config.hop_interval
            && hop > 0
        {
            query_params.push(format!("hop_interval={}", hop));
        }

        if !query_params.is_empty() {
            link.push_str(&format!("?{}", query_params.join("&")));
        }

        // Add fragment if present
        if let Some(ref fragment) = self.config.fragment {
            link.push_str(&format!("#{}", urlencoding::encode(fragment)));
        }

        Ok(link)
    }
}
