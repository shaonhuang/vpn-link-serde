//! Shared constants for protocol schemes and error messages.
//!
//! Centralizes magic strings to improve maintainability and consistency
//! (Clean Code: avoid magic strings, use named constants).

/// Protocol URI scheme prefixes (lowercase, with `://`).
pub mod scheme {
    /// VMess: `vmess://`
    pub const VMESS: &str = "vmess://";
    /// VLESS: `vless://`
    pub const VLESS: &str = "vless://";
    /// Shadowsocks: `ss://`
    pub const SHADOWSOCKS: &str = "ss://";
    /// Trojan: `trojan://`
    pub const TROJAN: &str = "trojan://";
    /// Hysteria2: `hysteria2://`
    pub const HYSTERIA2: &str = "hysteria2://";
}

/// Common error message fragments for link parsing.
pub mod error_msg {
    /// Missing `@` in userinfo@host part.
    pub const MISSING_AT: &str = "Missing '@' in main part";
    /// Missing `:` in host:port part.
    pub const MISSING_COLON_HOST_PORT: &str = "Missing ':' in host:port";
    /// Invalid port value.
    pub const INVALID_PORT: &str = "Invalid port";
    /// Link must start with scheme (placeholder: use with format!).
    pub const MUST_START_WITH: &str = "Link must start with";
}
