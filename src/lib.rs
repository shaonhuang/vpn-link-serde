//! # VPN Link Serde
//!
//! A comprehensive Rust library for parsing and serializing VPN proxy protocol links.
//! Supports VMess, VLess, Shadowsocks, Trojan, and Hysteria2 protocols.
//!
//! ## Features
//!
//! - Parse protocol links into structured Rust types
//! - Serialize structured types back into protocol links
//! - Full support for all protocol variants and parameters
//! - Comprehensive error handling
//! - Serde support for serialization/deserialization
//!
//! ## Supported Protocols
//!
//! - **[VMess]** (`vmess://`) — V1 and V2 formats; serialization always outputs V2
//! - **[VLess]** (`vless://`) — Full parameter support including Reality, XTLS
//! - **[Shadowsocks]** (`ss://`) — SIP002 (Base64 userinfo), plugin and tag
//! - **[Trojan]** (`trojan://`) — TLS, XTLS, query and fragment (remark)
//! - **[Hysteria2]** (`hysteria2://`) — Optional auth, official and extended query params
//!
//! ## Link format and parsing rules (unified)
//!
//! - **Scheme prefix**: Case-insensitive (e.g. `VMESS://` is valid).
//! - **Port**: 1–65535; VMess allows port as number or string in JSON; others require a valid u16.
//! - **Query string**: Parsed as `application/x-www-form-urlencoded`; parameter names are case-sensitive.
//! - **Fragment (`#`)**: Decoded as remark/tag; non-ASCII and spaces must be URL-encoded.
//! - **Errors**: Invalid format → `InvalidFormat`; invalid or missing required field → `InvalidField`;
//!   unknown scheme → `UnsupportedProtocol`.
//!
//! See each type's module (e.g. [VMess], [VLess]) for format details, required/optional fields, and serialization rules.
//!
//! ## References
//!
//! Link formats and parsing rules follow the specifications and community conventions:
//! - VMess: [Project V VMess](https://www.v2ray.com/en/configuration/protocols/vmess.html), [V2Fly Guide](https://guide.v2fly.org/en_US/basics/vmess.html)
//! - VLESS: [XTLS VLESS](https://xtls.github.io/en/config/inbounds/vless.html)
//! - Shadowsocks: [SIP002 URI Scheme](https://shadowsocks.org/doc/sip002.html) (RFC 3986)
//! - Trojan: [Trojan Protocol](https://trojan-gfw.github.io/trojan/protocol.html), [Trojan-Go URL](https://azadzadeh.github.io/trojan-go/en/developer/url/)
//! - Hysteria2: [Hysteria 2 URI Scheme](https://v2.hysteria.network/docs/developers/URI-Scheme)
//!
//! A detailed specification (link format, parsing rules, and serialization) is available in the repository at `doc/protocols.md`.
//!
//! ## Example
//!
//! ```rust
//! use vpn_link_serde::Protocol;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse any protocol link
//! let protocol = Protocol::parse("vmess://eyJ2IjoiMiIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOjQ0MywiaWQiOiJ1dWlkLTEyMyJ9")?;
//!
//! // Generate link from parsed protocol
//! let link = protocol.to_link()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## License
//!
//! Licensed under either of
//! - MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)
//!

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

mod constants;
mod error;
mod hysteria2;
mod shadowsocks;
mod trojan;
mod vless;
mod vmess;

#[cfg(test)]
mod protocols_comprehensive;

pub use error::{ProtocolError, Result};
pub use hysteria2::{Hysteria2, Hysteria2Config};
pub use shadowsocks::{Shadowsocks, ShadowsocksConfig};
pub use trojan::{Trojan, TrojanConfig};
pub use vless::{VLess, VLessConfig};
pub use vmess::{VMess, VMessV2};

/// Trait for protocol parsers that can parse links and generate links
pub trait ProtocolParser: Sized {
    /// Parse a protocol link string into a structured configuration
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the link format is invalid or unsupported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vpn_link_serde::{VMess, ProtocolParser};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let vmess = VMess::parse("vmess://eyJ2IjoiMiIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOjQ0MywiaWQiOiJ1dWlkLTEyMyJ9")?;
    /// # Ok(())
    /// # }
    /// ```
    fn parse(link: &str) -> Result<Self>;

    /// Generate a protocol link string from the structured configuration
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the configuration is invalid or cannot be serialized.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vpn_link_serde::{VMess, ProtocolParser};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let vmess = VMess::parse("vmess://eyJ2IjoiMiIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOjQ0MywiaWQiOiJ1dWlkLTEyMyJ9")?;
    /// let link = vmess.to_link()?;
    /// # Ok(())
    /// # }
    /// ```
    fn to_link(&self) -> Result<String>;
}

/// Enum representing different protocol types
///
/// This enum provides a unified interface for working with different VPN protocols.
/// Use `Protocol::parse()` to automatically detect and parse any supported protocol link.
///
/// # Example
///
/// ```rust
/// use vpn_link_serde::Protocol;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Automatically detect protocol type
/// let protocol = Protocol::parse("vmess://eyJ2IjoiMiIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOjQ0MywiaWQiOiJ1dWlkLTEyMyJ9")?;
///
/// match &protocol {
///     Protocol::VMess(v) => println!("VMess: {}", v.config.add),
///     Protocol::VLess(v) => println!("VLess: {}", v.config.address),
///     Protocol::Shadowsocks(s) => println!("Shadowsocks: {}", s.config.address),
///     Protocol::Trojan(t) => println!("Trojan: {}", t.config.address),
///     Protocol::Hysteria2(h) => println!("Hysteria2: {}", h.config.host),
/// }
///
/// // Generate link
/// let link = protocol.to_link()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    /// VMess protocol
    VMess(VMess),
    /// VLess protocol
    VLess(VLess),
    /// Shadowsocks protocol
    Shadowsocks(Shadowsocks),
    /// Trojan protocol
    Trojan(Trojan),
    /// Hysteria2 protocol
    Hysteria2(Hysteria2),
}

impl Protocol {
    /// Parse any protocol link and return the appropriate protocol variant
    ///
    /// Automatically detects the protocol type based on the link prefix and parses it accordingly.
    ///
    /// # Arguments
    ///
    /// * `link` - The protocol link string (e.g., "vmess://...", "vless://...")
    ///
    /// # Returns
    ///
    /// Returns `Ok(Protocol)` with the appropriate variant if parsing succeeds,
    /// or `Err(ProtocolError)` if the link is invalid or unsupported.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vpn_link_serde::Protocol;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let protocol = Protocol::parse("vmess://eyJ2IjoiMiIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOjQ0MywiaWQiOiJ1dWlkLTEyMyJ9")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(link: &str) -> Result<Self> {
        use crate::constants::scheme;

        let link_lower = link.to_lowercase();

        if link_lower.starts_with(scheme::VMESS) {
            Ok(Protocol::VMess(VMess::parse(link)?))
        } else if link_lower.starts_with(scheme::VLESS) {
            Ok(Protocol::VLess(VLess::parse(link)?))
        } else if link_lower.starts_with(scheme::SHADOWSOCKS) {
            Ok(Protocol::Shadowsocks(Shadowsocks::parse(link)?))
        } else if link_lower.starts_with(scheme::TROJAN) {
            Ok(Protocol::Trojan(Trojan::parse(link)?))
        } else if link_lower.starts_with(scheme::HYSTERIA2) {
            Ok(Protocol::Hysteria2(Hysteria2::parse(link)?))
        } else {
            let scheme_name = link.split("://").next().unwrap_or("unknown");
            Err(ProtocolError::UnsupportedProtocol(format!(
                "Unsupported protocol: {}",
                scheme_name
            )))
        }
    }

    /// Generate a link string from the protocol
    ///
    /// Converts the parsed protocol configuration back into a link string.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` with the generated link if successful,
    /// or `Err(ProtocolError)` if the configuration cannot be serialized.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vpn_link_serde::Protocol;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let protocol = Protocol::parse("vmess://eyJ2IjoiMiIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOjQ0MywiaWQiOiJ1dWlkLTEyMyJ9")?;
    /// let link = protocol.to_link()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_link(&self) -> Result<String> {
        match self {
            Protocol::VMess(v) => v.to_link(),
            Protocol::VLess(v) => v.to_link(),
            Protocol::Shadowsocks(s) => s.to_link(),
            Protocol::Trojan(t) => t.to_link(),
            Protocol::Hysteria2(h) => h.to_link(),
        }
    }
}
