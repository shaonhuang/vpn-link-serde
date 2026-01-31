# VPN Link Serde

[![Crates.io](https://img.shields.io/crates/v/vpn-link-serde.svg)](https://crates.io/crates/vpn-link-serde)
[![Documentation](https://docs.rs/vpn-link-serde/badge.svg)](https://docs.rs/vpn-link-serde)
[![License](https://img.shields.io/crates/l/vpn-link-serde.svg)](LICENSE-MIT)

A comprehensive Rust library for parsing and serializing VPN proxy protocol links. Supports VMess, VLess, Shadowsocks, Trojan, and Hysteria2 protocols with full parameter support.

## Features

- ✅ **Parse protocol links** into structured Rust types
- ✅ **Serialize structured types** back into protocol links
- ✅ **Full protocol support** for all variants and parameters
- ✅ **Comprehensive error handling** with detailed error messages
- ✅ **Serde support** for serialization/deserialization
- ✅ **Well-documented** with examples
- ✅ **Zero dependencies** on external parsing libraries (only uses standard Rust crates)

## Supported Protocols

- **VMess** (`vmess://`) - V1 and V2 formats
- **VLess** (`vless://`) - Full parameter support including Reality, XTLS, and TLS
- **Shadowsocks** (`ss://`) - Base64 and SIP002 formats
- **Trojan** (`trojan://`) - Full TLS and XTLS support
- **Hysteria2** (`hysteria2://`) - Complete configuration support

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
vpn-link-serde = "0.1.5"
```

## Usage

### Basic Example

```rust
use vpn_link_serde::Protocol;

// Parse any protocol link
let protocol = Protocol::parse("vmess://eyJ2IjoiMiIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOjQ0MywiaWQiOiJ1dWlkLTEyMyJ9")?;

// Generate link from parsed protocol
let link = protocol.to_link()?;
```

### Protocol-Specific Parsing

```rust
use vpn_link_serde::{VMess, VLess, Shadowsocks, Trojan, Hysteria2};

// Parse VMess link
let vmess = VMess::parse("vmess://...")?;
println!("Address: {}", vmess.config.add);
println!("Port: {}", vmess.config.port);

// Parse VLess link
let vless = VLess::parse("vless://uuid@example.com:443?security=tls&sni=example.com#MyServer")?;
println!("ID: {}", vless.config.id);
println!("Address: {}", vless.config.address);

// Parse Shadowsocks link
let ss = Shadowsocks::parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#MySS")?;
println!("Method: {}", ss.config.method);
println!("Address: {}", ss.config.address);

// Parse Trojan link
let trojan = Trojan::parse("trojan://password@example.com:443?security=tls&sni=example.com#MyTrojan")?;
println!("Password: {}", trojan.config.password);
println!("Address: {}", trojan.config.address);

// Parse Hysteria2 link
let h2 = Hysteria2::parse("hysteria2://password@example.com:443?up_mbps=100&down_mbps=200#MyHysteria2")?;
println!("Host: {}", h2.config.host);
println!("Port: {}", h2.config.port);
```

### Using the Protocol Enum

```rust
use vpn_link_serde::Protocol;

// Automatically detect protocol type
let protocol = Protocol::parse("vmess://...")?;

match protocol {
    Protocol::VMess(v) => println!("VMess: {}", v.config.add),
    Protocol::VLess(v) => println!("VLess: {}", v.config.address),
    Protocol::Shadowsocks(s) => println!("Shadowsocks: {}", s.config.address),
    Protocol::Trojan(t) => println!("Trojan: {}", t.config.address),
    Protocol::Hysteria2(h) => println!("Hysteria2: {}", h.config.host),
}

// Generate link
let link = protocol.to_link()?;
```

### Serialization/Deserialization

All configuration structures implement `Serialize` and `Deserialize`:

```rust
use vpn_link_serde::VMess;
use serde_json;

let vmess = VMess::parse("vmess://...")?;

// Serialize to JSON
let json = serde_json::to_string(&vmess.config)?;

// Deserialize from JSON
let config: VMessV2 = serde_json::from_str(&json)?;
```

## Error Handling

The library provides comprehensive error handling:

```rust
use vpn_link_serde::{Protocol, ProtocolError};

match Protocol::parse("invalid-link") {
    Ok(protocol) => println!("Parsed: {:?}", protocol),
    Err(ProtocolError::InvalidFormat(msg)) => eprintln!("Invalid format: {}", msg),
    Err(ProtocolError::UnsupportedProtocol(msg)) => eprintln!("Unsupported: {}", msg),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Protocol Details

### VMess

Supports both V1 and V2 formats. V1 format links are automatically converted to V2 format when parsed.

```rust
use vpn_link_serde::VMess;

// V2 format (recommended)
let vmess = VMess::parse("vmess://eyJ2IjoiMiIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOjQ0MywiaWQiOiJ1dWlkLTEyMyJ9")?;
```

### VLess

Full support for all VLess parameters including Reality, XTLS, and TLS:

```rust
use vpn_link_serde::VLess;

let vless = VLess::parse("vless://uuid@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=sni.yahoo.com&fp=chrome&pbk=xxx&sid=88&type=tcp&headerType=none&host=hk.yahoo.com#reality")?;
```

### Shadowsocks

Supports both base64-encoded and SIP002 formats:

```rust
use vpn_link_serde::Shadowsocks;

// SIP002 format (recommended)
let ss = Shadowsocks::parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#MySS")?;
```

### Trojan

Full TLS and XTLS support:

```rust
use vpn_link_serde::Trojan;

let trojan = Trojan::parse("trojan://password@example.com:443?flow=xtls-rprx-origin&security=xtls&sni=example.com#trojan")?;
```

### Hysteria2

Complete configuration support:

```rust
use vpn_link_serde::Hysteria2;

let h2 = Hysteria2::parse("hysteria2://password@example.com:443?protocol=udp&up_mbps=100&down_mbps=200&sni=example.com#MyHysteria2")?;
```

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for code standards and the pull request process. By participating, you agree to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Licensed under either of
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for details.
