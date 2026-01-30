# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-27

### Added

- Initial release
- Support for VMess protocol (V1 and V2 formats)
- Support for VLess protocol with full parameter support (Reality, XTLS, TLS)
- Support for Shadowsocks protocol (base64 and SIP002 formats)
- Support for Trojan protocol (TLS and XTLS)
- Support for Hysteria2 protocol with complete configuration options
- `Protocol` enum for unified protocol handling
- `ProtocolParser` trait for consistent parsing interface
- Comprehensive error handling with `ProtocolError`
- Full Serde support for all configuration structures
- Extensive documentation and examples
- Round-trip parsing tests for all protocols
