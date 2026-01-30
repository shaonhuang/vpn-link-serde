# Contributing to VPN Link Serde

Thank you for your interest in contributing. This document outlines code and process standards so contributions align with the project’s quality and style.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Development setup

- **Rust**: Use the version specified in `Cargo.toml` (`rust-version`) or the latest stable.
- **Format**: Run `cargo fmt` before committing.
- **Lints**: Fix warnings and run `cargo clippy` (optional but recommended).

## Code standards (Clean Code)

- **Names**: Use clear, meaningful names for modules, types, functions, and variables. Avoid abbreviations unless widely known (e.g. `id`, `uuid`).
- **Constants**: Prefer named constants over magic strings/numbers. Shared scheme and error strings live in `src/constants.rs`.
- **Functions**: Keep functions small and focused. One level of abstraction per function where possible.
- **Comments**: Prefer self-explanatory code. Use doc comments (`///`) for public API; use `//` for non-obvious logic. Keep comments in English for open-source consistency.
- **Errors**: Use `ProtocolError` variants consistently. Prefer `error_msg` and `scheme` constants from `constants.rs` for user-facing messages.
- **Tests**: Every meaningful change should be covered by tests. Run `cargo test` before committing; the test suite must pass.

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make your changes, following the code standards above.
3. Add or update tests as needed.
4. Run `cargo fmt`, `cargo test`, and (if available) `cargo clippy`.
5. Open a PR with a clear description and reference any related issues.
6. Address review feedback. Once approved, maintainers will merge.

## Protocol behavior

- Parsing and serialization behavior is defined in `doc/protocols.md`. Changes that affect link format or parsing rules should be documented there and reflected in tests (including `src/protocols_comprehensive.rs`).

## Questions

If you have questions, open a GitHub Discussion or Issue.
