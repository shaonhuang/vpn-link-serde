//! Error types for protocol parsing and serialization
//!
//! This crate uses a unified error convention (see crate-level docs):
//! - **InvalidFormat**: Malformed link (e.g. missing `@` or `:` in main part, wrong structure).
//! - **InvalidField**: Invalid or missing required field (e.g. port not in 1–65535, invalid u16).
//! - **UnsupportedProtocol**: Unknown or unsupported scheme (e.g. `unknown://`).
//! - **Base64DecodeError** / **JsonParseError** / **UrlParseError**: Decoding or parsing failures.

use std::fmt;

/// Result type for protocol parsing operations
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Errors that can occur during protocol parsing and serialization
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolError {
    /// Invalid link format (e.g. missing `@` or `:` in main part)
    InvalidFormat(String),
    /// Unsupported or unknown protocol scheme
    UnsupportedProtocol(String),
    /// Base64 decoding error
    Base64DecodeError(String),
    /// JSON parsing error (e.g. VMess V2 body)
    JsonParseError(String),
    /// URL parsing or decoding error (e.g. fragment, query)
    UrlParseError(String),
    /// Missing required field
    MissingField(String),
    /// Invalid field value (e.g. port out of range)
    InvalidField(String),
    /// IO error
    IoError(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            ProtocolError::UnsupportedProtocol(msg) => write!(f, "Unsupported protocol: {}", msg),
            ProtocolError::Base64DecodeError(msg) => write!(f, "Base64 decode error: {}", msg),
            ProtocolError::JsonParseError(msg) => write!(f, "JSON parse error: {}", msg),
            ProtocolError::UrlParseError(msg) => write!(f, "URL parse error: {}", msg),
            ProtocolError::MissingField(msg) => write!(f, "Missing required field: {}", msg),
            ProtocolError::InvalidField(msg) => write!(f, "Invalid field value: {}", msg),
            ProtocolError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<base64::DecodeError> for ProtocolError {
    fn from(err: base64::DecodeError) -> Self {
        ProtocolError::Base64DecodeError(err.to_string())
    }
}

impl From<serde_json::Error> for ProtocolError {
    fn from(err: serde_json::Error) -> Self {
        ProtocolError::JsonParseError(err.to_string())
    }
}

impl From<std::num::ParseIntError> for ProtocolError {
    fn from(err: std::num::ParseIntError) -> Self {
        ProtocolError::InvalidField(format!("Parse integer error: {}", err))
    }
}
