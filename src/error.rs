//! SOCKS5 error definitions.
//!
//! This module defines [`SocksError`], the unified error type used across the
//! SOCKS5 implementation. Errors are grouped by protocol phase:
//! - **Version / Method Selection** (RFC 1928 §3).
//! - **Authentication** (RFC 1929).
//! - **Connection requests and replies** (RFC 1928 §4–5).
//! - **General I/O errors** from the underlying transport.
//!
//! Each variant carries enough context to help diagnose protocol violations
//! or unexpected input during parsing.

use thiserror::Error;

/// Represents all possible errors that can occur while using the SOCKS5 server.
#[derive(Debug, Error)]
pub enum SocksError {
    // ===== Version / Method Selection =====
    /// The client requested an unsupported SOCKS protocol version.
    #[error("unsupported SOCKS version: {0}")]
    UnsupportedVersion(u8),

    /// The client's version message was too short to contain mandatory fields.
    #[error("version message too short")]
    VersionMessageTooShort,

    /// The client's version message was truncated and missing method bytes.
    #[error("incomplete version message")]
    IncompleteVersionMessage,

    /// The client requested an unknown or invalid authentication method.
    #[error("unknown authentication method: {0}")]
    UnknownMethod(u8),

    // ===== Authentication =====
    /// The client used an unsupported authentication version.
    #[error("authentication version not supported: {0}")]
    UnsupportedAuthVersion(u8),

    /// The authentication message from the client was too short.
    #[error("authentication message too short")]
    AuthMessageTooShort,

    /// The client's authentication attempt failed with a reason.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    // ===== Connection =====
    /// The client specified an invalid or unsupported address type.
    #[error("invalid address type: {0}")]
    InvalidAddressType(u8),

    /// The client provided an invalid or malformed domain name.
    #[error("invalid domain name")]
    InvalidDomain,

    /// The connection request from the client was too short.
    #[error("connection request too short")]
    ConnRequestTooShort,

    /// The client requested an unsupported command (e.g., not CONNECT/BIND/UDP).
    #[error("unsupported command: {0}")]
    UnsupportedCommand(u8),

    /// The reply message from the server was too short.
    #[error("reply too short")]
    ReplyTooShort,

    // ===== General =====
    /// A general I/O error occurred in the underlying transport.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

