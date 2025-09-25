use thiserror::Error;

/// Represents the possible errors that can occur while using the SOCKS5 server.
#[derive(Debug, Error)]
pub enum SocksError {
    // ===== Version / Method Selection =====
    /// Occurs when the client requests an unsupported SOCKS version.
    #[error("unsupported SOCKS version: {0}")]
    UnsupportedVersion(u8),

    /// Occurs when the version message from the client is too short.
    #[error("version message too short")]
    VersionMessageTooShort,

    /// Occurs when the version message from the client is incomplete.
    #[error("incomplete version message")]
    IncompleteVersionMessage,

    /// Occurs when the client requests an unknown authentication method.
    #[error("unknown authentication method: {0}")]
    UnknownMethod(u8),

    // ===== Authentication =====
    /// Occurs when the client uses an unsupported authentication version.
    #[error("authentication version not supported: {0}")]
    UnsupportedAuthVersion(u8),

    /// Occurs when the authentication message from the client is too short.
    #[error("authentication message too short")]
    AuthMessageTooShort,

    /// Occurs when the client's authentication fails.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    // ===== Connection =====
    /// Occurs when the client provides an invalid address type.
    #[error("invalid address type: {0}")]
    InvalidAddressType(u8),

    /// Occurs when the client provides an invalid domain name.
    #[error("invalid domain name")]
    InvalidDomain,

    /// Occurs when the connection request from the client is too short.
    #[error("connection request too short")]
    ConnRequestTooShort,

    /// Occurs when the client requests an unsupported command.
    #[error("unsupported command: {0}")]
    UnsupportedCommand(u8),

    /// Occurs when the reply message is too short.
    #[error("reply too short")]
    ReplyTooShort,

    // ===== General =====
    /// Occurs when an I/O error happens.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}