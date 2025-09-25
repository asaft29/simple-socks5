use thiserror::Error;

#[derive(Debug, Error)]
pub enum SocksError {
    // ===== Version / Method Selection =====
    #[error("unsupported SOCKS version: {0}")]
    UnsupportedVersion(u8),

    #[error("version message too short")]
    VersionMessageTooShort,

    #[error("incomplete version message")]
    IncompleteVersionMessage,

    #[error("unknown authentication method: {0}")]
    UnknownMethod(u8),

    // ===== Authentication =====
    #[error("authentication version not supported: {0}")]
    UnsupportedAuthVersion(u8),

    #[error("authentication message too short")]
    AuthMessageTooShort,

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    // ===== Connection =====
    #[error("invalid address type: {0}")]
    InvalidAddressType(u8),

    #[error("invalid domain name")]
    InvalidDomain,

    #[error("connection request too short")]
    ConnRequestTooShort,

    #[error("unsupported command: {0}")]
    UnsupportedCommand(u8),

    #[error("reply too short")]
    ReplyTooShort,

    // ===== General =====
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
