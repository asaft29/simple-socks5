use crate::error::SocksError;

/// Represents the status of the authentication.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthStatus {
    /// Represents a successful authentication.
    Success = 0x00,
    /// Represents a failed authentication.
    Failure = 0x01, // any non-zero value is failure
}

/// Represents an authentication reply.
pub struct AuthReply {
    /// The version of the authentication protocol.
    pub ver: u8,
    /// The status of the authentication.
    pub status: AuthStatus,
}

impl AuthReply {
    /// Creates a new `AuthReply`.
    ///
    /// # Arguments
    ///
    /// * `status` - The status of the authentication.
    pub fn new(status: AuthStatus) -> Self {
        Self { ver: 0x01, status }
    }

    /// Converts the `AuthReply` to a byte array.
    pub fn to_bytes(&self) -> [u8; 2] {
        [self.ver, self.status as u8]
    }
}

impl TryFrom<&[u8]> for AuthReply {
    type Error = SocksError;

    /// Converts a byte slice to an `AuthReply`.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 2 {
            return Err(SocksError::AuthMessageTooShort);
        }

        let ver = bytes[0];
        if ver != 0x01 {
            return Err(SocksError::UnsupportedAuthVersion(ver));
        }

        let status = match bytes[1] {
            0x00 => AuthStatus::Success,
            _ => AuthStatus::Failure,
        };

        Ok(Self { ver, status })
    }
}