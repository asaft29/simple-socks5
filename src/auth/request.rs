use crate::VER;
use crate::error::SocksError;

/// Represents an authentication request.
pub struct AuthRequest {
    /// The version of the authentication protocol.
    pub ver: u8,
    /// The username.
    pub uname: String,
    /// The password.
    pub passwd: String,
}

impl AuthRequest {
    /// Creates a new `AuthRequest`.
    ///
    /// # Arguments
    ///
    /// * `uname` - The username.
    /// * `passwd` - The password.
    pub fn new(uname: String, passwd: String) -> Self {
        Self {
            ver: VER,
            uname,
            passwd,
        }
    }
}

impl TryFrom<&[u8]> for AuthRequest {
    type Error = SocksError;

    /// Converts a byte slice to an `AuthRequest`.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 2 {
            return Err(SocksError::AuthMessageTooShort);
        }

        let ver = bytes[0];
        if ver != VER {
            return Err(SocksError::UnsupportedAuthVersion(ver));
        }

        let ulen = bytes[1] as usize;
        if bytes.len() < 2 + ulen + 1 {
            return Err(SocksError::AuthFailed("truncated before username".into()));
        }

        let uname = String::from_utf8(bytes[2..2 + ulen].to_vec())
            .map_err(|_| SocksError::AuthFailed("invalid UTF-8 in username".into()))?;

        let plen_index = 2 + ulen;
        let plen = bytes[plen_index] as usize;

        if bytes.len() < plen_index + 1 + plen {
            return Err(SocksError::AuthFailed("truncated before password".into()));
        }

        let passwd = String::from_utf8(bytes[plen_index + 1..plen_index + 1 + plen].to_vec())
            .map_err(|_| SocksError::AuthFailed("invalid UTF-8 in password".into()))?;

        Ok(Self { ver, uname, passwd })
    }
}

