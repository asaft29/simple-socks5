use super::method::*;
use crate::error::SocksError;

/// Represents the SOCKS5 version/methods message from the client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMessage {
    /// The SOCKS5 protocol version.
    pub ver: u8,
    /// The methods supported by the client.
    pub methods: Vec<Method>,
}

impl TryFrom<&[u8]> for VersionMessage {
    type Error = SocksError;

    /// Converts a byte slice to a `VersionMessage`.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 2 {
            return Err(SocksError::VersionMessageTooShort);
        }

        let ver = bytes[0];
        if ver != 0x05 {
            return Err(SocksError::UnsupportedVersion(ver));
        }

        let nmethods = bytes[1] as usize;
        if bytes.len() < 2 + nmethods {
            return Err(SocksError::IncompleteVersionMessage);
        }

        let mut methods = Vec::with_capacity(nmethods);
        for b in &bytes[2..2 + nmethods] {
            methods.push(Method::from_u8(*b)?);
        }

        Ok(Self { ver, methods })
    }
}

/// Represents the server's method selection message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSelection {
    /// The SOCKS5 protocol version.
    pub ver: u8,
    /// The method selected by the server.
    pub method: Method,
}

impl MethodSelection {
    /// Creates a new `MethodSelection`.
    ///
    /// # Arguments
    ///
    /// * `method` - The method selected by the server.
    pub fn new(method: Method) -> Self {
        Self { ver: 0x05, method }
    }

    /// Converts the `MethodSelection` to a byte array.
    pub fn to_bytes(&self) -> [u8; 2] {
        [self.ver, self.method.to_u8()]
    }
}

impl TryFrom<&[u8]> for MethodSelection {
    type Error = SocksError;

    /// Converts a byte slice to a `MethodSelection`.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 2 {
            return Err(SocksError::VersionMessageTooShort);
        }

        let ver = bytes[0];
        if ver != 0x05 {
            return Err(SocksError::UnsupportedVersion(ver));
        }

        let method = Method::from_u8(bytes[1])?;
        Ok(Self { ver, method })
    }
}