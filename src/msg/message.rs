use super::method::*;
use crate::error::SocksError;

/// Represents the SOCKS5 version/methods message from the client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMessage {
    pub ver: u8,
    pub methods: Vec<Method>,
}

impl TryFrom<&[u8]> for VersionMessage {
    type Error = SocksError;

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
    pub ver: u8,
    pub method: Method,
}

impl MethodSelection {
    pub fn new(method: Method) -> Self {
        Self { ver: 0x05, method }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        [self.ver, self.method.to_u8()]
    }
}

impl TryFrom<&[u8]> for MethodSelection {
    type Error = SocksError;

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
