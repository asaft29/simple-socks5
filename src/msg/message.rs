use super::method::*;
use anyhow::{Result, anyhow};

/// Represents the SOCKS5 version/methods message from the client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMessage {
    pub ver: u8,
    pub methods: Vec<Method>,
}

impl TryFrom<&[u8]> for VersionMessage {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(anyhow!("Version message too short"));
        }

        let ver = bytes[0];
        if ver != 0x05 {
            return Err(anyhow!("Unsupported SOCKS version: {ver}"));
        }

        let nmethods = bytes[1] as usize;
        if bytes.len() < 2 + nmethods {
            return Err(anyhow!("Incomplete version message"));
        }

        let methods: Result<Vec<Method>> = bytes[2..2 + nmethods]
            .iter()
            .map(|b| Method::from_u8(*b))
            .collect();

        Ok(Self {
            ver,
            methods: methods?,
        })
    }
}

impl VersionMessage {
    /// Returns a copy of the methods
    pub fn get_methods(&self) -> Vec<Method> {
        self.methods.clone()
    }
}

/// Represents the server's method selection message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSelection {
    pub ver: u8,
    pub method: Method,
}

impl MethodSelection {
    /// Creates a new method selection response
    pub fn new(method: Method) -> Self {
        Self { ver: 0x05, method }
    }

    /// Converts the method selection into the 2-byte RFC 1928 message
    pub fn to_bytes(&self) -> [u8; 2] {
        [self.ver, self.method.to_u8()]
    }
}
