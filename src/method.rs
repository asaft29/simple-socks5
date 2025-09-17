// method.rs

use anyhow::{Result, anyhow};

/// A wrapper for a human-readable description of a SOCKS5 method.
pub struct MethodMessage(pub String);

/// Trait for getting a human-readable description of a method.
pub(crate) trait Description {
    fn description(&self) -> MethodMessage;
}

/// Trait to convert to and from u8
pub(crate) trait ToFromBytes: Sized {
    fn to_u8(self) -> u8;
    fn from_u8(byte: u8) -> Result<Self>;
}

/// Represents the fixed SOCKS5 authentication methods.
#[repr(u8)]
#[derive(Clone, Copy)]
pub(crate) enum FixedMethod {
    NoAuth = 0x00,
    GssApi = 0x01,
    UsePass = 0x02,
    NoAcceptable = 0xFF,
}

impl Description for FixedMethod {
    fn description(&self) -> MethodMessage {
        let msg = match self {
            FixedMethod::NoAuth => "NO AUTHENTICATION REQUIRED".to_string(),
            FixedMethod::GssApi => "GSSAPI".to_string(),
            FixedMethod::UsePass => "USERNAME/PASSWORD".to_string(),
            FixedMethod::NoAcceptable => "NO ACCEPTABLE METHODS".to_string(),
        };
        MethodMessage(msg)
    }
}

/// Represents any SOCKS5 method, including fixed, IANA-assigned, and private ranges.
pub(crate) enum Method {
    Fixed(FixedMethod),
    IanaAssigned(u8),
    Private(u8),
}

impl Description for Method {
    fn description(&self) -> MethodMessage {
        let msg = match self {
            Method::Fixed(f) => f.description().0,
            Method::IanaAssigned(b) => format!("IANA ASSIGNED METHOD 0x{:02X}", b),
            Method::Private(b) => format!("PRIVATE METHOD 0x{:02X}", b),
        };
        MethodMessage(msg)
    }
}

impl ToFromBytes for FixedMethod {
    fn to_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(byte: u8) -> Result<Self> {
        match byte {
            0x00 => Ok(FixedMethod::NoAuth),
            0x01 => Ok(FixedMethod::GssApi),
            0x02 => Ok(FixedMethod::UsePass),
            0xFF => Ok(FixedMethod::NoAcceptable),
            _ => Err(anyhow!(
                "Value doesn't match with anything : 0x{:02X}",
                byte
            )),
        }
    }
}

impl ToFromBytes for Method {
    fn to_u8(self) -> u8 {
        match self {
            Method::Fixed(f) => f.to_u8(),
            Method::IanaAssigned(b) => b,
            Method::Private(b) => b,
        }
    }

    fn from_u8(byte: u8) -> Result<Self> {
        match byte {
            0x00 => Ok(Method::Fixed(FixedMethod::NoAuth)),
            0x01 => Ok(Method::Fixed(FixedMethod::GssApi)),
            0x02 => Ok(Method::Fixed(FixedMethod::UsePass)),
            0xFF => Ok(Method::Fixed(FixedMethod::NoAcceptable)),
            0x03..=0x7F => Ok(Method::IanaAssigned(byte)),
            0x80..=0xFE => Ok(Method::Private(byte)),
        }
    }
}
