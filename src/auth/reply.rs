use anyhow::{Result, anyhow};

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthStatus {
    Success = 0x00,
    Failure = 0x01, // any non-zero value is failure
}

pub struct AuthReply {
    pub ver: u8,
    pub status: AuthStatus,
}

impl AuthReply {
    pub fn new(status: AuthStatus) -> Self {
        Self { ver: 0x01, status }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        [self.ver, self.status as u8]
    }
}

impl TryFrom<&[u8]> for AuthReply {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 2 {
            return Err(anyhow!(
                "AuthReply must be exactly 2 bytes, got {}",
                bytes.len()
            ));
        }

        let ver = bytes[0];
        if ver != 0x01 {
            return Err(anyhow!("Invalid AuthReply version: {}", ver));
        }

        let status = match bytes[1] {
            0x00 => AuthStatus::Success,
            _ => AuthStatus::Failure,
        };

        Ok(Self { ver, status })
    }
}
