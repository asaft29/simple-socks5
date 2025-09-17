use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod method;

use method::*;

const VER5: u8 = 0x05;

struct VersionMessage {
    ver: u8,
    methods: Vec<Method>,
}

// TODO : Display for better logging information
impl VersionMessage {
    fn from_bytes(buf: &[u8]) -> Option<VersionMessage> {
        if buf.len() < 2 {
            return None;
        }
        // TODO : maybe check to see if the version matches?
        let ver = buf[0];
        let nmeth = buf[1] as usize;

        if buf.len() < 2 + nmeth {
            return None;
        }

        let methods = buf[2..2 + nmeth]
            .iter()
            .filter_map(|b| Method::from_u8(*b).ok())
            .collect();

        Some(VersionMessage { ver, methods })
    }

    fn nmeth(&self) -> u8 {
        self.methods.len() as u8
    }
}
pub struct Socks5 {}
