use std::net::{Ipv4Addr, Ipv6Addr};

/// Helper enum to represent an IP address and port
pub enum IpPort {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
}

/// Parse IPv4 or IPv6 from a byte slice
///
/// # Arguments
/// * `buf` - slice of bytes containing the address starting at offset 0
/// * `atyp` - ATYP value: 0x01 = IPv4, 0x04 = IPv6
///
/// # Returns
/// * Some((IpPort, bytes_consumed)) if successful
/// * None if buffer is too short or invalid
pub fn parse_ip_port(buf: &[u8], atyp: u8) -> Option<(IpPort, usize)> {
    match atyp {
        0x01 => {
            // IPv4
            if buf.len() < 6 {
                return None;
            } // 4 bytes IP + 2 bytes port
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Some((IpPort::V4(ip, port), 6))
        }
        0x04 => {
            // IPv6
            if buf.len() < 18 {
                return None;
            } // 16 bytes IP + 2 bytes port
            let ip = Ipv6Addr::new(
                ((buf[0] as u16) << 8) | buf[1] as u16,
                ((buf[2] as u16) << 8) | buf[3] as u16,
                ((buf[4] as u16) << 8) | buf[5] as u16,
                ((buf[6] as u16) << 8) | buf[7] as u16,
                ((buf[8] as u16) << 8) | buf[9] as u16,
                ((buf[10] as u16) << 8) | buf[11] as u16,
                ((buf[12] as u16) << 8) | buf[13] as u16,
                ((buf[14] as u16) << 8) | buf[15] as u16,
            );
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Some((IpPort::V6(ip, port), 18))
        }
        _ => None,
    }
}
