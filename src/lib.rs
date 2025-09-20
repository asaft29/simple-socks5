use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod method;
pub mod parse;
pub mod reply;
pub mod request;

use method::*;
use parse::AddrPort;
use reply::*;
use request::*;

pub type V4 = Ipv4Addr;
pub type V6 = Ipv6Addr;

const VER5: u8 = 0x05;

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum ATYP {
    V4 = 0x01,
    DomainName = 0x03,
    V6 = 0x04,
}

struct VersionMessage {
    ver: u8,
    methods: Vec<Method>,
}

impl VersionMessage {
    fn from_bytes(buf: &[u8]) -> Option<VersionMessage> {
        if buf.len() < 2 {
            return None;
        }
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
}

pub struct Socks5 {
    listener: TcpListener,
}

impl Socks5 {
    pub async fn new(addr: &str) -> Result<Socks5> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Socks5 { listener })
    }

    pub async fn run(&mut self) -> Result<()> {
        println!("SOCKS5 server running on {:?}", self.listener.local_addr()?);
        loop {
            let (stream, addr) = self.listener.accept().await?;
            println!("Accepted connection from {:?}", addr);
            tokio::spawn(async move {
                if let Err(e) = handle_client(stream).await {
                    eprintln!("Error handling client {}: {:?}", addr, e);
                }
            });
        }
    }
}

async fn handle_client(mut stream: TcpStream) -> Result<()> {
    let mut buf = [0u8; 256];

    let n = stream.read(&mut buf).await?;
    let version_msg =
        VersionMessage::from_bytes(&buf[..n]).ok_or(anyhow::anyhow!("Invalid version message"))?;

    println!(
        "Client version: {}, methods: {:?}",
        version_msg.ver, version_msg.methods
    );

    let method = if version_msg
        .methods
        .contains(&Method::Fixed(FixedMethod::NoAuth))
    {
        Method::Fixed(FixedMethod::NoAuth)
    } else {
        Method::Fixed(FixedMethod::NoAcceptable)
    };

    stream.write_all(&[VER5, method.to_u8()]).await?;
    if method == Method::Fixed(FixedMethod::NoAcceptable) {
        stream.shutdown().await?;
        return Ok(());
    }

    let n = stream.read(&mut buf).await?;
    let request = Request::from_bytes(&buf[..n]).ok_or(anyhow::anyhow!("Invalid request"))?;

    println!("Received SOCKS5 request:");
    println!("  Version: {}", request.ver);
    println!("  Command: {:?}", request.cmd);
    println!("  Reserved: {}", request.rsv);
    println!("  Address type: {:?}", request.atyp);

    match &request.dst {
        AddrPort::V4(ip, port) => {
            println!("  AddrPort: IPv4 {}:{}", ip, port);
        }
        AddrPort::V6(ip, port) => {
            println!("  AddrPort: IPv6 [{}]:{}", ip, port);
        }
        AddrPort::Domain(name, port) => {
            println!("  AddrPort: Domain {}:{}", name, port);
        }
    }

    let target_result = match &request.dst {
        AddrPort::V4(ip, port) => TcpStream::connect((*ip, *port)).await,
        AddrPort::V6(ip, port) => TcpStream::connect((*ip, *port)).await,
        AddrPort::Domain(name, port) => TcpStream::connect((name.as_str(), *port)).await,
    };

    let reply = match target_result {
        Ok(target_stream) => {
            let local_addr = target_stream.local_addr()?;
            let bnd = match local_addr.ip() {
                IpAddr::V4(ip) => AddrPort::V4(ip, local_addr.port()),
                IpAddr::V6(ip) => AddrPort::V6(ip, local_addr.port()),
            };
            Reply {
                ver: VER5,
                rep: Rep::Succeeded,
                rsv: 0x00,
                atyp: match bnd {
                    AddrPort::V4(_, _) => ATYP::V4,
                    AddrPort::V6(_, _) => ATYP::V6,
                    _ => ATYP::DomainName,
                },
                bnd,
            }
        }
        Err(_) => Reply {
            ver: VER5,
            rep: Rep::HostUnreachable,
            rsv: 0x00,
            atyp: ATYP::V4,
            bnd: AddrPort::V4(Ipv4Addr::UNSPECIFIED, 0),
        },
    };

    stream.write_all(&reply.to_bytes()).await?;

    if reply.rep != Rep::Succeeded {
        stream.shutdown().await?;
        return Ok(());
    }

    // 5️⃣TODO: forward data between client and target
    Ok(())
}
