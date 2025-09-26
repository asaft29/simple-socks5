use simple_socks5::conn::request::CMD;
use simple_socks5::{ATYP, Socks5, conn::reply::Rep, error::SocksError, parse::AddrPort};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), SocksError> {
    let mut server = Socks5::bind("127.0.0.1:1080").await?;
    server.allow_no_auth();
    server.allow_userpass(|u, p| u == "admin" && p == "admin");

    let server = Arc::new(server);

    println!("SOCKS5 proxy listening on {}", server.local_addr()?);

    loop {
        let (client, addr) = server.accept().await?;
        let server_ref = Arc::clone(&server);

        tokio::spawn(async move {
            if let Err(e) = handle_client(server_ref, client).await {
                eprintln!("Error with client {}: {:?}", addr, e);
            }
        });
    }
}

async fn handle_client(server: Arc<Socks5>, mut stream: TcpStream) -> Result<(), SocksError> {
    if let Err(e) = server.authenticate(&mut stream).await {
        eprintln!("Authentication failed: {:?}", e);
        let _ = stream.shutdown().await;
        return Ok(());
    }

    let req = match Socks5::read_conn_request(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to read connection request: {:?}", e);
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    println!("Command = {:?}", req.cmd);

    match req.cmd {
        CMD::Connect => {
            let mut target = match req.dst {
                AddrPort::V4(ip, port) => TcpStream::connect((ip, port)).await?,
                AddrPort::V6(ip, port) => TcpStream::connect((ip, port)).await?,
                AddrPort::Domain(ref host, port) => {
                    TcpStream::connect((host.as_str(), port)).await?
                }
            };

            let local_addr = target.local_addr()?;
            let bnd = match local_addr.ip() {
                IpAddr::V4(ip) => AddrPort::V4(ip, local_addr.port()),
                IpAddr::V6(ip) => AddrPort::V6(ip, local_addr.port()),
            };

            let atyp = match bnd {
                AddrPort::V4(_, _) => ATYP::V4,
                AddrPort::V6(_, _) => ATYP::V6,
                _ => ATYP::DomainName,
            };

            Socks5::send_conn_reply(&mut stream, Rep::Succeeded, atyp, bnd).await?;

            if let Err(e) = io::copy_bidirectional(&mut stream, &mut target).await {
                eprintln!("TCP Connection closed: {:?}", e);
            }
        }

        _ => {
            Socks5::send_conn_reply(
                &mut stream,
                Rep::CommandNotSupported,
                ATYP::V4,
                AddrPort::V4(Ipv4Addr::UNSPECIFIED, 0),
            )
            .await?;
        }
    }

    Ok(())
}
