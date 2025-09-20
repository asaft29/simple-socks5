use anyhow::Result;
use sockrs5::Socks5;

#[tokio::main]
async fn main() -> Result<()> {
    let mut server = Socks5::new("127.0.0.1:1080").await?;
    server.run().await?;

    Ok(())
}
