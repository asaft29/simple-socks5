use dotenv::dotenv;
use sockrs5::{Socks5, error::SocksError};

#[tokio::main]
async fn main() -> Result<(), SocksError> {
    dotenv().ok();

    let mut server = Socks5::new("[::1]:1080").await?;
    server.run().await?;
    Ok(())
}

