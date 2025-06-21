use std::path::Path;

use eyre::Result;
use ruxy_server::RuxyServer;

pub fn main() -> Result<()> {
    color_eyre::install()?;

    if ruxy_server::should_start_server() {
        ruxy_server::daemonize(|| {
            ruxy_server::init_logging(ruxy_server::LOG_DIR, ruxy_server::LOG_FILE)?;
            RuxyServer::new()?.run()?;
            Ok(())
        })?;
    }

    with_retry(50, || Path::new(ruxy_server::SOCKET_PATH).exists())?;
    ruxy_client::RuxyClient::new(ruxy_server::SOCKET_PATH)?.run()?;

    Ok(())
}

fn with_retry<F>(max_attempts: usize, try_fn: F) -> Result<()>
where
    F: Fn() -> bool,
{
    let mut attempts = 0;
    while !try_fn() {
        if attempts >= max_attempts {
            eyre::bail!("Max connection attempts exceeded");
        }
        attempts += 1;
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(())
}
