use eyre::Result;
use ruxy_server::RuxyServer;

pub fn main() -> Result<()> {
    color_eyre::install()?;

    if ruxy_server::should_start_server() {
        ruxy_server::daemonize(|| {
            RuxyServer::new()?.run()?;
            Ok(())
        })?;
    } else {
        println!("ruxy is already running");
    }

    Ok(())
}
