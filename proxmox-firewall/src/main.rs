use anyhow::Error;

mod config;
mod firewall;
mod object;
mod rule;

fn main() -> Result<(), Error> {
    env_logger::init();
    Ok(())
}
