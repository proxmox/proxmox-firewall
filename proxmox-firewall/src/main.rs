use anyhow::Error;

mod config;
mod rule;

fn main() -> Result<(), Error> {
    env_logger::init();
    Ok(())
}
