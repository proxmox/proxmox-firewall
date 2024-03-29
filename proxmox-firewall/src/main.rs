use anyhow::Error;

mod config;
mod object;
mod rule;

fn main() -> Result<(), Error> {
    env_logger::init();
    Ok(())
}
