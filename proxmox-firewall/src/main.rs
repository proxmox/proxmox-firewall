use anyhow::Error;

mod config;

fn main() -> Result<(), Error> {
    env_logger::init();
    Ok(())
}
