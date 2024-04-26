use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Error};

use proxmox_firewall::config::{FirewallConfig, PveFirewallConfigLoader, PveNftConfigLoader};
use proxmox_firewall::firewall::Firewall;
use proxmox_nftables::{client::NftError, NftClient};

const RULE_BASE: &str = include_str!("../../resources/proxmox-firewall.nft");

const FORCE_DISABLE_FLAG_FILE: &str = "/run/proxmox-nftables-firewall-force-disable";

fn remove_firewall() -> Result<(), std::io::Error> {
    log::info!("removing existing firewall rules");

    for command in Firewall::remove_commands() {
        // can ignore other errors, since it fails when tables do not exist
        if let Err(NftError::Io(err)) = NftClient::run_json_commands(&command) {
            return Err(err);
        }
    }

    Ok(())
}

fn handle_firewall() -> Result<(), Error> {
    let config = FirewallConfig::new(&PveFirewallConfigLoader::new(), &PveNftConfigLoader::new())?;

    let firewall = Firewall::new(config);

    if !firewall.is_enabled() {
        return remove_firewall().with_context(|| "could not remove firewall tables".to_string());
    }

    log::info!("creating the firewall skeleton");
    NftClient::run_commands(RULE_BASE)?;

    let commands = firewall.full_host_fw()?;

    log::info!("Running proxmox-firewall commands");
    for (idx, c) in commands.iter().enumerate() {
        log::debug!("cmd #{idx} {}", serde_json::to_string(&c)?);
    }

    let response = NftClient::run_json_commands(&commands)?;

    if let Some(output) = response {
        log::debug!("got response from nftables: {output:?}");
    }

    Ok(())
}

fn init_logger() {
    match std::env::var("RUST_LOG_STYLE") {
        Ok(s) if s == "SYSTEMD" => env_logger::builder()
            .format(|buf, record| {
                writeln!(
                    buf,
                    "<{}>{}: {}",
                    match record.level() {
                        log::Level::Error => 3,
                        log::Level::Warn => 4,
                        log::Level::Info => 6,
                        log::Level::Debug => 7,
                        log::Level::Trace => 7,
                    },
                    record.target(),
                    record.args()
                )
            })
            .init(),
        _ => env_logger::init(),
    };
}

fn main() -> Result<(), std::io::Error> {
    init_logger();

    let term = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))?;

    let force_disable_flag = std::path::Path::new(FORCE_DISABLE_FLAG_FILE);

    while !term.load(Ordering::Relaxed) {
        if force_disable_flag.exists() {
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }
        let start = Instant::now();

        if let Err(error) = handle_firewall() {
            log::error!("error updating firewall rules: {error}");
        }

        let duration = start.elapsed();
        log::info!("firewall update time: {}ms", duration.as_millis());

        std::thread::sleep(Duration::from_secs(5));
    }

    remove_firewall()
}
