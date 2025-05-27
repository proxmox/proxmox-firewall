use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, format_err, Context, Error};
use pico_args::Arguments;

use proxmox_firewall::config::{FirewallConfig, PveFirewallConfigLoader, PveNftConfigLoader};
use proxmox_firewall::firewall::Firewall;
use proxmox_log as log;
use proxmox_log::{LevelFilter, Logger};
use proxmox_nftables::{client::NftError, NftClient};
use proxmox_ve_config::firewall::host::Config as HostConfig;

const HELP: &str = r#"
USAGE:
  proxmox-firewall <COMMAND>

COMMANDS:
  help              Prints this help message.
  skeleton          Prints the firewall rule skeleton as accepted by 'nft -f -'
  compile           Compile and print firewall rules as accepted by 'nft -j -f -'
  start             Execute proxmox-firewall service in foreground
  localnet          Print the contents of the management ipset
"#;

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

fn create_firewall_instance() -> Result<Firewall, Error> {
    let config = FirewallConfig::new(&PveFirewallConfigLoader::new(), &PveNftConfigLoader::new())?;
    Ok(Firewall::new(config))
}

fn handle_firewall() -> Result<(), Error> {
    let firewall = create_firewall_instance()?;

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

fn init_logger(command: Command) -> Result<(), Error> {
    let mut logger = Logger::from_env("PVE_LOG", LevelFilter::WARN);

    if command == Command::Start {
        logger = logger.journald();
    } else {
        logger = logger.stderr_pve();
    }

    logger.init()
}

fn run_firewall() -> Result<(), Error> {
    let term = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))?;

    // simple flag that is set by legacy pve-firewall and provides a side-channel to signal that
    // we're disabled here without the need to parse the config, avoiding log-spam errors from that
    let force_disable_flag = std::path::Path::new(FORCE_DISABLE_FLAG_FILE);

    while !term.load(Ordering::Relaxed) {
        if force_disable_flag.exists() {
            if let Err(error) = remove_firewall() {
                log::error!("unable to disable firewall: {error:?}");
            }

            std::thread::sleep(Duration::from_secs(5));
            continue;
        }
        let start = Instant::now();

        if let Err(error) = handle_firewall() {
            log::error!("error updating firewall rules: {error:#}");
        }

        let duration = start.elapsed();
        log::info!("firewall update time: {}ms", duration.as_millis());

        std::thread::sleep(Duration::from_secs(5));
    }

    remove_firewall().with_context(|| "Could not remove firewall rules")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Compile,
    Help,
    Skeleton,
    Start,
    Localnet,
}

impl std::str::FromStr for Command {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "help" => Command::Help,
            "compile" => Command::Compile,
            "skeleton" => Command::Skeleton,
            "start" => Command::Start,
            "localnet" => Command::Localnet,
            cmd => {
                bail!("{cmd} is not a valid command")
            }
        })
    }
}

fn run_command(command: Command) -> Result<(), Error> {
    init_logger(command)?;

    match command {
        Command::Help => {
            println!("{}", HELP);
        }
        Command::Compile => {
            let commands = create_firewall_instance()?.full_host_fw()?;
            let json = serde_json::to_string_pretty(&commands)?;

            println!("{json}");
        }
        Command::Skeleton => {
            println!("{}", RULE_BASE);
        }
        Command::Start => run_firewall()?,
        Command::Localnet => {
            let management_ips = HostConfig::management_ips()?;

            println!("Management IPSet:");
            for ip in management_ips {
                println!("{ip}");
            }
        }
    };

    Ok(())
}

fn main() -> Result<(), Error> {
    let mut args = Arguments::from_env();

    let parsed_command = args
        .subcommand()?
        .ok_or_else(|| format_err!("No subcommand specified!\n{}", HELP))?
        .parse();

    if let Ok(command) = parsed_command {
        run_command(command)
    } else {
        eprintln!("Invalid command specified!\n{}", HELP);
        std::process::exit(1);
    }
}
