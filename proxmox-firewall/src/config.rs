use std::collections::BTreeMap;
use std::default::Default;
use std::fs::File;
use std::io::{self, BufReader};
use std::sync::OnceLock;

use anyhow::Error;

use proxmox_ve_config::firewall::cluster::Config as ClusterConfig;
use proxmox_ve_config::firewall::guest::Config as GuestConfig;
use proxmox_ve_config::firewall::host::Config as HostConfig;
use proxmox_ve_config::firewall::types::alias::{Alias, AliasName, AliasScope};

use proxmox_ve_config::guest::types::Vmid;
use proxmox_ve_config::guest::{GuestEntry, GuestMap};

use proxmox_nftables::command::{CommandOutput, Commands, List, ListOutput};
use proxmox_nftables::types::ListChain;
use proxmox_nftables::NftClient;

pub trait FirewallConfigLoader {
    fn cluster(&self) -> Option<Box<dyn io::BufRead>>;
    fn host(&self) -> Option<Box<dyn io::BufRead>>;
    fn guest_list(&self) -> GuestMap;
    fn guest_config(&self, vmid: &Vmid, guest: &GuestEntry) -> Option<Box<dyn io::BufRead>>;
    fn guest_firewall_config(&self, vmid: &Vmid) -> Option<Box<dyn io::BufRead>>;
}

#[derive(Default)]
struct PveFirewallConfigLoader {}

impl PveFirewallConfigLoader {
    pub fn new() -> Self {
        Default::default()
    }
}

/// opens a configuration file
///
/// It returns a file handle to the file or [`None`] if it doesn't exist.
fn open_config_file(path: &str) -> Result<Option<File>, Error> {
    match File::open(path) {
        Ok(data) => Ok(Some(data)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            log::info!("config file does not exist: {path}");
            Ok(None)
        }
        Err(err) => {
            let context = format!("unable to open configuration file at {path}");
            Err(anyhow::Error::new(err).context(context))
        }
    }
}

const CLUSTER_CONFIG_PATH: &str = "/etc/pve/firewall/cluster.fw";
const HOST_CONFIG_PATH: &str = "/etc/pve/local/host.fw";

impl FirewallConfigLoader for PveFirewallConfigLoader {
    fn cluster(&self) -> Option<Box<dyn io::BufRead>> {
        log::info!("loading cluster config");

        let fd =
            open_config_file(CLUSTER_CONFIG_PATH).expect("able to read cluster firewall config");

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Some(buf_reader);
        }

        None
    }

    fn host(&self) -> Option<Box<dyn io::BufRead>> {
        log::info!("loading host config");

        let fd = open_config_file(HOST_CONFIG_PATH).expect("able to read host firewall config");

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Some(buf_reader);
        }

        None
    }

    fn guest_list(&self) -> GuestMap {
        log::info!("loading vmlist");
        GuestMap::new().expect("able to read vmlist")
    }

    fn guest_config(&self, vmid: &Vmid, entry: &GuestEntry) -> Option<Box<dyn io::BufRead>> {
        log::info!("loading guest #{vmid} config");

        let fd = open_config_file(&GuestMap::config_path(vmid, entry))
            .expect("able to read guest config");

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Some(buf_reader);
        }

        None
    }

    fn guest_firewall_config(&self, vmid: &Vmid) -> Option<Box<dyn io::BufRead>> {
        log::info!("loading guest #{vmid} firewall config");

        let fd = open_config_file(&GuestMap::firewall_config_path(vmid))
            .expect("able to read guest firewall config");

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Some(buf_reader);
        }

        None
    }
}

pub trait NftConfigLoader {
    fn chains(&self) -> CommandOutput;
}

#[derive(Debug, Default)]
pub struct PveNftConfigLoader {}

impl PveNftConfigLoader {
    pub fn new() -> Self {
        Default::default()
    }
}

impl NftConfigLoader for PveNftConfigLoader {
    fn chains(&self) -> CommandOutput {
        log::info!("querying nftables config for chains");

        let commands = Commands::new(vec![List::chains()]);

        NftClient::run_json_commands(&commands)
            .expect("can query chains in nftables")
            .expect("nft returned output")
    }
}

pub struct FirewallConfig {
    firewall_loader: Box<dyn FirewallConfigLoader>,
    nft_loader: Box<dyn NftConfigLoader>,
    cluster_config: OnceLock<ClusterConfig>,
    host_config: OnceLock<HostConfig>,
    guest_config: OnceLock<BTreeMap<Vmid, GuestConfig>>,
    nft_config: OnceLock<BTreeMap<String, ListChain>>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            firewall_loader: Box::new(PveFirewallConfigLoader::new()),
            nft_loader: Box::new(PveNftConfigLoader::new()),
            cluster_config: OnceLock::new(),
            host_config: OnceLock::new(),
            guest_config: OnceLock::new(),
            nft_config: OnceLock::new(),
        }
    }
}

impl FirewallConfig {
    pub fn new(
        firewall_loader: Box<dyn FirewallConfigLoader>,
        nft_loader: Box<dyn NftConfigLoader>,
    ) -> Self {
        Self {
            firewall_loader,
            nft_loader,
            cluster_config: OnceLock::new(),
            host_config: OnceLock::new(),
            guest_config: OnceLock::new(),
            nft_config: OnceLock::new(),
        }
    }

    pub fn cluster(&self) -> &ClusterConfig {
        self.cluster_config.get_or_init(|| {
            let raw_config = self.firewall_loader.cluster();

            match raw_config {
                Some(data) => ClusterConfig::parse(data).expect("cluster firewall config is valid"),
                None => {
                    log::info!("no cluster config found, falling back to default");
                    ClusterConfig::default()
                }
            }
        })
    }

    pub fn host(&self) -> &HostConfig {
        self.host_config.get_or_init(|| {
            let raw_config = self.firewall_loader.host();

            match raw_config {
                Some(data) => HostConfig::parse(data).expect("host firewall config is valid"),
                None => {
                    log::info!("no host config found, falling back to default");
                    HostConfig::default()
                }
            }
        })
    }

    pub fn guests(&self) -> &BTreeMap<Vmid, GuestConfig> {
        self.guest_config.get_or_init(|| {
            let mut guests = BTreeMap::new();

            for (vmid, entry) in self.firewall_loader.guest_list().iter() {
                if !entry.is_local() {
                    log::debug!("guest #{vmid} is not local, skipping");
                    continue;
                }

                let raw_firewall_config = self.firewall_loader.guest_firewall_config(vmid);

                if let Some(raw_firewall_config) = raw_firewall_config {
                    log::debug!("found firewall config for #{vmid}, loading guest config");

                    let raw_config = self
                        .firewall_loader
                        .guest_config(vmid, entry)
                        .expect("guest config exists if firewall config exists");

                    let config = GuestConfig::parse(
                        vmid,
                        entry.ty().iface_prefix(),
                        raw_firewall_config,
                        raw_config,
                    )
                    .expect("guest config is valid");

                    guests.insert(*vmid, config);
                }
            }

            guests
        })
    }

    pub fn nft_chains(&self) -> &BTreeMap<String, ListChain> {
        self.nft_config.get_or_init(|| {
            let output = self.nft_loader.chains();
            let mut chains = BTreeMap::new();

            for element in &output.nftables {
                if let ListOutput::Chain(chain) = element {
                    chains.insert(chain.name().to_owned(), chain.clone());
                }
            }

            chains
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.cluster().is_enabled() && self.host().nftables()
    }

    pub fn alias(&self, name: &AliasName, vmid: Option<Vmid>) -> Option<&Alias> {
        log::trace!("getting alias {name:?}");

        match name.scope() {
            AliasScope::Datacenter => self.cluster().alias(name.name()),
            AliasScope::Guest => {
                if let Some(vmid) = vmid {
                    if let Some(entry) = self.guests().get(&vmid) {
                        return entry.alias(name);
                    }

                    log::warn!("trying to get alias {name} for non-existing guest: #{vmid}");
                }

                None
            }
        }
    }
}
