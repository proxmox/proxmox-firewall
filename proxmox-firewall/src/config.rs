use std::collections::BTreeMap;
use std::default::Default;
use std::fs::{self, DirEntry, File, ReadDir};
use std::io::{self, BufReader};

use anyhow::{bail, format_err, Context, Error};

use proxmox_ve_config::firewall::bridge::Config as BridgeConfig;
use proxmox_ve_config::firewall::cluster::Config as ClusterConfig;
use proxmox_ve_config::firewall::guest::Config as GuestConfig;
use proxmox_ve_config::firewall::host::Config as HostConfig;
use proxmox_ve_config::firewall::types::alias::{Alias, AliasName, AliasScope};

use proxmox_ve_config::guest::types::Vmid;
use proxmox_ve_config::guest::{GuestEntry, GuestMap};
use proxmox_ve_config::host::network::InterfaceMapping;
use proxmox_ve_config::host::network::IpLink;
use proxmox_ve_config::host::types::BridgeName;

use proxmox_nftables::command::{CommandOutput, Commands, List, ListOutput};
use proxmox_nftables::types::ListChain;
use proxmox_nftables::NftClient;
use proxmox_ve_config::sdn::{
    config::{RunningConfig, SdnConfig},
    ipam::{Ipam, IpamJson},
};

pub trait FirewallConfigLoader {
    fn cluster(&self) -> Result<Option<Box<dyn io::BufRead>>, Error>;
    fn host(&self) -> Result<Option<Box<dyn io::BufRead>>, Error>;
    fn guest_list(&self) -> Result<GuestMap, Error>;
    fn guest_config(
        &self,
        vmid: &Vmid,
        guest: &GuestEntry,
    ) -> Result<Option<Box<dyn io::BufRead>>, Error>;
    fn guest_firewall_config(&self, vmid: &Vmid) -> Result<Option<Box<dyn io::BufRead>>, Error>;
    fn sdn_running_config(&self) -> Result<Option<Box<dyn io::BufRead>>, Error>;
    fn ipam(&self) -> Result<Option<Box<dyn io::BufRead>>, Error>;
    fn bridge_list(&self) -> Result<Vec<BridgeName>, Error>;
    fn bridge_firewall_config(
        &self,
        bridge_name: &BridgeName,
    ) -> Result<Option<Box<dyn io::BufRead>>, Error>;
    fn interface_mapping(&self) -> Result<InterfaceMapping, Error>;
}

#[derive(Default)]
pub struct PveFirewallConfigLoader {}

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

fn open_config_folder(path: &str) -> Result<Option<ReadDir>, Error> {
    match fs::read_dir(path) {
        Ok(paths) => Ok(Some(paths)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            log::info!("SDN config folder {path} does not exist");
            Ok(None)
        }
        Err(err) => {
            let context = format!("unable to open configuration folder at {BRIDGE_CONFIG_PATH}");
            Err(anyhow::Error::new(err).context(context))
        }
    }
}

fn fw_name(dir_entry: DirEntry) -> Option<String> {
    dir_entry
        .file_name()
        .to_str()?
        .strip_suffix(".fw")
        .map(str::to_string)
}

const CLUSTER_CONFIG_PATH: &str = "/etc/pve/firewall/cluster.fw";
const HOST_CONFIG_PATH: &str = "/etc/pve/local/host.fw";
const BRIDGE_CONFIG_PATH: &str = "/etc/pve/sdn/firewall";

const SDN_RUNNING_CONFIG_PATH: &str = "/etc/pve/sdn/.running-config";
const SDN_IPAM_PATH: &str = "/etc/pve/sdn/pve-ipam-state.json";
const SDN_IPAM_PATH_LEGACY: &str = "/etc/pve/priv/ipam.db"; // TODO: remove with PVE 9+

impl FirewallConfigLoader for PveFirewallConfigLoader {
    fn cluster(&self) -> Result<Option<Box<dyn io::BufRead>>, Error> {
        log::info!("loading cluster config");

        let fd = open_config_file(CLUSTER_CONFIG_PATH)?;

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Ok(Some(buf_reader));
        }

        Ok(None)
    }

    fn host(&self) -> Result<Option<Box<dyn io::BufRead>>, Error> {
        log::info!("loading host config");

        let fd = open_config_file(HOST_CONFIG_PATH)?;

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Ok(Some(buf_reader));
        }

        Ok(None)
    }

    fn guest_list(&self) -> Result<GuestMap, Error> {
        log::info!("loading vmlist");
        GuestMap::new()
    }

    fn guest_config(
        &self,
        vmid: &Vmid,
        entry: &GuestEntry,
    ) -> Result<Option<Box<dyn io::BufRead>>, Error> {
        log::info!("loading guest #{vmid} config");

        let fd = open_config_file(&GuestMap::config_path(vmid, entry))?;

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Ok(Some(buf_reader));
        }

        Ok(None)
    }

    fn guest_firewall_config(&self, vmid: &Vmid) -> Result<Option<Box<dyn io::BufRead>>, Error> {
        log::info!("loading guest #{vmid} firewall config");

        let fd = open_config_file(&GuestMap::firewall_config_path(vmid))?;

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Ok(Some(buf_reader));
        }

        Ok(None)
    }

    fn sdn_running_config(&self) -> Result<Option<Box<dyn io::BufRead>>, Error> {
        log::info!("loading SDN running-config");

        let fd = open_config_file(SDN_RUNNING_CONFIG_PATH)?;

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Ok(Some(buf_reader));
        }

        Ok(None)
    }

    fn ipam(&self) -> Result<Option<Box<dyn io::BufRead>>, Error> {
        log::info!("loading IPAM config");

        let fd = match open_config_file(SDN_IPAM_PATH)? {
            // fallback to legacy path for compat transition
            None => open_config_file(SDN_IPAM_PATH_LEGACY)?,
            Some(file) => Some(file),
        };

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Ok(Some(buf_reader));
        }

        Ok(None)
    }

    fn bridge_list(&self) -> Result<Vec<BridgeName>, Error> {
        let mut bridges = Vec::new();

        if let Some(files) = open_config_folder(BRIDGE_CONFIG_PATH)? {
            for file in files {
                let bridge_name = fw_name(file?).map(BridgeName::new).transpose()?;

                if let Some(bridge_name) = bridge_name {
                    bridges.push(bridge_name);
                }
            }
        }

        Ok(bridges)
    }

    fn bridge_firewall_config(
        &self,
        bridge_name: &BridgeName,
    ) -> Result<Option<Box<dyn io::BufRead>>, Error> {
        log::info!("loading firewall config for bridge {bridge_name}");

        let fd = open_config_file(&format!("/etc/pve/sdn/firewall/{bridge_name}.fw"))?;

        if let Some(file) = fd {
            let buf_reader = Box::new(BufReader::new(file)) as Box<dyn io::BufRead>;
            return Ok(Some(buf_reader));
        }

        Ok(None)
    }

    fn interface_mapping(&self) -> Result<InterfaceMapping, Error> {
        let output = std::process::Command::new("ip")
            .arg("-details")
            .arg("-json")
            .arg("link")
            .arg("show")
            .stdout(std::process::Stdio::piped())
            .output()
            .with_context(|| "could not obtain ip link output")?;

        if !output.status.success() {
            bail!("ip link returned non-zero exit code")
        }

        Ok(serde_json::from_slice::<Vec<IpLink>>(&output.stdout)
            .with_context(|| "could not deserialize ip link output")?
            .into_iter()
            .collect())
    }
}

pub trait NftConfigLoader {
    fn chains(&self) -> Result<Option<CommandOutput>, Error>;
}

#[derive(Debug, Default)]
pub struct PveNftConfigLoader {}

impl PveNftConfigLoader {
    pub fn new() -> Self {
        Default::default()
    }
}

impl NftConfigLoader for PveNftConfigLoader {
    fn chains(&self) -> Result<Option<CommandOutput>, Error> {
        log::info!("querying nftables config for chains");

        let commands = Commands::new(vec![List::chains()]);

        NftClient::run_json_commands(&commands)
            .with_context(|| "unable to query nft chains".to_string())
    }
}

pub struct FirewallConfig {
    cluster_config: ClusterConfig,
    host_config: HostConfig,
    guest_config: BTreeMap<Vmid, GuestConfig>,
    bridge_config: BTreeMap<BridgeName, BridgeConfig>,
    nft_config: BTreeMap<String, ListChain>,
    sdn_config: Option<SdnConfig>,
    ipam_config: Option<Ipam>,
    interface_mapping: InterfaceMapping,
}

impl FirewallConfig {
    fn parse_cluster(firewall_loader: &dyn FirewallConfigLoader) -> Result<ClusterConfig, Error> {
        match firewall_loader.cluster()? {
            Some(data) => ClusterConfig::parse(data),
            None => {
                log::info!("no cluster config found, falling back to default");
                Ok(ClusterConfig::default())
            }
        }
    }

    fn parse_host(firewall_loader: &dyn FirewallConfigLoader) -> Result<HostConfig, Error> {
        match firewall_loader.host()? {
            Some(data) => HostConfig::parse(data),
            None => {
                log::info!("no host config found, falling back to default");
                Ok(HostConfig::default())
            }
        }
    }

    pub fn parse_guests(
        firewall_loader: &dyn FirewallConfigLoader,
    ) -> Result<BTreeMap<Vmid, GuestConfig>, Error> {
        let mut guests = BTreeMap::new();

        for (vmid, entry) in firewall_loader.guest_list()?.iter() {
            if !entry.is_local() {
                log::debug!("guest #{vmid} is not local, skipping");
                continue;
            }

            let raw_firewall_config = firewall_loader.guest_firewall_config(vmid)?;

            if let Some(raw_firewall_config) = raw_firewall_config {
                log::debug!("found firewall config for #{vmid}, loading guest config");

                let raw_config = firewall_loader
                    .guest_config(vmid, entry)?
                    .ok_or_else(|| format_err!("could not load guest config for #{vmid}"))?;

                let config = GuestConfig::parse(
                    vmid,
                    entry.ty().iface_prefix(),
                    raw_firewall_config,
                    raw_config,
                )?;

                guests.insert(*vmid, config);
            }
        }

        Ok(guests)
    }

    pub fn parse_sdn(
        firewall_loader: &dyn FirewallConfigLoader,
    ) -> Result<Option<SdnConfig>, Error> {
        Ok(match firewall_loader.sdn_running_config()? {
            Some(data) => {
                let running_config: RunningConfig = serde_json::from_reader(data)?;
                Some(SdnConfig::try_from(running_config)?)
            }
            _ => None,
        })
    }

    pub fn parse_ipam(firewall_loader: &dyn FirewallConfigLoader) -> Result<Option<Ipam>, Error> {
        Ok(match firewall_loader.ipam()? {
            Some(data) => {
                let raw_ipam: IpamJson = serde_json::from_reader(data)?;
                Some(Ipam::try_from(raw_ipam)?)
            }
            _ => None,
        })
    }

    pub fn parse_nft(
        nft_loader: &dyn NftConfigLoader,
    ) -> Result<BTreeMap<String, ListChain>, Error> {
        let output = nft_loader
            .chains()?
            .ok_or_else(|| format_err!("no command output from nft query"))?;

        let mut chains = BTreeMap::new();

        for element in &output.nftables {
            if let ListOutput::Chain(chain) = element {
                chains.insert(chain.name().to_owned(), chain.clone());
            }
        }

        Ok(chains)
    }

    pub fn parse_bridges(
        firewall_loader: &dyn FirewallConfigLoader,
    ) -> Result<BTreeMap<BridgeName, BridgeConfig>, Error> {
        let mut bridge_config = BTreeMap::new();

        for bridge_name in firewall_loader.bridge_list()? {
            if let Some(config) = firewall_loader.bridge_firewall_config(&bridge_name)? {
                bridge_config.insert(bridge_name, BridgeConfig::parse(config)?);
            } else {
                bail!("Could not read config for {bridge_name}")
            }
        }

        Ok(bridge_config)
    }

    pub fn new(
        firewall_loader: &dyn FirewallConfigLoader,
        nft_loader: &dyn NftConfigLoader,
    ) -> Result<Self, Error> {
        Ok(Self {
            cluster_config: Self::parse_cluster(firewall_loader)?,
            host_config: Self::parse_host(firewall_loader)?,
            guest_config: Self::parse_guests(firewall_loader)?,
            bridge_config: Self::parse_bridges(firewall_loader)?,
            sdn_config: Self::parse_sdn(firewall_loader)?,
            ipam_config: Self::parse_ipam(firewall_loader)?,
            nft_config: Self::parse_nft(nft_loader)?,
            interface_mapping: firewall_loader.interface_mapping()?,
        })
    }

    pub fn cluster(&self) -> &ClusterConfig {
        &self.cluster_config
    }

    pub fn host(&self) -> &HostConfig {
        &self.host_config
    }

    pub fn guests(&self) -> &BTreeMap<Vmid, GuestConfig> {
        &self.guest_config
    }

    pub fn bridges(&self) -> &BTreeMap<BridgeName, BridgeConfig> {
        &self.bridge_config
    }

    pub fn nft_chains(&self) -> &BTreeMap<String, ListChain> {
        &self.nft_config
    }

    pub fn sdn(&self) -> Option<&SdnConfig> {
        self.sdn_config.as_ref()
    }

    pub fn ipam(&self) -> Option<&Ipam> {
        self.ipam_config.as_ref()
    }

    pub fn is_enabled(&self) -> bool {
        self.cluster().is_enabled() && self.host().nftables()
    }

    pub fn interface_mapping(&self, iface_name: &str) -> Option<&str> {
        self.interface_mapping.get(iface_name).map(|x| x.as_str())
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
