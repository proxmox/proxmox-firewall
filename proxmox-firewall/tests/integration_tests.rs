use anyhow::{Context, Error};
use std::collections::HashMap;

use proxmox_firewall::config::{FirewallConfig, FirewallConfigLoader, NftConfigLoader};
use proxmox_firewall::firewall::Firewall;
use proxmox_network_api::{AltnameMapping, IpLink};
use proxmox_nftables::command::CommandOutput;
use proxmox_sys::nodename;
use proxmox_ve_config::guest::types::Vmid;
use proxmox_ve_config::guest::{GuestEntry, GuestMap, GuestType};
use proxmox_ve_config::host::types::BridgeName;

/// The SDN running configuration returned by [`MockFirewallConfigLoader`].
enum MockSdnConfig {
    Valid,
    Invalid,
    InvalidIpam,
    ReadError,
}

/// A reader that fails like a configuration file whose content cannot be read.
struct FailingReader;

impl std::io::Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("read error"))
    }
}

struct MockFirewallConfigLoader {
    mounted: bool,
    sdn_config: MockSdnConfig,
}

impl MockFirewallConfigLoader {
    pub fn new() -> Self {
        Self::with_sdn_config(MockSdnConfig::Valid)
    }

    pub fn with_sdn_config(sdn_config: MockSdnConfig) -> Self {
        Self {
            mounted: true,
            sdn_config,
        }
    }
}

impl FirewallConfigLoader for MockFirewallConfigLoader {
    fn check_mounted(&self) -> Result<(), Error> {
        if !self.mounted {
            anyhow::bail!("not mounted");
        }

        Ok(())
    }

    fn cluster(&self) -> Result<Option<Box<dyn std::io::BufRead>>, Error> {
        Ok(Some(Box::new(include_str!("input/cluster.fw").as_bytes())))
    }

    fn host(&self) -> Result<Option<Box<dyn std::io::BufRead>>, Error> {
        Ok(Some(Box::new(include_str!("input/host.fw").as_bytes())))
    }

    fn guest_list(&self) -> Result<GuestMap, Error> {
        let hostname = nodename().to_string();

        let mut map = HashMap::new();

        let entry = GuestEntry::new(hostname.clone(), GuestType::Vm);
        map.insert(101.into(), entry);

        let entry = GuestEntry::new(hostname, GuestType::Ct);
        map.insert(100.into(), entry);

        Ok(GuestMap::from(map))
    }

    fn guest_config(
        &self,
        vmid: &Vmid,
        _guest: &GuestEntry,
    ) -> Result<Option<Box<dyn std::io::BufRead>>, Error> {
        if *vmid == Vmid::new(101) {
            return Ok(Some(Box::new(include_str!("input/101.conf").as_bytes())));
        }

        if *vmid == Vmid::new(100) {
            return Ok(Some(Box::new(include_str!("input/100.conf").as_bytes())));
        }

        Ok(None)
    }

    fn guest_firewall_config(
        &self,
        vmid: &Vmid,
    ) -> Result<Option<Box<dyn std::io::BufRead>>, Error> {
        if *vmid == Vmid::new(101) {
            return Ok(Some(Box::new(include_str!("input/101.fw").as_bytes())));
        }

        if *vmid == Vmid::new(100) {
            return Ok(Some(Box::new(include_str!("input/100.fw").as_bytes())));
        }

        Ok(None)
    }

    fn sdn_running_config(&self) -> Result<Option<Box<dyn std::io::BufRead>>, Error> {
        Ok(Some(match self.sdn_config {
            MockSdnConfig::Valid | MockSdnConfig::InvalidIpam => {
                Box::new(include_str!("input/.running-config.json").as_bytes())
            }
            MockSdnConfig::Invalid => Box::new("{ invalid".as_bytes()),
            MockSdnConfig::ReadError => Box::new(std::io::BufReader::new(FailingReader)),
        }))
    }

    fn ipam(&self) -> Result<Option<Box<dyn std::io::BufRead>>, Error> {
        Ok(Some(match self.sdn_config {
            MockSdnConfig::InvalidIpam => Box::new("{ invalid".as_bytes()),
            _ => Box::new(include_str!("input/ipam.db").as_bytes()),
        }))
    }

    fn bridge_list(&self) -> Result<Vec<BridgeName>, Error> {
        Ok(Vec::new())
    }

    fn bridge_firewall_config(
        &self,
        _bridge_name: &BridgeName,
    ) -> Result<Option<Box<dyn std::io::BufRead>>, Error> {
        Ok(None)
    }

    fn interface_mapping(&self) -> Result<AltnameMapping, Error> {
        Ok(AltnameMapping::from_iter(vec![]))
    }

    fn network_links(&self) -> Result<Vec<IpLink>, Error> {
        let link = |name: &str, kind: Option<&str>, master: Option<&str>, parent: Option<&str>| {
            let linkinfo = kind.map(|kind| match kind {
                "vlan" => serde_json::json!({
                    "info_kind": kind,
                    "info_data": { "protocol": "802.1Q", "id": 50 },
                }),
                "vlan-ad" => serde_json::json!({
                    "info_kind": "vlan",
                    "info_data": { "protocol": "802.1ad", "id": 51 },
                }),
                _ => serde_json::json!({ "info_kind": kind }),
            });

            serde_json::from_value(serde_json::json!({
                "ifindex": 1,
                "ifname": name,
                "link_type": "ether",
                "operstate": "UP",
                "master": master,
                "link": parent,
                "linkinfo": linkinfo,
            }))
            .expect("valid link")
        };

        Ok(vec![
            link("vrf_test", Some("vrf"), None, None),
            link("public", Some("bridge"), Some("vrf_test"), None),
            link("vmbr0", Some("bridge"), None, None),
            link("vmbr0.50", Some("vlan"), Some("vrf_test"), Some("vmbr0")),
            link("vmbr0.51", Some("vlan-ad"), Some("vrf_test"), Some("vmbr0")),
            link("vmbr1", Some("bridge"), Some("vrf_test"), None),
            link("eth1", None, None, None),
            link("eth1.50", Some("vlan"), Some("vrf_test"), Some("eth1")),
        ])
    }
}

struct MockNftConfigLoader {}

impl MockNftConfigLoader {
    pub fn new() -> Self {
        Self {}
    }
}

impl NftConfigLoader for MockNftConfigLoader {
    fn chains(&self) -> Result<Option<CommandOutput>, Error> {
        serde_json::from_str::<CommandOutput>(include_str!("input/chains.json"))
            .map(Some)
            .with_context(|| "invalid chains.json".to_string())
    }
}

#[test]
fn test_firewall() {
    let firewall_config = FirewallConfig::new(
        &MockFirewallConfigLoader::new(),
        &MockNftConfigLoader::new(),
    )
    .expect("valid mock configuration");

    let firewall = Firewall::new(firewall_config);

    insta::assert_json_snapshot!(firewall.full_host_fw().expect("firewall can be generated"));
}

#[test]
fn test_sdn_ct_zone_commands() {
    let firewall_config = FirewallConfig::new(
        &MockFirewallConfigLoader::new(),
        &MockNftConfigLoader::new(),
    )
    .expect("valid mock configuration");

    assert_eq!(
        Firewall::new(firewall_config).sdn_ct_zone_commands(),
        "flush map bridge proxmox-firewall-guests sdn-ct-zones\n\
         flush map bridge proxmox-firewall-guests sdn-ct-zones-vlan\n\
         add element bridge proxmox-firewall-guests sdn-ct-zones { \"public\" : 16384, \"vmbr1\" : 16384 }\n\
         add element bridge proxmox-firewall-guests sdn-ct-zones-vlan { \"vmbr0\" . 50 : 16384 }\n",
    );
}

#[test]
fn test_invalid_sdn_config_is_ignored() {
    let loader = MockFirewallConfigLoader::with_sdn_config(MockSdnConfig::Invalid);

    let firewall_config = FirewallConfig::new(&loader, &MockNftConfigLoader::new())
        .expect("an invalid SDN configuration does not fail the update");

    assert!(firewall_config.sdn().is_none());
    assert!(firewall_config.ipam().is_some());

    let firewall = Firewall::new(firewall_config);

    // the conntrack zones are unknown, so the current ones are kept
    assert_eq!(firewall.sdn_ct_zone_commands(), "");

    let commands = firewall
        .full_host_fw()
        .expect("firewall can be generated without the SDN configuration");

    // rules referencing the ipsets of the IPAM state are still generated
    let commands = serde_json::to_string(&commands).expect("commands can be serialized");
    assert!(commands.contains("\"@v4-sdn/guest-ipam-101\""));
}

#[test]
fn test_invalid_ipam_is_ignored() {
    let loader = MockFirewallConfigLoader::with_sdn_config(MockSdnConfig::InvalidIpam);

    let firewall_config = FirewallConfig::new(&loader, &MockNftConfigLoader::new())
        .expect("an invalid IPAM state does not fail the update");

    assert!(firewall_config.sdn().is_some());
    assert!(firewall_config.ipam().is_none());

    Firewall::new(firewall_config)
        .full_host_fw()
        .expect("firewall can be generated without the IPAM state");
}

#[test]
fn test_sdn_read_error_fails() {
    let loader = MockFirewallConfigLoader::with_sdn_config(MockSdnConfig::ReadError);

    assert!(FirewallConfig::new(&loader, &MockNftConfigLoader::new()).is_err());
}

#[test]
fn test_unmounted_config_fails() {
    let loader = MockFirewallConfigLoader {
        mounted: false,
        ..MockFirewallConfigLoader::new()
    };

    assert!(FirewallConfig::new(&loader, &MockNftConfigLoader::new()).is_err());
}
