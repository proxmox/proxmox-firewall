use anyhow::{Context, Error};
use proxmox_ve_config::host::network::InterfaceMapping;
use std::collections::HashMap;

use proxmox_firewall::config::{FirewallConfig, FirewallConfigLoader, NftConfigLoader};
use proxmox_firewall::firewall::Firewall;
use proxmox_nftables::command::CommandOutput;
use proxmox_sys::nodename;
use proxmox_ve_config::guest::types::Vmid;
use proxmox_ve_config::guest::{GuestEntry, GuestMap, GuestType};
use proxmox_ve_config::host::types::BridgeName;

struct MockFirewallConfigLoader {}

impl MockFirewallConfigLoader {
    pub fn new() -> Self {
        Self {}
    }
}

impl FirewallConfigLoader for MockFirewallConfigLoader {
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
        Ok(Some(Box::new(
            include_str!("input/.running-config.json").as_bytes(),
        )))
    }

    fn ipam(&self) -> Result<Option<Box<dyn std::io::BufRead>>, Error> {
        Ok(Some(Box::new(include_str!("input/ipam.db").as_bytes())))
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

    fn interface_mapping(
        &self,
    ) -> Result<proxmox_ve_config::host::network::InterfaceMapping, Error> {
        Ok(InterfaceMapping::from_iter(vec![]))
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
