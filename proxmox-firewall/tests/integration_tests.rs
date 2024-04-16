use std::collections::HashMap;

use proxmox_firewall::config::{FirewallConfig, FirewallConfigLoader, NftConfigLoader};
use proxmox_firewall::firewall::Firewall;
use proxmox_nftables::command::CommandOutput;
use proxmox_sys::nodename;
use proxmox_ve_config::guest::types::Vmid;
use proxmox_ve_config::guest::{GuestEntry, GuestMap, GuestType};

struct MockFirewallConfigLoader {}

impl MockFirewallConfigLoader {
    pub fn new() -> Self {
        Self {}
    }
}

impl FirewallConfigLoader for MockFirewallConfigLoader {
    fn cluster(&self) -> Option<Box<dyn std::io::BufRead>> {
        Some(Box::new(include_str!("input/cluster.fw").as_bytes()))
    }

    fn host(&self) -> Option<Box<dyn std::io::BufRead>> {
        Some(Box::new(include_str!("input/host.fw").as_bytes()))
    }

    fn guest_list(&self) -> GuestMap {
        let hostname = nodename().to_string();

        let mut map = HashMap::new();

        let entry = GuestEntry::new(hostname.clone(), GuestType::Vm);
        map.insert(101.into(), entry);

        let entry = GuestEntry::new(hostname, GuestType::Ct);
        map.insert(100.into(), entry);

        GuestMap::from(map)
    }

    fn guest_config(&self, vmid: &Vmid, _guest: &GuestEntry) -> Option<Box<dyn std::io::BufRead>> {
        if *vmid == Vmid::new(101) {
            return Some(Box::new(include_str!("input/101.conf").as_bytes()));
        }

        if *vmid == Vmid::new(100) {
            return Some(Box::new(include_str!("input/100.conf").as_bytes()));
        }

        None
    }

    fn guest_firewall_config(&self, vmid: &Vmid) -> Option<Box<dyn std::io::BufRead>> {
        if *vmid == Vmid::new(101) {
            return Some(Box::new(include_str!("input/101.fw").as_bytes()));
        }

        if *vmid == Vmid::new(100) {
            return Some(Box::new(include_str!("input/100.fw").as_bytes()));
        }

        None
    }
}

struct MockNftConfigLoader {}

impl MockNftConfigLoader {
    pub fn new() -> Self {
        Self {}
    }
}

impl NftConfigLoader for MockNftConfigLoader {
    fn chains(&self) -> CommandOutput {
        serde_json::from_str(include_str!("input/chains.json")).expect("valid chains.json")
    }
}

#[test]
fn test_firewall() {
    let firewall_config = FirewallConfig::new(
        Box::new(MockFirewallConfigLoader::new()),
        Box::new(MockNftConfigLoader::new()),
    );

    let firewall = Firewall::from(firewall_config);

    insta::assert_json_snapshot!(firewall.full_host_fw().expect("firewall can be generated"));
}
