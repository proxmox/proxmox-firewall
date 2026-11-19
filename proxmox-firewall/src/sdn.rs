//! Conntrack zones of SDN zone VRFs.
//!
//! Sets the conntrack zone of each zone VRF for the VRF device and the interfaces in the VRF. NAT
//! relies on conntrack as well, so the rules are independent of the firewall and live in a table of
//! their own.

use anyhow::{Context, Error};

use proxmox_network_api::IpLink;
use proxmox_nftables::command::{Add, Commands, Delete};
use proxmox_nftables::expression::{Map, Meta};
use proxmox_nftables::statement::Mangle;
use proxmox_nftables::types::{
    AddChain, AddRule, AddTable, BaseChainConfig, ChainPart, ChainPolicy, ChainType, Hook,
    TableFamily, TablePart,
};
use proxmox_nftables::{Expression, Statement};
use proxmox_ve_config::sdn::config::SdnConfig;
use proxmox_ve_config::sdn::conntrack::VrfCtZones;

use crate::config::{FirewallConfig, FirewallConfigLoader, FirewallSdnConfig, read_config};

pub const VRF_CT_ZONES_TABLE: &str = "proxmox-sdn-ct-zones";

// before the iptables raw table (-300) and conntrack (-200), so that the zone takes effect
// regardless of the order in which the tables were loaded
const VRF_CT_ZONES_PRIORITY: i64 = -310;

/// Loads the SDN running configuration.
///
/// Fails if the configuration cannot be read or parsed, so that the existing rules are kept
/// instead of being removed.
pub fn load_sdn_config(
    loader: &dyn FirewallConfigLoader,
) -> Result<Option<FirewallSdnConfig>, Error> {
    loader.check_mounted()?;

    let data = read_config(loader.sdn_running_config()?)
        .context("failed to read the SDN running configuration")?;

    FirewallConfig::parse_sdn(data.as_deref())
}

/// Collects the zone VRFs with a conntrack zone and the interfaces that are enslaved to them.
///
/// The members are taken from the kernel, which reflects all sources that put an interface into a
/// VRF once the network configuration got applied.
pub fn vrf_ct_zones(
    sdn: Option<&SdnConfig>,
    links: impl IntoIterator<Item = IpLink>,
) -> VrfCtZones {
    let mut ct_zones = sdn.map(VrfCtZones::from).unwrap_or_default();

    for link in links {
        if let Some(master) = link.master() {
            ct_zones.add_interface(master, link.name());
        }
    }

    ct_zones
}

/// Generates the commands that atomically replace the table for the conntrack zones.
///
/// Without any zone VRF, the commands only remove the table.
pub fn vrf_ct_zones_commands(ct_zones: &VrfCtZones) -> Commands {
    let table = TablePart::new(TableFamily::Inet, VRF_CT_ZONES_TABLE);

    let mut commands = Commands::new(vec![
        Add::table(AddTable::new(TableFamily::Inet, VRF_CT_ZONES_TABLE)),
        Delete::table(table.clone()),
    ]);

    if ct_zones.is_empty() {
        return commands;
    }

    commands.push(Add::table(AddTable::new(
        TableFamily::Inet,
        VRF_CT_ZONES_TABLE,
    )));

    // received packets pass prerouting on the receiving interface and on the VRF device, locally
    // generated ones pass output on the VRF device and on the outgoing interface
    for (hook, key) in [(Hook::Prerouting, "iifname"), (Hook::Output, "oifname")] {
        let chain = ChainPart::new(table.clone(), hook.to_string());

        commands.push(Add::chain(AddChain::new_base_chain(
            table.clone(),
            chain.name(),
            BaseChainConfig::new(
                ChainType::Filter,
                hook,
                VRF_CT_ZONES_PRIORITY,
                ChainPolicy::Accept,
            ),
        )));

        commands.push(Add::rule(AddRule::from_statement(
            chain,
            Statement::from(Mangle::ct_zone(Map::new(
                Meta::new(key),
                Expression::from(ct_zones),
            ))),
        )));
    }

    commands
}

#[cfg(test)]
mod tests {
    use proxmox_ve_config::sdn::config::RunningConfig;
    use serde_json::json;

    use super::*;

    fn link(name: &str, master: Option<&str>) -> IpLink {
        serde_json::from_value(json!({
            "ifindex": 1,
            "ifname": name,
            "link_type": "ether",
            "operstate": "UP",
            "master": master,
        }))
        .unwrap()
    }

    fn sdn_config() -> SdnConfig {
        let running_config: RunningConfig = serde_json::from_value(json!({
            "zones": {
                "ids": {
                    "red": { "type": "simple", "dedicated-vrf": 1, "ct-zone": 16384 },
                    "blue": { "type": "simple", "dedicated-vrf": 1, "ct-zone": "16389" },
                    "green": { "type": "simple" },
                },
            },
        }))
        .unwrap();

        SdnConfig::try_from(running_config).unwrap()
    }

    #[test]
    fn vrf_ct_zones_from_links() {
        let links = [
            link("vrf_red", None),
            link("vnetr1", Some("vrf_red")),
            link("bond0.101", Some("vrf_red")),
            link("vnetb", Some("vrf_blue")),
            link("ens18", Some("vmbr0")),
            link("eth5", Some("vrf_other")),
            link("vnetg", Some("vrf_green")),
            link("lo", None),
        ];

        let interfaces: Vec<_> = vrf_ct_zones(Some(&sdn_config()), links)
            .interfaces()
            .map(|(interface, ct_zone)| (interface.to_string(), ct_zone.id()))
            .collect();

        assert_eq!(
            interfaces,
            [
                ("vrf_blue".to_string(), 16389),
                ("vnetb".to_string(), 16389),
                ("vrf_red".to_string(), 16384),
                ("bond0.101".to_string(), 16384),
                ("vnetr1".to_string(), 16384),
            ]
        );

        assert!(vrf_ct_zones(None, [link("vnetr1", Some("vrf_red"))]).is_empty());
    }

    #[test]
    fn vrf_ct_zones_commands_without_zones() {
        let commands = vrf_ct_zones_commands(&VrfCtZones::default());

        assert_eq!(
            serde_json::to_value(&commands).unwrap(),
            json!({"nftables": [
                {"add": {"table": {"family": "inet", "name": "proxmox-sdn-ct-zones"}}},
                {"delete": {"table": {"family": "inet", "name": "proxmox-sdn-ct-zones"}}},
            ]})
        );
    }

    #[test]
    fn vrf_ct_zones_commands_with_zones() {
        let ct_zones = vrf_ct_zones(Some(&sdn_config()), [link("vnetb", Some("vrf_blue"))]);

        let elements = json!({"set": [
            ["vrf_blue", 16389],
            ["vnetb", 16389],
            ["vrf_red", 16384],
        ]});

        let chain = |hook: &str, key: &str| {
            [
                json!({"add": {"chain": {
                    "family": "inet",
                    "table": "proxmox-sdn-ct-zones",
                    "name": hook,
                    "type": "filter",
                    "hook": hook,
                    "prio": -310,
                    "policy": "accept",
                }}}),
                json!({"add": {"rule": {
                    "family": "inet",
                    "table": "proxmox-sdn-ct-zones",
                    "chain": hook,
                    "expr": [{"mangle": {
                        "key": {"ct": {"key": "zone"}},
                        "value": {"map": {"key": {"meta": {"key": key}}, "data": elements}},
                    }}],
                }}}),
            ]
        };

        let mut expected = vec![
            json!({"add": {"table": {"family": "inet", "name": "proxmox-sdn-ct-zones"}}}),
            json!({"delete": {"table": {"family": "inet", "name": "proxmox-sdn-ct-zones"}}}),
            json!({"add": {"table": {"family": "inet", "name": "proxmox-sdn-ct-zones"}}}),
        ];
        expected.extend(chain("prerouting", "iifname"));
        expected.extend(chain("output", "oifname"));

        assert_eq!(
            serde_json::to_value(vrf_ct_zones_commands(&ct_zones)).unwrap(),
            json!({ "nftables": expected })
        );
    }
}
