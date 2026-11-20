//! Conntrack zones of SDN zone VRFs.
//!
//! Sets the conntrack zone of each zone VRF for the VRF device and the interfaces in the VRF. NAT
//! relies on conntrack as well, so the rules are independent of the firewall and live in a table of
//! their own.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Error};

use proxmox_network_api::{IpLink, LinkInfo};
use proxmox_nftables::command::{Add, Commands, Delete};
use proxmox_nftables::expression::{Map, Meta};
use proxmox_nftables::statement::Mangle;
use proxmox_nftables::types::{
    AddChain, AddRule, AddTable, BaseChainConfig, ChainPart, ChainPolicy, ChainType, Hook,
    TableFamily, TablePart,
};
use proxmox_nftables::{Expression, Statement};
use proxmox_ve_config::sdn::config::SdnConfig;
use proxmox_ve_config::sdn::conntrack::{VrfCtZone, VrfCtZones};

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

/// Collects the zone VRFs with a conntrack zone on `node` and the interfaces that are enslaved to
/// them.
///
/// The members are taken from the kernel, which reflects all sources that put an interface into a
/// VRF once the network configuration got applied.
pub fn vrf_ct_zones<'a>(
    sdn: Option<&SdnConfig>,
    node: &str,
    links: impl IntoIterator<Item = &'a IpLink>,
) -> VrfCtZones {
    let mut ct_zones = sdn
        .map(|sdn| VrfCtZones::for_node(sdn, node))
        .unwrap_or_default();

    for link in links {
        if let Some(master) = link.master() {
            ct_zones.add_interface(master, link.name());
        }
    }

    ct_zones
}

/// Whether an interface name can be put into nft syntax without quoting issues.
fn is_plain_ifname(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// The conntrack zones of bridged traffic in zone VRFs, by bridge and by bridge and VLAN ID.
///
/// Bridge conntrack tracks packets before they reach a VRF, so the conntrack zone of a zone VRF
/// has to be set on the bridge already: for bridges in the VRF, including vnets, and, for VLAN
/// interfaces in the VRF, for their VLAN on the bridge they are stacked on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BridgeCtZones {
    bridges: BTreeMap<String, VrfCtZone>,
    vlans: BTreeMap<(String, u16), VrfCtZone>,
}

impl BridgeCtZones {
    /// Collects the conntrack zones from the interfaces that the kernel reports as enslaved to a
    /// zone VRF on `node`.
    ///
    /// Vnets are taken from the kernel as well, not from the SDN config, so that their conntrack
    /// zone follows the VRF their traffic is routed in, as for the inet hooks, and a bridge on a
    /// node that is not part of the zone does not get it just because of its name.
    pub fn new(sdn: &SdnConfig, node: &str, links: &[IpLink]) -> Self {
        let mut ct_zones = Self::default();

        let links: HashMap<&str, &IpLink> = links.iter().map(|link| (link.name(), link)).collect();

        let is_bridge = |name: &str| {
            links
                .get(name)
                .and_then(|link| link.linkinfo())
                .and_then(LinkInfo::info_kind)
                .is_some_and(|kind| kind == "bridge")
        };

        let vrf_ct_zones = vrf_ct_zones(Some(sdn), node, links.values().copied());

        for (_, entry) in vrf_ct_zones.iter() {
            for name in entry.interfaces() {
                if is_bridge(name) {
                    if is_plain_ifname(name) {
                        ct_zones.bridges.insert(name.to_string(), entry.ct_zone());
                    }
                } else if let Some(link) = links.get(name)
                    && let Some(linkinfo) = link.linkinfo()
                    // the map matches 802.1Q tags, an 802.1ad interface must not claim their VLAN
                    && linkinfo.vlan_protocol() == Some("802.1Q")
                    && let Some(vlan_id) = linkinfo.vlan_id()
                    && let Some(parent) = link.link()
                    && is_plain_ifname(parent)
                    && is_bridge(parent)
                {
                    ct_zones
                        .vlans
                        .insert((parent.to_string(), vlan_id), entry.ct_zone());
                }
            }
        }

        ct_zones
    }

    /// The bridges whose traffic belongs to the conntrack zone of a zone VRF.
    pub fn bridges(&self) -> impl Iterator<Item = (&str, VrfCtZone)> + '_ {
        self.bridges
            .iter()
            .map(|(bridge, ct_zone)| (bridge.as_str(), *ct_zone))
    }

    /// The VLANs on bridges whose traffic belongs to the conntrack zone of a zone VRF.
    pub fn vlans(&self) -> impl Iterator<Item = (&str, u16, VrfCtZone)> + '_ {
        self.vlans
            .iter()
            .map(|((bridge, vlan_id), ct_zone)| (bridge.as_str(), *vlan_id, *ct_zone))
    }
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
                    "white": {
                        "type": "simple",
                        "dedicated-vrf": 1,
                        "ct-zone": 16390,
                        "nodes": { "pve2": 1 },
                    },
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
            // a VRF with the name of the VRF of a zone that does not exist on this node
            link("vrf_white", None),
            link("eth6", Some("vrf_white")),
            link("lo", None),
        ];

        let interfaces: Vec<_> = vrf_ct_zones(Some(&sdn_config()), "pve1", &links)
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

        assert!(vrf_ct_zones(None, "pve1", &[link("vnetr1", Some("vrf_red"))]).is_empty());
    }

    #[test]
    fn bridge_ct_zones_from_links() {
        let link = |name: &str, linkinfo: serde_json::Value, master: Option<&str>| -> IpLink {
            let parent = name.split_once('.').map(|(parent, _)| parent);

            serde_json::from_value(json!({
                "ifindex": 1,
                "ifname": name,
                "link_type": "ether",
                "operstate": "UP",
                "master": master,
                "link": parent,
                "linkinfo": linkinfo,
            }))
            .unwrap()
        };
        let bridge = json!({ "info_kind": "bridge" });
        let vlan = |protocol: &str, id: u16| {
            let info_data = json!({ "protocol": protocol, "id": id });
            json!({ "info_kind": "vlan", "info_data": info_data })
        };

        let running_config: RunningConfig = serde_json::from_value(json!({
            "zones": {
                "ids": {
                    "red": {
                        "type": "simple",
                        "dedicated-vrf": 1,
                        "ct-zone": 16384,
                        "nodes": { "pve1": 1 },
                    },
                },
            },
            "vnets": {
                "ids": {
                    "vnetr": { "type": "vnet", "zone": "red" },
                    "vnetx": { "type": "vnet", "zone": "red" },
                },
            },
        }))
        .unwrap();
        let sdn = SdnConfig::try_from(running_config).unwrap();

        let links = vec![
            link("vrf_red", json!({ "info_kind": "vrf" }), None),
            link("vnetr", bridge.clone(), Some("vrf_red")),
            // a configured vnet whose bridge is not in the VRF, or a same-name bridge on a node
            // that is not part of the zone
            link("vnetx", bridge.clone(), None),
            link("vmbr0", bridge.clone(), None),
            link("vmbr0.60", vlan("802.1Q", 60), Some("vrf_red")),
            link("vmbr0.61", vlan("802.1ad", 61), Some("vrf_red")),
            link("eth1", json!(null), None),
            link("eth1.62", vlan("802.1Q", 62), Some("vrf_red")),
        ];

        let ct_zones = BridgeCtZones::new(&sdn, "pve1", &links);

        assert_eq!(
            ct_zones
                .bridges()
                .map(|(bridge, ct_zone)| (bridge.to_string(), ct_zone.id()))
                .collect::<Vec<_>>(),
            [("vnetr".to_string(), 16384)]
        );
        assert_eq!(
            ct_zones
                .vlans()
                .map(|(bridge, vlan_id, ct_zone)| (bridge.to_string(), vlan_id, ct_zone.id()))
                .collect::<Vec<_>>(),
            [("vmbr0".to_string(), 60, 16384)]
        );

        // the same interfaces on a node that is not part of the zone
        assert_eq!(
            BridgeCtZones::new(&sdn, "pve2", &links),
            BridgeCtZones::default()
        );
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
        let ct_zones = vrf_ct_zones(
            Some(&sdn_config()),
            "pve1",
            &[link("vnetb", Some("vrf_blue"))],
        );

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
