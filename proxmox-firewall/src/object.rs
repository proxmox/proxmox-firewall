use anyhow::{Error, format_err};

use proxmox_log as log;
use proxmox_nftables::{
    Command, Expression,
    command::{Add, Flush},
    expression::Prefix,
    types::{
        AddCtHelper, AddElement, CtHelperProtocol, ElementType, L3Protocol, SetConfig, SetFlag,
        SetName, TablePart,
    },
};
use proxmox_ve_config::{
    firewall::{
        ct_helper::CtHelperMacro,
        types::{Alias, Ipset, alias::RuleAliasName, ipset::IpsetAddress},
    },
    guest::types::Vmid,
};

use proxmox_network_types::ip_address::Family;

use crate::config::FirewallConfig;

pub(crate) struct NftObjectEnv<'a, 'b> {
    pub(crate) table: &'a TablePart,
    pub(crate) firewall_config: &'b FirewallConfig,
    pub(crate) vmid: Option<Vmid>,
}

impl NftObjectEnv<'_, '_> {
    pub(crate) fn alias(&self, name: &RuleAliasName) -> Option<&Alias> {
        self.firewall_config.alias(name, self.vmid)
    }
}

pub(crate) trait ToNftObjects {
    fn to_nft_objects(&self, env: &NftObjectEnv) -> Result<Vec<Command>, Error>;
}

impl ToNftObjects for CtHelperMacro {
    fn to_nft_objects(&self, env: &NftObjectEnv) -> Result<Vec<Command>, Error> {
        let mut commands = Vec::new();

        if let Some(_protocol) = self.tcp() {
            commands.push(Add::ct_helper(AddCtHelper {
                table: env.table.clone(),
                name: self.tcp_helper_name(),
                ty: self.name().to_string(),
                protocol: CtHelperProtocol::TCP,
                l3proto: self.family().map(L3Protocol::from),
            }));
        }

        if let Some(_protocol) = self.udp() {
            commands.push(Add::ct_helper(AddCtHelper {
                table: env.table.clone(),
                name: self.udp_helper_name(),
                ty: self.name().to_string(),
                protocol: CtHelperProtocol::UDP,
                l3proto: self.family().map(L3Protocol::from),
            }));
        }

        Ok(commands)
    }
}

impl ToNftObjects for Ipset {
    fn to_nft_objects(&self, env: &NftObjectEnv) -> Result<Vec<Command>, Error> {
        let mut commands = Vec::new();
        log::trace!("generating objects for ipset: {self:?}");

        for family in env.table.family().families() {
            let mut elements = Vec::new();
            let mut nomatch_elements = Vec::new();

            for element in self.iter() {
                let expression = match &element.address {
                    IpsetAddress::Range(range) => {
                        if family != range.family() {
                            continue;
                        }

                        Expression::from(range)
                    }
                    IpsetAddress::Cidr(cidr) => {
                        if family != cidr.family() {
                            continue;
                        }

                        Expression::from(Prefix::from(cidr))
                    }
                    IpsetAddress::Alias(alias) => {
                        let cidr = env
                            .alias(alias)
                            .ok_or_else(|| {
                                format_err!("could not find alias {alias} in environment")
                            })?
                            .address();

                        if family != cidr.family() {
                            continue;
                        }

                        Expression::from(Prefix::from(cidr))
                    }
                };

                if element.nomatch {
                    nomatch_elements.push(expression);
                } else {
                    elements.push(expression);
                }
            }

            let element_type = match family {
                Family::V4 => ElementType::Ipv4Addr,
                Family::V6 => ElementType::Ipv6Addr,
            };

            let set_name = SetName::new(
                env.table.clone(),
                SetName::ipset_name(family, self.name(), env.vmid, false),
            );

            let set_config = SetConfig::new(set_name.clone(), vec![element_type])
                .with_flag(SetFlag::Interval)
                .with_auto_merge(true);

            let nomatch_name = SetName::new(
                env.table.clone(),
                SetName::ipset_name(family, self.name(), env.vmid, true),
            );

            let nomatch_config = SetConfig::new(nomatch_name.clone(), vec![element_type])
                .with_flag(SetFlag::Interval)
                .with_auto_merge(true);

            commands.append(&mut vec![
                Add::set(set_config),
                Flush::set(set_name.clone()),
                Add::set(nomatch_config),
                Flush::set(nomatch_name.clone()),
            ]);

            if !elements.is_empty() {
                commands.push(Add::element(AddElement::set_from_expressions(
                    set_name, elements,
                )));
            }

            if !nomatch_elements.is_empty() {
                commands.push(Add::element(AddElement::set_from_expressions(
                    nomatch_name,
                    nomatch_elements,
                )));
            }
        }

        Ok(commands)
    }
}
