use std::collections::BTreeMap;
use std::fs;

use anyhow::Error;

use proxmox_nftables::command::{Add, Commands, Delete, Flush};
use proxmox_nftables::expression::{Meta, Payload};
use proxmox_nftables::helper::NfVec;
use proxmox_nftables::statement::{AnonymousLimit, Log, LogLevel, Match, Set, SetOperation};
use proxmox_nftables::types::{
    AddElement, AddRule, ChainPart, MapValue, RateTimescale, SetName, TableFamily, TableName,
    TablePart, Verdict,
};
use proxmox_nftables::{Expression, Statement};

use proxmox_ve_config::firewall::ct_helper::get_cthelper;
use proxmox_ve_config::firewall::guest::Config as GuestConfig;
use proxmox_ve_config::firewall::host::Config as HostConfig;

use proxmox_ve_config::firewall::types::address::Ipv6Cidr;
use proxmox_ve_config::firewall::types::ipset::{
    Ipfilter, Ipset, IpsetEntry, IpsetName, IpsetScope,
};
use proxmox_ve_config::firewall::types::log::{LogLevel as ConfigLogLevel, LogRateLimit};
use proxmox_ve_config::firewall::types::rule::{Direction, Verdict as ConfigVerdict};
use proxmox_ve_config::firewall::types::Group;
use proxmox_ve_config::guest::types::Vmid;

use crate::config::FirewallConfig;
use crate::object::{NftObjectEnv, ToNftObjects};
use crate::rule::{generate_verdict, NftRule, NftRuleEnv};

static CLUSTER_TABLE_NAME: &str = "proxmox-firewall";
static HOST_TABLE_NAME: &str = "proxmox-firewall";
static GUEST_TABLE_NAME: &str = "proxmox-firewall-guests";

static NF_CONNTRACK_MAX_FILE: &str = "/proc/sys/net/netfilter/nf_conntrack_max";
static NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED: &str =
    "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established";
static NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV: &str =
    "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_recv";
static LOG_CONNTRACK_FILE: &str = "/var/lib/pve-firewall/log_nf_conntrack";

pub struct Firewall {
    config: FirewallConfig,
}

impl From<FirewallConfig> for Firewall {
    fn from(config: FirewallConfig) -> Self {
        Self { config }
    }
}

impl Firewall {
    pub fn new(config: FirewallConfig) -> Self {
        Self { config }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.is_enabled()
    }

    fn cluster_table() -> TablePart {
        TablePart::new(TableFamily::Inet, CLUSTER_TABLE_NAME)
    }

    fn host_table() -> TablePart {
        TablePart::new(TableFamily::Inet, HOST_TABLE_NAME)
    }

    fn guest_table() -> TablePart {
        TablePart::new(TableFamily::Bridge, GUEST_TABLE_NAME)
    }

    fn guest_vmap(dir: Direction) -> SetName {
        SetName::new(Self::guest_table(), format!("vm-map-{dir}"))
    }

    fn cluster_chain(dir: Direction) -> ChainPart {
        ChainPart::new(Self::cluster_table(), format!("cluster-{dir}"))
    }

    fn host_chain(dir: Direction) -> ChainPart {
        ChainPart::new(Self::host_table(), format!("host-{dir}"))
    }

    fn guest_chain(dir: Direction, vmid: Vmid) -> ChainPart {
        ChainPart::new(Self::guest_table(), format!("guest-{vmid}-{dir}"))
    }

    fn group_chain(table: TablePart, name: &str, dir: Direction) -> ChainPart {
        ChainPart::new(table, format!("group-{name}-{dir}"))
    }

    fn host_conntrack_chain() -> ChainPart {
        ChainPart::new(Self::host_table(), "ct-in".to_string())
    }

    fn host_option_chain(dir: Direction) -> ChainPart {
        ChainPart::new(Self::host_table(), format!("option-{dir}"))
    }

    fn synflood_limit_chain() -> ChainPart {
        ChainPart::new(Self::host_table(), "ratelimit-synflood")
    }

    fn log_invalid_tcp_chain() -> ChainPart {
        ChainPart::new(Self::host_table(), "log-invalid-tcp")
    }

    fn log_smurfs_chain() -> ChainPart {
        ChainPart::new(Self::host_table(), "log-smurfs")
    }

    fn default_log_limit(&self) -> Option<LogRateLimit> {
        self.config.cluster().log_ratelimit()
    }

    fn reset_firewall(&self, commands: &mut Commands) {
        commands.append(&mut vec![
            Flush::chain(Self::cluster_chain(Direction::In)),
            Flush::chain(Self::cluster_chain(Direction::Out)),
            Add::chain(Self::host_chain(Direction::In)),
            Flush::chain(Self::host_chain(Direction::In)),
            Flush::chain(Self::host_option_chain(Direction::In)),
            Add::chain(Self::host_chain(Direction::Out)),
            Flush::chain(Self::host_chain(Direction::Out)),
            Flush::chain(Self::host_option_chain(Direction::Out)),
            Flush::map(Self::guest_vmap(Direction::In)),
            Flush::map(Self::guest_vmap(Direction::Out)),
            Flush::chain(Self::host_conntrack_chain()),
            Flush::chain(Self::synflood_limit_chain()),
            Flush::chain(Self::log_invalid_tcp_chain()),
            Flush::chain(Self::log_smurfs_chain()),
        ]);

        /*
        for prefix in ["v4-guest-", "v6-guest-", "v4-dc/", "v6-dc/"] {
            for (name, set) in &self.config.nft().sets {
                if name.starts_with(prefix) {
                    commands.push(Delete::set(set.name().clone()))
                }
            }
        }
        */

        // we need to remove guest chains before group chains
        for prefix in ["guest-", "group-"] {
            for (name, chain) in self.config.nft_chains() {
                if name.starts_with(prefix) {
                    commands.push(Delete::chain(chain.clone()))
                }
            }
        }
    }

    pub fn remove_commands() -> Vec<Commands> {
        vec![
            Commands::new(vec![Delete::table(Self::cluster_table())]),
            Commands::new(vec![Delete::table(Self::guest_table())]),
        ]
    }

    fn create_management_ipset(&self, commands: &mut Commands) -> Result<(), Error> {
        if self.config.cluster().ipsets().get("management").is_none() {
            log::trace!("auto-generating management ipset");

            let management_ips = HostConfig::management_ips()?;

            let mut ipset = Ipset::from_parts(IpsetScope::Datacenter, "management");
            ipset.reserve(management_ips.len());

            let entries = management_ips.into_iter().map(IpsetEntry::from);

            ipset.extend(entries);

            let env = NftObjectEnv {
                table: &Self::cluster_table(),
                firewall_config: &self.config,
                vmid: None,
            };

            commands.append(&mut ipset.to_nft_objects(&env)?);
        }

        Ok(())
    }

    pub fn full_host_fw(&self) -> Result<Commands, Error> {
        let mut commands = Commands::default();

        if !self.config.is_enabled() {
            log::info!("firewall is disabled - doing nothing!");
            return Ok(commands);
        }

        self.reset_firewall(&mut commands);

        let cluster_host_table = Self::cluster_table();

        if self.config.host().is_enabled() {
            log::info!("creating cluster / host configuration");

            self.create_management_ipset(&mut commands)?;

            self.create_ipsets(
                &mut commands,
                self.config.cluster().ipsets(),
                &cluster_host_table,
                None,
            )?;

            for (name, group) in self.config.cluster().groups() {
                self.create_group_chain(
                    &mut commands,
                    &cluster_host_table,
                    group,
                    name,
                    Direction::In,
                )?;
                self.create_group_chain(
                    &mut commands,
                    &cluster_host_table,
                    group,
                    name,
                    Direction::Out,
                )?;
            }

            self.create_cluster_rules(&mut commands, Direction::In)?;
            self.create_cluster_rules(&mut commands, Direction::Out)?;

            log::debug!("Generating host firewall config");

            self.setup_ct_helper(&mut commands)?;

            self.handle_host_options(&mut commands)?;

            self.create_host_rules(&mut commands, Direction::In)?;
            self.create_host_rules(&mut commands, Direction::Out)?;
        } else {
            commands.push(Delete::table(TableName::from(Self::cluster_table())));
        }

        let guest_table = Self::guest_table();
        let enabled_guests: BTreeMap<&Vmid, &GuestConfig> = self
            .config
            .guests()
            .iter()
            .filter(|(_, config)| config.is_enabled())
            .collect();

        if !enabled_guests.is_empty() {
            log::info!("creating guest configuration");

            self.create_ipsets(
                &mut commands,
                self.config.cluster().ipsets(),
                &guest_table,
                None,
            )?;

            for (name, group) in self.config.cluster().groups() {
                self.create_group_chain(&mut commands, &guest_table, group, name, Direction::In)?;
                self.create_group_chain(&mut commands, &guest_table, group, name, Direction::Out)?;
            }
        } else {
            commands.push(Delete::table(TableName::from(Self::guest_table())));
        }

        for (vmid, config) in enabled_guests {
            log::debug!("Generating firewall config for VM #{vmid}");

            self.create_guest_chain(&mut commands, *vmid, Direction::In)?;
            self.create_guest_chain(&mut commands, *vmid, Direction::Out)?;

            self.create_ipsets(&mut commands, config.ipsets(), &guest_table, config)?;

            self.handle_guest_options(&mut commands, *vmid, config)?;

            self.create_guest_rules(&mut commands, *vmid, config, Direction::In)?;
            self.create_guest_rules(&mut commands, *vmid, config, Direction::Out)?;
        }

        Ok(commands)
    }

    fn handle_host_options(&self, commands: &mut Commands) -> Result<(), Error> {
        log::info!("setting host options");

        let chain_in = Self::host_option_chain(Direction::In);
        let chain_out = Self::host_option_chain(Direction::Out);

        let ndp_chains = if self.config.host().allow_ndp() {
            ("allow-ndp-in", "allow-ndp-out")
        } else {
            ("block-ndp-in", "block-ndp-out")
        };

        commands.append(&mut vec![
            Add::rule(AddRule::from_statement(
                chain_in.clone(),
                Statement::jump(ndp_chains.0),
            )),
            Add::rule(AddRule::from_statement(
                chain_out,
                Statement::jump(ndp_chains.1),
            )),
        ]);

        if self.config.host().block_synflood() {
            log::debug!("set block_synflood");

            let rate_limit = Statement::from(AnonymousLimit {
                rate: self.config.host().synflood_rate(),
                per: RateTimescale::Second,
                burst: Some(self.config.host().synflood_burst()),
                inv: Some(true),
                ..Default::default()
            });

            let synflood_limit_chain = Self::synflood_limit_chain();

            let v4_rule = AddRule::from_statements(
                synflood_limit_chain.clone(),
                [
                    Statement::Set(Set {
                        op: SetOperation::Update,
                        elem: Expression::from(Payload::field("ip", "saddr")),
                        stmt: Some(NfVec::one(rate_limit.clone())),
                        set: "@v4-synflood-limit".to_string(),
                    }),
                    Statement::make_drop(),
                ],
            );

            let v6_rule = AddRule::from_statements(
                synflood_limit_chain,
                [
                    Statement::Set(Set {
                        op: SetOperation::Update,
                        elem: Expression::from(Payload::field("ip6", "saddr")),
                        stmt: Some(NfVec::one(rate_limit)),
                        set: "@v6-synflood-limit".to_string(),
                    }),
                    Statement::make_drop(),
                ],
            );

            commands.append(&mut vec![
                Add::rule(AddRule::from_statement(
                    chain_in.clone(),
                    Statement::jump("block-synflood"),
                )),
                Add::rule(v4_rule),
                Add::rule(v6_rule),
            ])
        }

        if self.config.host().block_invalid_tcp() {
            log::debug!("set block_invalid_tcp");

            commands.push(Add::rule(AddRule::from_statement(
                chain_in.clone(),
                Statement::jump("block-invalid-tcp"),
            )));

            self.create_log_rule(
                commands,
                self.config.host().block_invalid_tcp_log_level(),
                Self::log_invalid_tcp_chain(),
                ConfigVerdict::Drop,
                None,
            )?;
        }

        if self.config.host().block_smurfs() {
            log::debug!("set block_smurfs");

            commands.push(Add::rule(AddRule::from_statement(
                chain_in.clone(),
                Statement::jump("block-smurfs"),
            )));

            self.create_log_rule(
                commands,
                self.config.host().block_smurfs_log_level(),
                Self::log_smurfs_chain(),
                ConfigVerdict::Drop,
                None,
            )?;
        }

        if self.config.host().block_invalid_conntrack() {
            log::debug!("set block_invalid_conntrack");

            commands.push(Add::rule(AddRule::from_statement(
                chain_in,
                Statement::jump("block-conntrack-invalid"),
            )));
        }

        if let Some(value) = self.config.host().nf_conntrack_max() {
            log::debug!("set nf_conntrack_max");
            fs::write(NF_CONNTRACK_MAX_FILE, value.to_string())
                .unwrap_or_else(|_| log::warn!("cannot set nf_conntrack_max"));
        }

        if let Some(value) = self.config.host().nf_conntrack_tcp_timeout_established() {
            log::debug!("set nf_conntrack_tcp_timeout_established");
            fs::write(NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED, value.to_string())
                .unwrap_or_else(|_| log::warn!("cannot set nf_conntrack_tcp_timeout_established"));
        }

        if let Some(value) = self.config.host().nf_conntrack_tcp_timeout_syn_recv() {
            log::debug!("set nf_conntrack_tcp_timeout_syn_recv");
            fs::write(NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV, value.to_string())
                .unwrap_or_else(|_| log::warn!("cannot set nf_conntrack_tcp_timeout_syn_recv"));
        }

        let value = (self.config.host().log_nf_conntrack() as u8).to_string();
        fs::write(LOG_CONNTRACK_FILE, value)
            .unwrap_or_else(|_| log::warn!("cannot set conntrack_log_file"));

        /*
        CliCommand::new("systemctl")
            .args(["try-reload-or-restart", "pvefw-logger.service"])
            .output()
            .map_err(anyhow::Error::msg)?;
        */

        Ok(())
    }

    fn handle_guest_options(
        &self,
        commands: &mut Commands,
        vmid: Vmid,
        config: &GuestConfig,
    ) -> Result<(), Error> {
        let chain_in = Self::guest_chain(Direction::In, vmid);
        let chain_out = Self::guest_chain(Direction::Out, vmid);

        if config.macfilter() {
            log::debug!("setting macfilter for guest #{vmid}");
            let mac_address_set: Vec<Expression> = config
                .network_config()
                .network_devices()
                .iter()
                .map(|(index, device)| {
                    Expression::concat([
                        Expression::from(config.iface_name_by_index(*index)),
                        Expression::from(device.mac_address().to_string()),
                    ])
                })
                .collect();

            if !mac_address_set.is_empty() {
                let macfilter_rule = AddRule::from_statements(
                    chain_out.clone(),
                    [
                        Match::new_ne(
                            Expression::concat([
                                Expression::from(Meta::new("iifname")),
                                Expression::from(Payload::field("ether", "saddr")),
                            ]),
                            Expression::set(mac_address_set.clone()),
                        )
                        .into(),
                        Statement::make_drop(),
                    ],
                );

                let macfilter_arp_rule = AddRule::from_statements(
                    chain_out.clone(),
                    [
                        Match::new_ne(
                            Expression::concat([
                                Expression::from(Meta::new("iifname")),
                                Expression::from(Payload::field("arp", "saddr ether")),
                            ]),
                            Expression::set(mac_address_set),
                        )
                        .into(),
                        Statement::make_drop(),
                    ],
                );

                commands.push(Add::rule(macfilter_rule));
                commands.push(Add::rule(macfilter_arp_rule));
            }
        }

        let dhcp_chains = if config.allow_dhcp() {
            ("allow-dhcp-in", "allow-dhcp-out")
        } else {
            ("block-dhcp-in", "block-dhcp-out")
        };

        commands.append(&mut vec![
            Add::rule(AddRule::from_statement(
                chain_in.clone(),
                Statement::jump(dhcp_chains.0),
            )),
            Add::rule(AddRule::from_statement(
                chain_out.clone(),
                Statement::jump(dhcp_chains.1),
            )),
        ]);

        let ndp_chains = if config.allow_ndp() {
            ("allow-ndp-in", "allow-ndp-out")
        } else {
            ("block-ndp-in", "block-ndp-out")
        };

        commands.append(&mut vec![
            Add::rule(AddRule::from_statement(
                chain_in,
                Statement::jump(ndp_chains.0),
            )),
            Add::rule(AddRule::from_statement(
                chain_out.clone(),
                Statement::jump(ndp_chains.1),
            )),
        ]);

        let ra_chain_out = if config.allow_ra() {
            "allow-ra-out"
        } else {
            "block-ra-out"
        };

        commands.push(Add::rule(AddRule::from_statement(
            chain_out.clone(),
            Statement::jump(ra_chain_out),
        )));

        // we allow outgoing ARP, except if blocked by the MAC filter above
        let arp_rule = vec![
            Match::new_eq(Payload::field("ether", "type"), Expression::from("arp")).into(),
            Statement::make_accept(),
        ];

        commands.push(Add::rule(AddRule::from_statements(chain_out, arp_rule)));

        Ok(())
    }

    fn setup_ct_helper(&self, commands: &mut Commands) -> Result<(), Error> {
        let chain_in = Self::host_conntrack_chain();

        if let Some(helpers) = self.config.host().conntrack_helpers() {
            let object_env = NftObjectEnv {
                table: chain_in.table(),
                firewall_config: &self.config,
                vmid: None,
            };

            let rule_env = NftRuleEnv {
                chain: chain_in.clone(),
                direction: Direction::In,
                firewall_config: &self.config,
                vmid: None,
            };

            for helper in helpers {
                log::debug!("adding conntrack helper: {helper:?}");

                let helper_macro = get_cthelper(&helper.to_string());

                if let Some(helper_macro) = helper_macro {
                    commands.append(&mut helper_macro.to_nft_objects(&object_env)?);

                    // todo: use vmap
                    for rule in NftRule::from_ct_helper(helper_macro, &rule_env)? {
                        commands.push(Add::rule(rule.into_add_rule(chain_in.clone())));
                    }
                } else {
                    log::warn!("provided invalid helper macro name: {:?}", helper);
                }
            }
        }

        Ok(())
    }

    fn create_ipfilter_rules(
        &self,
        commands: &mut Commands,
        vmid: Vmid,
        ipfilter: &Ipfilter,
    ) -> Result<(), Error> {
        for direction in [Direction::In, Direction::Out] {
            let chain = Self::guest_chain(direction, vmid);

            let rule_env = NftRuleEnv {
                chain: chain.clone(),
                direction,
                firewall_config: &self.config,
                vmid: Some(vmid),
            };

            for rule in NftRule::from_ipfilter(ipfilter, &rule_env)? {
                commands.push(Add::rule(rule.into_add_rule(chain.clone())));
            }
        }

        Ok(())
    }

    fn create_ipsets<'a>(
        &self,
        commands: &mut Commands,
        ipsets: &BTreeMap<String, Ipset>,
        table: &TablePart,
        guest_config: impl Into<Option<&'a GuestConfig>>,
    ) -> Result<(), Error> {
        let config = guest_config.into();
        let vmid = config.map(|cfg| cfg.vmid());

        let env = NftObjectEnv {
            table,
            vmid,
            firewall_config: &self.config,
        };

        for (name, ipset) in ipsets {
            if ipset.ipfilter().is_some() {
                continue;
            }

            log::info!("creating ipset {name} in table {}", table.table());
            commands.append(&mut ipset.to_nft_objects(&env)?);
        }

        if let (Some(cfg), Some(vmid)) = (config, vmid) {
            let network_devices = cfg.network_config().network_devices();

            for (index, network_device) in network_devices {
                let ipfilter_name = Ipfilter::name_for_index(*index);

                if let Some(ipset) = ipsets.get(&ipfilter_name) {
                    log::debug!("creating ipfilter for guest #{vmid} net{index}");

                    commands.append(&mut ipset.to_nft_objects(&env)?);
                    // safe due to constructing the name above
                    let ipfilter = ipset.ipfilter().expect("is an ip filter");
                    self.create_ipfilter_rules(commands, vmid, &ipfilter)?;
                } else if cfg.ipfilter() {
                    log::debug!("generating default ipfilter for guest #{vmid} net{index}");
                    let ipset_name = IpsetName::new(IpsetScope::Guest, ipfilter_name);
                    let mut ipset = Ipset::new(ipset_name);

                    let cidr =
                        Ipv6Cidr::from(network_device.mac_address().eui64_link_local_address());

                    ipset.push(cidr.into());

                    if let Some(ip_address) = network_device.ip() {
                        ipset.push(IpsetEntry::from(*ip_address));
                    }

                    if let Some(ip6_address) = network_device.ip6() {
                        ipset.push(IpsetEntry::from(*ip6_address));
                    }

                    commands.append(&mut ipset.to_nft_objects(&env)?);
                    // safe due to constructing the name above
                    let ipfilter = ipset.ipfilter().expect("is an ip filter");
                    self.create_ipfilter_rules(commands, vmid, &ipfilter)?;
                };
            }
        }

        Ok(())
    }

    fn create_cluster_rules(
        &self,
        commands: &mut Commands,
        direction: Direction,
    ) -> Result<(), Error> {
        log::info!("creating cluster chain {direction}");

        let chain = Self::cluster_chain(direction);

        let env = NftRuleEnv {
            chain: chain.clone(),
            direction,
            firewall_config: &self.config,
            vmid: None,
        };

        let rules = self.config.cluster().rules();

        commands.reserve(rules.len());

        for config_rule in rules {
            for rule in NftRule::from_config_rule(config_rule, &env)? {
                commands.push(Add::rule(rule.into_add_rule(chain.clone())));
            }
        }

        let default_policy = self.config.cluster().default_policy(direction);

        self.create_log_rule(
            commands,
            self.config.host().log_level(direction),
            chain.clone(),
            default_policy,
            None,
        )?;

        commands.push(Add::rule(AddRule::from_statement(
            chain,
            generate_verdict(default_policy, &env),
        )));

        Ok(())
    }

    fn create_host_rules(
        &self,
        commands: &mut Commands,
        direction: Direction,
    ) -> Result<(), Error> {
        log::info!("creating host chain {direction}");

        let chain = Self::host_chain(direction);

        let env = NftRuleEnv {
            chain: chain.clone(),
            direction,
            firewall_config: &self.config,
            vmid: None,
        };

        let rules = self.config.host().rules();
        commands.reserve(rules.len());

        for config_rule in rules {
            for rule in NftRule::from_config_rule(config_rule, &env)? {
                commands.push(Add::rule(rule.into_add_rule(chain.clone())));
            }
        }

        Ok(())
    }

    fn create_guest_chain(
        &self,
        commands: &mut Commands,
        vmid: Vmid,
        direction: Direction,
    ) -> Result<(), Error> {
        log::info!("creating guest chain #{vmid} {direction}");

        let chain = Self::guest_chain(direction, vmid);

        commands.append(&mut vec![Add::chain(chain.clone()), Flush::chain(chain)]);

        Ok(())
    }

    fn create_guest_rules(
        &self,
        commands: &mut Commands,
        vmid: Vmid,
        config: &GuestConfig,
        direction: Direction,
    ) -> Result<(), Error> {
        log::info!("creating guest rules #{vmid} {direction}");

        let chain = Self::guest_chain(direction, vmid);

        let env = NftRuleEnv {
            chain: chain.clone(),
            direction,
            firewall_config: &self.config,
            vmid: Some(vmid),
        };

        commands.reserve(config.rules().len());

        for config_rule in config.rules() {
            for rule in NftRule::from_config_rule(config_rule, &env)? {
                commands.push(Add::rule(rule.into_add_rule(chain.clone())))
            }
        }

        let network_devices = config.network_config().network_devices();

        if !network_devices.is_empty() {
            let map_elements = network_devices
                .iter()
                .filter(|(_, device)| device.has_firewall())
                .map(|(index, _)| {
                    (
                        Expression::from(config.iface_name_by_index(*index)),
                        MapValue::from(Verdict::Goto {
                            target: chain.name().to_string(),
                        }),
                    )
                });

            commands.push(Add::element(AddElement::map_from_expressions(
                Self::guest_vmap(direction),
                map_elements,
            )));
        }

        if direction == Direction::In {
            commands.push(Add::rule(AddRule::from_statement(
                chain.clone(),
                Statement::jump("after-vm-in"),
            )));
        }

        self.create_log_rule(
            commands,
            config.log_level(direction),
            chain.clone(),
            config.default_policy(direction),
            vmid,
        )?;

        commands.push(Add::rule(AddRule::from_statement(
            chain,
            generate_verdict(config.default_policy(direction), &env),
        )));

        Ok(())
    }

    fn create_group_chain(
        &self,
        commands: &mut Commands,
        table: &TablePart,
        group: &Group,
        name: &str,
        direction: Direction,
    ) -> Result<(), Error> {
        log::info!(
            "creating group chain {name} in table {} {direction}",
            table.table()
        );

        let chain = Self::group_chain(table.clone(), name, direction);

        let env = NftRuleEnv {
            chain: chain.clone(),
            direction,
            firewall_config: &self.config,
            vmid: None,
        };

        commands.append(&mut vec![
            Add::chain(chain.clone()),
            Flush::chain(chain.clone()),
        ]);

        for rule in group.rules() {
            for firewall_rule in NftRule::from_config_rule(rule, &env)? {
                commands.push(Add::rule(firewall_rule.into_add_rule(chain.clone())))
            }
        }

        Ok(())
    }

    fn create_log_rule(
        &self,
        commands: &mut Commands,
        log_level: ConfigLogLevel,
        chain: ChainPart,
        verdict: ConfigVerdict,
        vmid: impl Into<Option<Vmid>>,
    ) -> Result<(), Error> {
        if let Ok(log_level) = LogLevel::try_from(log_level) {
            let mut log_rule = AddRule::new(chain.clone());

            if let Some(limit) = self.default_log_limit() {
                log_rule.push(Statement::from(limit));
            }

            let log_statement = Log::new_nflog(
                Log::generate_prefix(vmid, log_level, chain.name(), verdict),
                0,
            );

            log_rule.push(Statement::from(log_statement));

            commands.push(Add::rule(log_rule));
        }

        Ok(())
    }
}
