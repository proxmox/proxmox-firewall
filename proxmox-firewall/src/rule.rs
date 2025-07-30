use std::ops::{Deref, DerefMut};

use anyhow::{Error, bail, format_err};

use proxmox_log as log;
use proxmox_nftables::{
    Expression, Statement,
    expression::{Ct, IpFamily, Meta, Payload, Prefix},
    statement::{Log, LogLevel, Match, Operator},
    types::{AddRule, ChainPart, SetName, TableFamily, TablePart},
};
use proxmox_ve_config::{
    firewall::{
        ct_helper::CtHelperMacro,
        fw_macros::{FwMacro, get_macro},
        types::{
            Alias, Rule,
            alias::AliasName,
            ipset::{Ipfilter, IpsetName},
            log::LogRateLimit,
            rule::{Direction, Kind, RuleGroup, Verdict as ConfigVerdict},
            rule_match::{
                Icmp, Icmpv6, IpAddrMatch, IpMatch, Ports, Protocol, RuleMatch, Sctp, Tcp, Udp,
            },
        },
    },
    guest::types::Vmid,
};

use proxmox_network_types::ip_address::Family;

use crate::config::FirewallConfig;

#[derive(Debug, Clone)]
pub(crate) struct NftRule {
    family: Option<Family>,
    statements: Vec<Statement>,
    terminal_statements: Vec<Statement>,
}

impl NftRule {
    pub fn from_terminal_statements(terminal_statements: Vec<Statement>) -> Self {
        Self {
            family: None,
            statements: Vec::new(),
            terminal_statements,
        }
    }

    pub fn new(terminal_statement: Statement) -> Self {
        Self {
            family: None,
            statements: Vec::new(),
            terminal_statements: vec![terminal_statement],
        }
    }

    pub fn from_config_rule(rule: &Rule, env: &NftRuleEnv) -> Result<Vec<NftRule>, Error> {
        let mut rules = Vec::new();

        if rule.disabled() {
            return Ok(rules);
        }

        rule.to_nft_rules(&mut rules, env)?;

        Ok(rules)
    }

    pub fn from_ct_helper(
        ct_helper: &CtHelperMacro,
        env: &NftRuleEnv,
    ) -> Result<Vec<NftRule>, Error> {
        let mut rules = Vec::new();
        ct_helper.to_nft_rules(&mut rules, env)?;
        Ok(rules)
    }

    pub fn from_ipfilter(ipfilter: &Ipfilter, env: &NftRuleEnv) -> Result<Vec<NftRule>, Error> {
        let mut rules = Vec::new();
        ipfilter.to_nft_rules(&mut rules, env)?;
        Ok(rules)
    }
}

impl Deref for NftRule {
    type Target = Vec<Statement>;

    fn deref(&self) -> &Self::Target {
        &self.statements
    }
}

impl DerefMut for NftRule {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.statements
    }
}

impl NftRule {
    pub fn into_add_rule(self, chain: ChainPart) -> AddRule {
        let statements = self.statements.into_iter().chain(self.terminal_statements);

        AddRule::from_statements(chain, statements)
    }

    pub fn family(&self) -> Option<Family> {
        self.family
    }

    pub fn set_family(&mut self, family: Family) {
        self.family = Some(family);
    }
}

pub(crate) struct NftRuleEnv<'a> {
    pub(crate) chain: ChainPart,
    pub(crate) direction: Direction,
    pub(crate) firewall_config: &'a FirewallConfig,
    pub(crate) vmid: Option<Vmid>,
}

impl NftRuleEnv<'_> {
    fn alias(&self, name: &AliasName) -> Option<&Alias> {
        self.firewall_config.alias(name, self.vmid)
    }

    fn iface_name(&self, rule_iface: &str) -> String {
        match &self.vmid {
            Some(vmid) => {
                if let Some(config) = self.firewall_config.guests().get(vmid) {
                    if let Ok(name) = config.iface_name_by_key(rule_iface) {
                        return name;
                    }
                }

                log::warn!("Unable to resolve interface name {rule_iface} for VM #{vmid}");

                rule_iface.to_string()
            }
            None => self
                .firewall_config
                .interface_mapping(rule_iface)
                .map(|iface_name| iface_name.to_string())
                .unwrap_or_else(|| rule_iface.to_string()),
        }
    }

    fn default_log_limit(&self) -> Option<LogRateLimit> {
        self.firewall_config.cluster().log_ratelimit()
    }

    fn contains_family(&self, family: Family) -> bool {
        self.chain.table().family().families().contains(&family)
    }

    fn table(&self) -> &TablePart {
        self.chain.table()
    }

    fn direction(&self) -> Direction {
        self.direction
    }
}

pub(crate) trait ToNftRules {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error>;
}

impl ToNftRules for Rule {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        log::trace!("generating nft rules for config rule {self:?}");

        match self.kind() {
            Kind::Match(rule) => rule.to_nft_rules(rules, env)?,
            Kind::Group(group) => group.to_nft_rules(rules, env)?,
        };

        Ok(())
    }
}

fn handle_iface(rules: &mut [NftRule], env: &NftRuleEnv, name: &str) -> Result<(), Error> {
    let iface_key = match (env.vmid, env.direction) {
        (Some(_), Direction::In) => "oifname",
        (Some(_), Direction::Out) => "iifname",
        (None, Direction::In) => "iifname",
        (None, Direction::Out) => "oifname",
        (_, Direction::Forward) => bail!("cannot define interfaces for forward direction"),
    };

    let iface_name = env.iface_name(name);

    log::trace!("adding interface: {iface_name}");

    for rule in rules.iter_mut() {
        rule.push(
            Match::new_eq(
                Expression::from(Meta::new(iface_key.to_string())),
                Expression::from(iface_name.clone()),
            )
            .into(),
        )
    }

    Ok(())
}

impl ToNftRules for RuleGroup {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        if env.direction == Direction::Forward && self.iface().is_some() {
            return Ok(());
        }

        let chain_name = format!("group-{}-{}", self.group(), env.direction);

        rules.push(NftRule::new(Statement::jump(chain_name)));

        if let Some(name) = &self.iface() {
            handle_iface(rules, env, name)?;
        }

        Ok(())
    }
}

pub(crate) fn generate_verdict(verdict: ConfigVerdict, env: &NftRuleEnv) -> Statement {
    match (env.table().family(), env.direction(), verdict) {
        (TableFamily::Bridge, Direction::In, ConfigVerdict::Reject) => Statement::make_drop(),
        (_, _, ConfigVerdict::Reject) => Statement::jump("do-reject"),
        _ => Statement::from(verdict),
    }
}

impl ToNftRules for RuleMatch {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        if env.direction != self.direction() {
            return Ok(());
        }

        if let Some(log) = self.log() {
            if let Ok(log_level) = LogLevel::try_from(log) {
                let mut terminal_statements = Vec::new();

                if let Some(limit) = env.default_log_limit() {
                    terminal_statements.push(Statement::from(limit));
                }

                terminal_statements.push(
                    Log::new_nflog(
                        Log::generate_prefix(env.vmid, log_level, env.chain.name(), self.verdict()),
                        0,
                    )
                    .into(),
                );

                rules.push(NftRule::from_terminal_statements(terminal_statements));
            }
        }

        rules.push(NftRule::new(generate_verdict(self.verdict(), env)));

        if let Some(name) = &self.iface() {
            handle_iface(rules, env, name)?;
        }

        if let Some(protocol) = self.proto() {
            protocol.to_nft_rules(rules, env)?;
        }

        if let Some(name) = self.fw_macro() {
            let fw_macro =
                get_macro(name).ok_or_else(|| format_err!("cannot find macro {name}"))?;

            fw_macro.to_nft_rules(rules, env)?;
        }

        if let Some(ip) = self.ip() {
            ip.to_nft_rules(rules, env)?;
        }

        Ok(())
    }
}

fn handle_set(
    rules: &mut Vec<NftRule>,
    name: &IpsetName,
    field_name: &str,
    env: &NftRuleEnv,
    contains: bool,
) -> Result<(), Error> {
    let mut new_rules = rules
        .drain(..)
        .flat_map(|rule| {
            let mut new_rules = Vec::new();

            if matches!(rule.family(), Some(Family::V4) | None) && env.contains_family(Family::V4) {
                let field = Payload::field("ip", field_name);

                let mut rule = rule.clone();
                rule.set_family(Family::V4);

                rule.append(&mut vec![
                    Match::new(
                        if contains { Operator::Eq } else { Operator::Ne },
                        field.clone(),
                        Expression::set_name(&SetName::ipset_name(
                            Family::V4,
                            name,
                            env.vmid,
                            false,
                        )),
                    )
                    .into(),
                    Match::new(
                        if contains { Operator::Ne } else { Operator::Eq },
                        field,
                        Expression::set_name(&SetName::ipset_name(
                            Family::V4,
                            name,
                            env.vmid,
                            true,
                        )),
                    )
                    .into(),
                ]);

                new_rules.push(rule);
            }

            if matches!(rule.family(), Some(Family::V6) | None) && env.contains_family(Family::V6) {
                let field = Payload::field("ip6", field_name);

                let mut rule = rule;
                rule.set_family(Family::V6);

                rule.append(&mut vec![
                    Match::new(
                        if contains { Operator::Eq } else { Operator::Ne },
                        field.clone(),
                        Expression::set_name(&SetName::ipset_name(
                            Family::V6,
                            name,
                            env.vmid,
                            false,
                        )),
                    )
                    .into(),
                    Match::new(
                        if contains { Operator::Ne } else { Operator::Eq },
                        field,
                        Expression::set_name(&SetName::ipset_name(
                            Family::V6,
                            name,
                            env.vmid,
                            true,
                        )),
                    )
                    .into(),
                ]);

                new_rules.push(rule);
            }

            new_rules
        })
        .collect::<Vec<NftRule>>();

    rules.append(&mut new_rules);

    Ok(())
}

fn handle_match(
    rules: &mut Vec<NftRule>,
    ip: &IpAddrMatch,
    field_name: &str,
    env: &NftRuleEnv,
) -> Result<(), Error> {
    match ip {
        IpAddrMatch::Ip(list) => {
            if !env.contains_family(list.family()) {
                return Ok(());
            }

            let field = match list.family() {
                Family::V4 => Payload::field("ip", field_name),
                Family::V6 => Payload::field("ip6", field_name),
            };

            for rule in rules {
                match rule.family() {
                    None => {
                        rule.push(Match::new_eq(field.clone(), Expression::from(list)).into());

                        rule.set_family(list.family());
                    }
                    Some(rule_family) if rule_family == list.family() => {
                        rule.push(Match::new_eq(field.clone(), Expression::from(list)).into());
                    }
                    _ => (),
                };
            }

            Ok(())
        }
        IpAddrMatch::Alias(alias_name) => {
            let alias = env
                .alias(alias_name)
                .ok_or_else(|| format_err!("could not find alias {alias_name}"))?;

            if !env.contains_family(alias.address().family()) {
                return Ok(());
            }

            let field = match alias.address().family() {
                Family::V4 => Payload::field("ip", field_name),
                Family::V6 => Payload::field("ip6", field_name),
            };

            for rule in rules {
                match rule.family() {
                    None => {
                        rule.push(
                            Match::new_eq(
                                field.clone(),
                                Expression::from(Prefix::from(alias.address())),
                            )
                            .into(),
                        );

                        rule.set_family(alias.address().family());
                    }
                    Some(rule_family) if rule_family == alias.address().family() => {
                        rule.push(
                            Match::new_eq(
                                field.clone(),
                                Expression::from(Prefix::from(alias.address())),
                            )
                            .into(),
                        );
                    }
                    _ => (),
                }
            }

            Ok(())
        }
        IpAddrMatch::Set(name) => handle_set(rules, name, field_name, env, true),
    }
}

impl ToNftRules for IpMatch {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        log::trace!("adding ip match: {self:?}");

        if let Some(src) = self.src() {
            log::trace!("adding src: {src:?}");
            handle_match(rules, src, "saddr", env)?;
        }

        if let Some(dst) = self.dst() {
            log::trace!("adding dst: {dst:?}");
            handle_match(rules, dst, "daddr", env)?;
        }

        Ok(())
    }
}

fn handle_protocol(rules: &mut [NftRule], _env: &NftRuleEnv, name: &str) -> Result<(), Error> {
    for rule in rules.iter_mut() {
        rule.push(Match::new_eq(Meta::new("l4proto"), Expression::from(name)).into());
    }

    Ok(())
}

impl ToNftRules for Protocol {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        log::trace!("adding protocol: {self:?}");

        match self {
            Protocol::Tcp(tcp) => tcp.to_nft_rules(rules, env),
            Protocol::Udp(udp) => udp.to_nft_rules(rules, env),
            Protocol::Dccp(ports) => {
                handle_protocol(rules, env, "dccp")?;
                ports.to_nft_rules(rules, env)
            }
            Protocol::UdpLite(ports) => {
                handle_protocol(rules, env, "udplite")?;
                ports.to_nft_rules(rules, env)
            }
            Protocol::Sctp(sctp) => sctp.to_nft_rules(rules, env),
            Protocol::Icmp(icmp) => icmp.to_nft_rules(rules, env),
            Protocol::Icmpv6(icmpv6) => icmpv6.to_nft_rules(rules, env),
            Protocol::Named(name) => handle_protocol(rules, env, name),
            Protocol::Numeric(id) => {
                for rule in rules.iter_mut() {
                    rule.push(Match::new_eq(Meta::new("l4proto"), Expression::from(*id)).into());
                }

                Ok(())
            }
        }
    }
}

impl ToNftRules for Tcp {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        handle_protocol(rules, env, "tcp")?;
        self.ports().to_nft_rules(rules, env)
    }
}

impl ToNftRules for Udp {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        handle_protocol(rules, env, "udp")?;
        self.ports().to_nft_rules(rules, env)
    }
}

impl ToNftRules for Sctp {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        handle_protocol(rules, env, "sctp")?;
        self.ports().to_nft_rules(rules, env)
    }
}

impl ToNftRules for Icmp {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, _env: &NftRuleEnv) -> Result<(), Error> {
        for rule in rules.iter_mut() {
            if matches!(rule.family(), Some(Family::V4) | None) {
                if let Some(icmp_code) = self.code() {
                    rule.push(
                        Match::new_eq(Payload::field("icmp", "code"), Expression::from(icmp_code))
                            .into(),
                    );
                } else if let Some(icmp_type) = self.ty() {
                    rule.push(
                        Match::new_eq(Payload::field("icmp", "type"), Expression::from(icmp_type))
                            .into(),
                    );
                } else {
                    rule.push(Match::new_eq(Meta::new("l4proto"), Expression::from("icmp")).into());
                }

                rule.set_family(Family::V4);
            }
        }

        Ok(())
    }
}

impl ToNftRules for Icmpv6 {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, _env: &NftRuleEnv) -> Result<(), Error> {
        log::trace!("applying icmpv6: {self:?}");

        for rule in rules.iter_mut() {
            if matches!(rule.family(), Some(Family::V6) | None) {
                if let Some(icmp_code) = self.code() {
                    rule.push(
                        Match::new_eq(
                            Payload::field("icmpv6", "code"),
                            Expression::from(icmp_code),
                        )
                        .into(),
                    );
                } else if let Some(icmp_type) = self.ty() {
                    rule.push(
                        Match::new_eq(
                            Payload::field("icmpv6", "type"),
                            Expression::from(icmp_type),
                        )
                        .into(),
                    );
                } else {
                    rule.push(
                        Match::new_eq(Meta::new("l4proto"), Expression::from("icmpv6")).into(),
                    );
                }

                rule.set_family(Family::V6);
            }
        }

        Ok(())
    }
}

impl ToNftRules for Ports {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, _env: &NftRuleEnv) -> Result<(), Error> {
        log::trace!("applying ports: {self:?}");

        for rule in rules {
            if let Some(sport) = self.sport() {
                log::trace!("applying sport: {sport:?}");

                rule.push(
                    Match::new_eq(
                        Expression::from(Payload::field("th", "sport")),
                        Expression::from(sport),
                    )
                    .into(),
                )
            }

            if let Some(dport) = self.dport() {
                log::trace!("applying dport: {dport:?}");

                rule.push(
                    Match::new_eq(
                        Expression::from(Payload::field("th", "dport")),
                        Expression::from(dport),
                    )
                    .into(),
                )
            }
        }

        Ok(())
    }
}

impl ToNftRules for Ipfilter<'_> {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        let vmid = env
            .vmid
            .ok_or_else(|| format_err!("can only create ipfilter for guests"))?;

        let guest_config = env
            .firewall_config
            .guests()
            .get(&vmid)
            .ok_or_else(|| format_err!("no guest config found!"))?;

        if !guest_config.ipfilter() {
            return Ok(());
        }

        match env.direction {
            Direction::In => {
                if env.contains_family(Family::V4) {
                    let mut rule = NftRule::new(Statement::make_drop());
                    rule.set_family(Family::V4);

                    rule.append(&mut vec![
                        Match::new_eq(
                            Expression::from(Meta::new("oifname")),
                            guest_config.iface_name_by_index(self.index()),
                        )
                        .into(),
                        Match::new_ne(
                            Payload::field("arp", "daddr ip"),
                            Expression::set_name(&SetName::ipset_name(
                                Family::V4,
                                self.ipset().name(),
                                env.vmid,
                                false,
                            )),
                        )
                        .into(),
                    ]);

                    rules.push(rule);
                }
            }
            Direction::Out => {
                let mut base_rule = NftRule::new(Statement::make_drop());

                base_rule.push(
                    Match::new_eq(
                        Expression::from(Meta::new("iifname")),
                        guest_config.iface_name_by_index(self.index()),
                    )
                    .into(),
                );

                let mut ipfilter_rules = vec![base_rule.clone()];
                handle_set(
                    &mut ipfilter_rules,
                    self.ipset().name(),
                    "saddr",
                    env,
                    false,
                )?;
                rules.append(&mut ipfilter_rules);

                if env.contains_family(Family::V4) {
                    base_rule.set_family(Family::V4);

                    base_rule.append(&mut vec![
                        Match::new_ne(
                            Payload::field("arp", "saddr ip"),
                            Expression::set_name(&SetName::ipset_name(
                                Family::V4,
                                self.ipset().name(),
                                env.vmid,
                                false,
                            )),
                        )
                        .into(),
                    ]);

                    rules.push(base_rule);
                }
            }
            Direction::Forward => bail!("cannot generate IP filter for direction forward"),
        }
        Ok(())
    }
}

impl ToNftRules for CtHelperMacro {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        if let Some(family) = self.family() {
            if !env.contains_family(family) {
                return Ok(());
            }
        }

        if self.tcp().is_none() && self.udp().is_none() {
            return Ok(());
        }

        log::trace!("applying ct helper: {self:?}");

        let ip_family = self.family().map(IpFamily::from);

        if let Some(protocol) = self.tcp() {
            let base_rule = NftRule::from_terminal_statements(vec![
                Match::new_eq(
                    Ct::new("state", None),
                    Expression::List(vec!["new".into(), "established".into()]),
                )
                .into(),
                Statement::make_accept(),
            ]);

            let helper_rule = NftRule::new(Statement::CtHelper(self.tcp_helper_name()));

            let mut ct_rules = vec![base_rule, helper_rule];
            protocol.to_nft_rules(&mut ct_rules, env)?;
            rules.append(&mut ct_rules);
        }

        if let Some(protocol) = self.udp() {
            let base_rule = NftRule::from_terminal_statements(vec![
                Match::new_eq(
                    Ct::new("state", None),
                    Expression::List(vec!["new".into(), "established".into()]),
                )
                .into(),
                Statement::make_accept(),
            ]);

            let helper_rule = NftRule::new(Statement::CtHelper(self.udp_helper_name()));

            let mut ct_rules = vec![base_rule, helper_rule];
            protocol.to_nft_rules(&mut ct_rules, env)?;
            rules.append(&mut ct_rules);
        }

        let mut ct_helper_rule = NftRule::new(Statement::make_accept());

        ct_helper_rule.push(Match::new_eq(Ct::new("helper", ip_family), self.name()).into());

        rules.push(ct_helper_rule);

        Ok(())
    }
}

impl ToNftRules for FwMacro {
    fn to_nft_rules(&self, rules: &mut Vec<NftRule>, env: &NftRuleEnv) -> Result<(), Error> {
        log::trace!("applying macro: {self:?}");

        let initial_rules: Vec<NftRule> = std::mem::take(rules);

        for protocol in &self.code {
            let mut new_rules = initial_rules.to_vec();
            protocol.to_nft_rules(&mut new_rules, env)?;

            rules.append(&mut new_rules);
        }

        Ok(())
    }
}
