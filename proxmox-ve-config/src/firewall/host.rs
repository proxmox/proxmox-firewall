use std::io;
use std::net::IpAddr;

use anyhow::{bail, Error};
use serde::Deserialize;

use crate::host::utils::{host_ips, network_interface_cidrs};
use proxmox_sys::nodename;

use crate::firewall::parse;
use crate::firewall::types::log::LogLevel;
use crate::firewall::types::rule::Direction;
use crate::firewall::types::{Alias, Cidr, Rule};

/// default setting for the enabled key
pub const HOST_ENABLED_DEFAULT: bool = true;
/// default setting for the nftables key
pub const HOST_NFTABLES_DEFAULT: bool = false;
/// default return value for [`Config::allow_ndp()`]
pub const HOST_ALLOW_NDP_DEFAULT: bool = true;
/// default return value for [`Config::block_smurfs()`]
pub const HOST_BLOCK_SMURFS_DEFAULT: bool = true;
/// default return value for [`Config::block_synflood()`]
pub const HOST_BLOCK_SYNFLOOD_DEFAULT: bool = false;
/// default rate limit for synflood rule (packets / second)
pub const HOST_BLOCK_SYNFLOOD_RATE_DEFAULT: i64 = 200;
/// default rate limit for synflood rule (packets / second)
pub const HOST_BLOCK_SYNFLOOD_BURST_DEFAULT: i64 = 1000;
/// default return value for [`Config::block_invalid_tcp()`]
pub const HOST_BLOCK_INVALID_TCP_DEFAULT: bool = false;
/// default return value for [`Config::block_invalid_conntrack()`]
pub const HOST_BLOCK_INVALID_CONNTRACK: bool = false;
/// default setting for logging of invalid conntrack entries
pub const HOST_LOG_INVALID_CONNTRACK: bool = false;

#[derive(Debug, Default, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Options {
    #[serde(default, with = "parse::serde_option_bool")]
    enable: Option<bool>,

    #[serde(default, with = "parse::serde_option_bool")]
    nftables: Option<bool>,

    log_level_in: Option<LogLevel>,
    log_level_out: Option<LogLevel>,

    #[serde(default, with = "parse::serde_option_bool")]
    log_nf_conntrack: Option<bool>,
    #[serde(default, with = "parse::serde_option_bool")]
    ndp: Option<bool>,

    #[serde(default, with = "parse::serde_option_bool")]
    nf_conntrack_allow_invalid: Option<bool>,

    // is Option<Vec<>> for easier deserialization
    #[serde(default, with = "parse::serde_option_conntrack_helpers")]
    nf_conntrack_helpers: Option<Vec<String>>,

    #[serde(default, with = "parse::serde_option_number")]
    nf_conntrack_max: Option<i64>,
    #[serde(default, with = "parse::serde_option_number")]
    nf_conntrack_tcp_timeout_established: Option<i64>,
    #[serde(default, with = "parse::serde_option_number")]
    nf_conntrack_tcp_timeout_syn_recv: Option<i64>,

    #[serde(default, with = "parse::serde_option_bool")]
    nosmurfs: Option<bool>,

    #[serde(default, with = "parse::serde_option_bool")]
    protection_synflood: Option<bool>,
    #[serde(default, with = "parse::serde_option_number")]
    protection_synflood_burst: Option<i64>,
    #[serde(default, with = "parse::serde_option_number")]
    protection_synflood_rate: Option<i64>,

    smurf_log_level: Option<LogLevel>,
    tcp_flags_log_level: Option<LogLevel>,

    #[serde(default, with = "parse::serde_option_bool")]
    tcpflags: Option<bool>,
}

#[derive(Debug, Default)]
pub struct Config {
    pub(crate) config: super::common::Config<Options>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            config: Default::default(),
        }
    }

    pub fn parse<R: io::BufRead>(input: R) -> Result<Self, Error> {
        let config = super::common::Config::parse(input, &Default::default())?;

        if !config.groups.is_empty() {
            bail!("host firewall config cannot declare groups");
        }

        if !config.aliases.is_empty() {
            bail!("host firewall config cannot declare aliases");
        }

        if !config.ipsets.is_empty() {
            bail!("host firewall config cannot declare ipsets");
        }

        Ok(Self { config })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.config.rules
    }

    pub fn management_ips() -> Result<Vec<Cidr>, Error> {
        let mut management_cidrs = Vec::new();

        for host_ip in host_ips() {
            for network_interface_cidr in network_interface_cidrs() {
                match (host_ip, network_interface_cidr) {
                    (IpAddr::V4(ip), Cidr::Ipv4(cidr)) => {
                        if cidr.contains_address(&ip) {
                            management_cidrs.push(network_interface_cidr);
                        }
                    }
                    (IpAddr::V6(ip), Cidr::Ipv6(cidr)) => {
                        if cidr.contains_address(&ip) {
                            management_cidrs.push(network_interface_cidr);
                        }
                    }
                    _ => continue,
                };
            }
        }

        Ok(management_cidrs)
    }

    pub fn hostname() -> &'static str {
        nodename()
    }

    pub fn get_alias(&self, name: &str) -> Option<&Alias> {
        self.config.alias(name)
    }

    /// returns value of enabled key or [`HOST_ENABLED_DEFAULT`] if unset
    pub fn is_enabled(&self) -> bool {
        self.config.options.enable.unwrap_or(HOST_ENABLED_DEFAULT)
    }

    /// returns value of nftables key or [`HOST_NFTABLES_DEFAULT`] if unset
    pub fn nftables(&self) -> bool {
        self.config
            .options
            .nftables
            .unwrap_or(HOST_NFTABLES_DEFAULT)
    }

    /// returns value of ndp key or [`HOST_ALLOW_NDP_DEFAULT`] if unset
    pub fn allow_ndp(&self) -> bool {
        self.config.options.ndp.unwrap_or(HOST_ALLOW_NDP_DEFAULT)
    }

    /// returns value of nosmurfs key or [`HOST_BLOCK_SMURFS_DEFAULT`] if unset
    pub fn block_smurfs(&self) -> bool {
        self.config
            .options
            .nosmurfs
            .unwrap_or(HOST_BLOCK_SMURFS_DEFAULT)
    }

    /// returns the log level for the smurf protection rule
    ///
    /// If there is no log level set, it returns [`LogLevel::default()`]
    pub fn block_smurfs_log_level(&self) -> LogLevel {
        self.config.options.smurf_log_level.unwrap_or_default()
    }

    /// returns value of protection_synflood key or [`HOST_BLOCK_SYNFLOOD_DEFAULT`] if unset
    pub fn block_synflood(&self) -> bool {
        self.config
            .options
            .protection_synflood
            .unwrap_or(HOST_BLOCK_SYNFLOOD_DEFAULT)
    }

    /// returns value of protection_synflood_rate key or [`HOST_BLOCK_SYNFLOOD_RATE_DEFAULT`] if
    /// unset
    pub fn synflood_rate(&self) -> i64 {
        self.config
            .options
            .protection_synflood_rate
            .unwrap_or(HOST_BLOCK_SYNFLOOD_RATE_DEFAULT)
    }

    /// returns value of protection_synflood_burst key or [`HOST_BLOCK_SYNFLOOD_BURST_DEFAULT`] if
    /// unset
    pub fn synflood_burst(&self) -> i64 {
        self.config
            .options
            .protection_synflood_burst
            .unwrap_or(HOST_BLOCK_SYNFLOOD_BURST_DEFAULT)
    }

    /// returns value of tcpflags key or [`HOST_BLOCK_INVALID_TCP_DEFAULT`] if unset
    pub fn block_invalid_tcp(&self) -> bool {
        self.config
            .options
            .tcpflags
            .unwrap_or(HOST_BLOCK_INVALID_TCP_DEFAULT)
    }

    /// returns the log level for the block invalid TCP packets rule
    ///
    /// If there is no log level set, it returns [`LogLevel::default()`]
    pub fn block_invalid_tcp_log_level(&self) -> LogLevel {
        self.config.options.tcp_flags_log_level.unwrap_or_default()
    }

    /// returns value of nf_conntrack_allow_invalid key or [`HOST_BLOCK_INVALID_CONNTRACK`] if
    /// unset
    pub fn block_invalid_conntrack(&self) -> bool {
        !self
            .config
            .options
            .nf_conntrack_allow_invalid
            .unwrap_or(HOST_BLOCK_INVALID_CONNTRACK)
    }

    pub fn nf_conntrack_max(&self) -> Option<i64> {
        self.config.options.nf_conntrack_max
    }

    pub fn nf_conntrack_tcp_timeout_established(&self) -> Option<i64> {
        self.config.options.nf_conntrack_tcp_timeout_established
    }

    pub fn nf_conntrack_tcp_timeout_syn_recv(&self) -> Option<i64> {
        self.config.options.nf_conntrack_tcp_timeout_syn_recv
    }

    /// returns value of log_nf_conntrack key or [`HOST_LOG_INVALID_CONNTRACK`] if unset
    pub fn log_nf_conntrack(&self) -> bool {
        self.config
            .options
            .log_nf_conntrack
            .unwrap_or(HOST_LOG_INVALID_CONNTRACK)
    }

    pub fn conntrack_helpers(&self) -> Option<&Vec<String>> {
        self.config.options.nf_conntrack_helpers.as_ref()
    }

    /// returns the log level for the given direction
    ///
    /// If there is no log level set it returns [`LogLevel::default()`]
    pub fn log_level(&self, dir: Direction) -> LogLevel {
        match dir {
            Direction::In => self.config.options.log_level_in.unwrap_or_default(),
            Direction::Out => self.config.options.log_level_out.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::firewall::types::{
        log::LogLevel,
        rule::{Kind, RuleGroup, Verdict},
        rule_match::{Ports, Protocol, RuleMatch, Udp},
    };

    use super::*;

    #[test]
    fn test_parse_config() {
        const CONFIG: &str = r#"
[OPTIONS]
enable: 1
nftables: 1
log_level_in: debug
log_level_out: emerg
log_nf_conntrack: 0
ndp: 1
nf_conntrack_allow_invalid: yes
nf_conntrack_helpers: ftp
nf_conntrack_max: 44000
nf_conntrack_tcp_timeout_established: 500000
nf_conntrack_tcp_timeout_syn_recv: 44
nosmurfs: no
protection_synflood: 1
protection_synflood_burst: 2500
protection_synflood_rate: 300
smurf_log_level: notice
tcp_flags_log_level: nolog
tcpflags: yes

[RULES]

GROUP tgr -i eth0 # acomm
IN ACCEPT -p udp -dport 33 -sport 22 -log warning

"#;

        let mut config = CONFIG.as_bytes();
        let config = Config::parse(&mut config).unwrap();

        assert_eq!(
            config.config.options,
            Options {
                enable: Some(true),
                nftables: Some(true),
                log_level_in: Some(LogLevel::Debug),
                log_level_out: Some(LogLevel::Emergency),
                log_nf_conntrack: Some(false),
                ndp: Some(true),
                nf_conntrack_allow_invalid: Some(true),
                nf_conntrack_helpers: Some(vec!["ftp".to_string()]),
                nf_conntrack_max: Some(44000),
                nf_conntrack_tcp_timeout_established: Some(500000),
                nf_conntrack_tcp_timeout_syn_recv: Some(44),
                nosmurfs: Some(false),
                protection_synflood: Some(true),
                protection_synflood_burst: Some(2500),
                protection_synflood_rate: Some(300),
                smurf_log_level: Some(LogLevel::Notice),
                tcp_flags_log_level: Some(LogLevel::Nolog),
                tcpflags: Some(true),
            }
        );

        assert_eq!(config.config.rules.len(), 2);

        assert_eq!(
            config.config.rules[0],
            Rule {
                disabled: false,
                comment: Some("acomm".to_string()),
                kind: Kind::Group(RuleGroup {
                    group: "tgr".to_string(),
                    iface: Some("eth0".to_string()),
                }),
            },
        );

        assert_eq!(
            config.config.rules[1],
            Rule {
                disabled: false,
                comment: None,
                kind: Kind::Match(RuleMatch {
                    dir: Direction::In,
                    verdict: Verdict::Accept,
                    proto: Some(Protocol::Udp(Udp::new(Ports::from_u16(22, 33)))),
                    log: Some(LogLevel::Warning),
                    ..Default::default()
                }),
            },
        );

        Config::parse("[ALIASES]\ntest 127.0.0.1".as_bytes())
            .expect_err("host config cannot contain aliases");

        Config::parse("[GROUP test]".as_bytes()).expect_err("host config cannot contain groups");

        Config::parse("[IPSET test]".as_bytes()).expect_err("host config cannot contain ipsets");
    }
}
