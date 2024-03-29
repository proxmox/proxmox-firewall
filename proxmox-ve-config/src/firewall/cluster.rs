use std::collections::BTreeMap;
use std::io;

use anyhow::Error;
use serde::Deserialize;

use crate::firewall::common::ParserConfig;
use crate::firewall::types::ipset::{Ipset, IpsetScope};
use crate::firewall::types::log::LogRateLimit;
use crate::firewall::types::rule::{Direction, Verdict};
use crate::firewall::types::{Alias, Group, Rule};

use crate::firewall::parse::{serde_option_bool, serde_option_log_ratelimit};

#[derive(Debug, Default)]
pub struct Config {
    pub(crate) config: super::common::Config<Options>,
}

/// default setting for [`Config::is_enabled()`]
pub const CLUSTER_ENABLED_DEFAULT: bool = false;
/// default setting for [`Config::ebtables()`]
pub const CLUSTER_EBTABLES_DEFAULT: bool = false;
/// default setting for [`Config::default_policy()`]
pub const CLUSTER_POLICY_IN_DEFAULT: Verdict = Verdict::Drop;
/// default setting for [`Config::default_policy()`]
pub const CLUSTER_POLICY_OUT_DEFAULT: Verdict = Verdict::Accept;

impl Config {
    pub fn parse<R: io::BufRead>(input: R) -> Result<Self, Error> {
        let parser_config = ParserConfig {
            guest_iface_names: false,
            ipset_scope: Some(IpsetScope::Datacenter),
        };

        Ok(Self {
            config: super::common::Config::parse(input, &parser_config)?,
        })
    }

    pub fn rules(&self) -> &Vec<Rule> {
        &self.config.rules
    }

    pub fn groups(&self) -> &BTreeMap<String, Group> {
        &self.config.groups
    }

    pub fn ipsets(&self) -> &BTreeMap<String, Ipset> {
        &self.config.ipsets
    }

    pub fn alias(&self, name: &str) -> Option<&Alias> {
        self.config.alias(name)
    }

    pub fn is_enabled(&self) -> bool {
        self.config
            .options
            .enable
            .unwrap_or(CLUSTER_ENABLED_DEFAULT)
    }

    /// returns the ebtables option from the cluster config or [`CLUSTER_EBTABLES_DEFAULT`] if
    /// unset
    ///
    /// this setting is leftover from the old firewall, but has no effect on the nftables firewall
    pub fn ebtables(&self) -> bool {
        self.config
            .options
            .ebtables
            .unwrap_or(CLUSTER_EBTABLES_DEFAULT)
    }

    /// returns policy_in / out or [`CLUSTER_POLICY_IN_DEFAULT`] / [`CLUSTER_POLICY_OUT_DEFAULT`] if
    /// unset
    pub fn default_policy(&self, dir: Direction) -> Verdict {
        match dir {
            Direction::In => self
                .config
                .options
                .policy_in
                .unwrap_or(CLUSTER_POLICY_IN_DEFAULT),
            Direction::Out => self
                .config
                .options
                .policy_out
                .unwrap_or(CLUSTER_POLICY_OUT_DEFAULT),
        }
    }

    /// returns the rate_limit for logs or [`None`] if rate limiting is disabled
    ///
    /// If there is no rate limit set, then [`LogRateLimit::default`] is used
    pub fn log_ratelimit(&self) -> Option<LogRateLimit> {
        let rate_limit = self
            .config
            .options
            .log_ratelimit
            .clone()
            .unwrap_or_default();

        match rate_limit.enabled() {
            true => Some(rate_limit),
            false => None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Options {
    #[serde(default, with = "serde_option_bool")]
    enable: Option<bool>,

    #[serde(default, with = "serde_option_bool")]
    ebtables: Option<bool>,

    #[serde(default, with = "serde_option_log_ratelimit")]
    log_ratelimit: Option<LogRateLimit>,

    policy_in: Option<Verdict>,
    policy_out: Option<Verdict>,
}

#[cfg(test)]
mod tests {
    use crate::firewall::types::{
        address::IpList,
        alias::{AliasName, AliasScope},
        ipset::{IpsetAddress, IpsetEntry},
        log::{LogLevel, LogRateLimitTimescale},
        rule::{Kind, RuleGroup},
        rule_match::{
            Icmpv6, Icmpv6Code, IpAddrMatch, IpMatch, Ports, Protocol, RuleMatch, Tcp, Udp,
        },
        Cidr,
    };

    use super::*;

    #[test]
    fn test_parse_config() {
        const CONFIG: &str = r#"
[OPTIONS]
enable: 1
log_ratelimit: 1,rate=10/second,burst=20
ebtables: 0
policy_in: REJECT
policy_out: REJECT

[ALIASES]

another 8.8.8.18
analias 7.7.0.0/16 # much
wide cccc::/64

[IPSET a-set]

!5.5.5.5
1.2.3.4/30
dc/analias # a comment
dc/wide
dddd::/96

[RULES]

GROUP tgr -i eth0 # acomm
IN ACCEPT -p udp -dport 33 -sport 22 -log warning

[group tgr] # comment for tgr

|OUT ACCEPT -source fe80::1/48 -dest dddd:3:3::9/64 -p icmpv6 -log nolog -icmp-type port-unreachable
OUT ACCEPT -p tcp -sport 33 -log nolog
IN BGP(REJECT) -log crit -source 1.2.3.4
"#;

        let mut config = CONFIG.as_bytes();
        let config = Config::parse(&mut config).unwrap();

        assert_eq!(
            config.config.options,
            Options {
                ebtables: Some(false),
                enable: Some(true),
                log_ratelimit: Some(LogRateLimit::new(
                    true,
                    10,
                    LogRateLimitTimescale::Second,
                    20
                )),
                policy_in: Some(Verdict::Reject),
                policy_out: Some(Verdict::Reject),
            }
        );

        assert_eq!(config.config.aliases.len(), 3);

        assert_eq!(
            config.config.aliases["another"],
            Alias::new("another", Cidr::new_v4([8, 8, 8, 18], 32).unwrap(), None),
        );

        assert_eq!(
            config.config.aliases["analias"],
            Alias::new(
                "analias",
                Cidr::new_v4([7, 7, 0, 0], 16).unwrap(),
                "much".to_string()
            ),
        );

        assert_eq!(
            config.config.aliases["wide"],
            Alias::new(
                "wide",
                Cidr::new_v6(
                    [0xCCCC, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x000],
                    64
                )
                .unwrap(),
                None
            ),
        );

        assert_eq!(config.config.ipsets.len(), 1);

        let mut ipset_elements = vec![
            IpsetEntry {
                nomatch: true,
                address: Cidr::new_v4([5, 5, 5, 5], 32).unwrap().into(),
                comment: None,
            },
            IpsetEntry {
                nomatch: false,
                address: Cidr::new_v4([1, 2, 3, 4], 30).unwrap().into(),
                comment: None,
            },
            IpsetEntry {
                nomatch: false,
                address: IpsetAddress::Alias(AliasName::new(AliasScope::Datacenter, "analias")),
                comment: Some("a comment".to_string()),
            },
            IpsetEntry {
                nomatch: false,
                address: IpsetAddress::Alias(AliasName::new(AliasScope::Datacenter, "wide")),
                comment: None,
            },
            IpsetEntry {
                nomatch: false,
                address: Cidr::new_v6([0xdd, 0xdd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 96)
                    .unwrap()
                    .into(),
                comment: None,
            },
        ];

        let mut ipset = Ipset::from_parts(IpsetScope::Datacenter, "a-set");
        ipset.append(&mut ipset_elements);

        assert_eq!(config.config.ipsets["a-set"], ipset,);

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

        assert_eq!(config.config.groups.len(), 1);

        let entry = &config.config.groups["tgr"];
        assert_eq!(entry.comment(), Some("comment for tgr"));
        assert_eq!(entry.rules().len(), 3);

        assert_eq!(
            entry.rules()[0],
            Rule {
                disabled: true,
                comment: None,
                kind: Kind::Match(RuleMatch {
                    dir: Direction::Out,
                    verdict: Verdict::Accept,
                    ip: Some(IpMatch {
                        src: Some(IpAddrMatch::Ip(IpList::from(
                            Cidr::new_v6(
                                [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                                48
                            )
                            .unwrap()
                        ))),
                        dst: Some(IpAddrMatch::Ip(IpList::from(
                            Cidr::new_v6(
                                [0xdd, 0xdd, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
                                64
                            )
                            .unwrap()
                        ))),
                    }),
                    proto: Some(Protocol::Icmpv6(Icmpv6::new_code(Icmpv6Code::Named(
                        "port-unreachable"
                    )))),
                    log: Some(LogLevel::Nolog),
                    ..Default::default()
                }),
            },
        );
        assert_eq!(
            entry.rules()[1],
            Rule {
                disabled: false,
                comment: None,
                kind: Kind::Match(RuleMatch {
                    dir: Direction::Out,
                    verdict: Verdict::Accept,
                    proto: Some(Protocol::Tcp(Tcp::new(Ports::from_u16(33, None)))),
                    log: Some(LogLevel::Nolog),
                    ..Default::default()
                }),
            },
        );

        assert_eq!(
            entry.rules()[2],
            Rule {
                disabled: false,
                comment: None,
                kind: Kind::Match(RuleMatch {
                    dir: Direction::In,
                    verdict: Verdict::Reject,
                    log: Some(LogLevel::Critical),
                    fw_macro: Some("BGP".to_string()),
                    ip: Some(IpMatch {
                        src: Some(IpAddrMatch::Ip(IpList::from(
                            Cidr::new_v4([1, 2, 3, 4], 32).unwrap()
                        ))),
                        dst: None,
                    }),
                    ..Default::default()
                }),
            },
        );

        let empty_config = Config::parse("".as_bytes()).expect("empty config is invalid");

        assert_eq!(empty_config.config.options, Options::default());
        assert!(empty_config.config.rules.is_empty());
        assert!(empty_config.config.aliases.is_empty());
        assert!(empty_config.config.ipsets.is_empty());
        assert!(empty_config.config.groups.is_empty());
    }
}
