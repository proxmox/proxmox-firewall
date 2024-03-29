use std::collections::BTreeMap;
use std::io;

use crate::guest::types::Vmid;
use crate::guest::vm::NetworkConfig;

use crate::firewall::types::alias::{Alias, AliasName};
use crate::firewall::types::ipset::IpsetScope;
use crate::firewall::types::log::LogLevel;
use crate::firewall::types::rule::{Direction, Rule, Verdict};
use crate::firewall::types::Ipset;

use anyhow::{bail, Error};
use serde::Deserialize;

use crate::firewall::parse::serde_option_bool;

/// default return value for [`Config::is_enabled()`]
pub const GUEST_ENABLED_DEFAULT: bool = false;
/// default return value for [`Config::allow_ndp()`]
pub const GUEST_ALLOW_NDP_DEFAULT: bool = true;
/// default return value for [`Config::allow_dhcp()`]
pub const GUEST_ALLOW_DHCP_DEFAULT: bool = true;
/// default return value for [`Config::allow_ra()`]
pub const GUEST_ALLOW_RA_DEFAULT: bool = false;
/// default return value for [`Config::macfilter()`]
pub const GUEST_MACFILTER_DEFAULT: bool = true;
/// default return value for [`Config::ipfilter()`]
pub const GUEST_IPFILTER_DEFAULT: bool = false;
/// default return value for [`Config::default_policy()`]
pub const GUEST_POLICY_IN_DEFAULT: Verdict = Verdict::Drop;
/// default return value for [`Config::default_policy()`]
pub const GUEST_POLICY_OUT_DEFAULT: Verdict = Verdict::Accept;

#[derive(Debug, Default, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Options {
    #[serde(default, with = "serde_option_bool")]
    dhcp: Option<bool>,

    #[serde(default, with = "serde_option_bool")]
    enable: Option<bool>,

    #[serde(default, with = "serde_option_bool")]
    ipfilter: Option<bool>,

    #[serde(default, with = "serde_option_bool")]
    ndp: Option<bool>,

    #[serde(default, with = "serde_option_bool")]
    radv: Option<bool>,

    log_level_in: Option<LogLevel>,
    log_level_out: Option<LogLevel>,

    #[serde(default, with = "serde_option_bool")]
    macfilter: Option<bool>,

    #[serde(rename = "policy_in")]
    policy_in: Option<Verdict>,

    #[serde(rename = "policy_out")]
    policy_out: Option<Verdict>,
}

#[derive(Debug)]
pub struct Config {
    vmid: Vmid,

    /// The interface prefix: "veth" for containers, "tap" for VMs.
    iface_prefix: &'static str,

    network_config: NetworkConfig,
    config: super::common::Config<Options>,
}

impl Config {
    pub fn parse<T: io::BufRead, U: io::BufRead>(
        vmid: &Vmid,
        iface_prefix: &'static str,
        firewall_input: T,
        network_input: U,
    ) -> Result<Self, Error> {
        let parser_cfg = super::common::ParserConfig {
            guest_iface_names: true,
            ipset_scope: Some(IpsetScope::Guest),
        };

        let config = super::common::Config::parse(firewall_input, &parser_cfg)?;
        if !config.groups.is_empty() {
            bail!("guest firewall config cannot declare groups");
        }

        let network_config = NetworkConfig::parse(network_input)?;

        Ok(Self {
            vmid: *vmid,
            iface_prefix,
            config,
            network_config,
        })
    }

    pub fn vmid(&self) -> Vmid {
        self.vmid
    }

    pub fn alias(&self, name: &AliasName) -> Option<&Alias> {
        self.config.alias(name.name())
    }

    pub fn iface_name_by_key(&self, key: &str) -> Result<String, Error> {
        let index = NetworkConfig::index_from_net_key(key)?;
        Ok(format!("{}{}i{index}", self.iface_prefix, self.vmid))
    }

    pub fn iface_name_by_index(&self, index: i64) -> String {
        format!("{}{}i{index}", self.iface_prefix, self.vmid)
    }

    /// returns the value of the enabled config key or [`GUEST_ENABLED_DEFAULT`] if unset
    pub fn is_enabled(&self) -> bool {
        self.config.options.enable.unwrap_or(GUEST_ENABLED_DEFAULT)
    }

    pub fn rules(&self) -> &[Rule] {
        &self.config.rules
    }

    pub fn log_level(&self, dir: Direction) -> LogLevel {
        match dir {
            Direction::In => self.config.options.log_level_in.unwrap_or_default(),
            Direction::Out => self.config.options.log_level_out.unwrap_or_default(),
        }
    }

    /// returns the value of the ndp config key or [`GUEST_ALLOW_NDP_DEFAULT`] if unset
    pub fn allow_ndp(&self) -> bool {
        self.config.options.ndp.unwrap_or(GUEST_ALLOW_NDP_DEFAULT)
    }

    /// returns the value of the dhcp config key or [`GUEST_ALLOW_DHCP_DEFAULT`] if unset
    pub fn allow_dhcp(&self) -> bool {
        self.config.options.dhcp.unwrap_or(GUEST_ALLOW_DHCP_DEFAULT)
    }

    /// returns the value of the radv config key or [`GUEST_ALLOW_RA_DEFAULT`] if unset
    pub fn allow_ra(&self) -> bool {
        self.config.options.radv.unwrap_or(GUEST_ALLOW_RA_DEFAULT)
    }

    /// returns the value of the macfilter config key or [`GUEST_MACFILTER_DEFAULT`] if unset
    pub fn macfilter(&self) -> bool {
        self.config
            .options
            .macfilter
            .unwrap_or(GUEST_MACFILTER_DEFAULT)
    }

    /// returns the value of the ipfilter config key or [`GUEST_IPFILTER_DEFAULT`] if unset
    pub fn ipfilter(&self) -> bool {
        self.config
            .options
            .ipfilter
            .unwrap_or(GUEST_IPFILTER_DEFAULT)
    }

    /// returns the value of the policy_in/out config key or
    /// [`GUEST_POLICY_IN_DEFAULT`] / [`GUEST_POLICY_OUT_DEFAULT`] if unset
    pub fn default_policy(&self, dir: Direction) -> Verdict {
        match dir {
            Direction::In => self
                .config
                .options
                .policy_in
                .unwrap_or(GUEST_POLICY_IN_DEFAULT),
            Direction::Out => self
                .config
                .options
                .policy_out
                .unwrap_or(GUEST_POLICY_OUT_DEFAULT),
        }
    }

    pub fn network_config(&self) -> &NetworkConfig {
        &self.network_config
    }

    pub fn ipsets(&self) -> &BTreeMap<String, Ipset> {
        self.config.ipsets()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        // most of the stuff is already tested in cluster parsing, only testing
        // guest specific options here
        const CONFIG: &str = r#"
[OPTIONS]
enable: 1
dhcp: 1
ipfilter: 0
log_level_in: emerg
log_level_out: crit
macfilter: 0
ndp:1
radv:1
policy_in: REJECT
policy_out: REJECT
"#;

        let config = CONFIG.as_bytes();
        let network_config: Vec<u8> = Vec::new();
        let config =
            Config::parse(&Vmid::new(100), "tap", config, network_config.as_slice()).unwrap();

        assert_eq!(
            config.config.options,
            Options {
                dhcp: Some(true),
                enable: Some(true),
                ipfilter: Some(false),
                ndp: Some(true),
                radv: Some(true),
                log_level_in: Some(LogLevel::Emergency),
                log_level_out: Some(LogLevel::Critical),
                macfilter: Some(false),
                policy_in: Some(Verdict::Reject),
                policy_out: Some(Verdict::Reject),
            }
        );
    }
}
