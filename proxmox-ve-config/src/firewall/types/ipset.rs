use core::fmt::Display;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use anyhow::{bail, format_err, Error};
use serde_with::DeserializeFromStr;

use crate::firewall::parse::match_non_whitespace;
use crate::firewall::types::address::Cidr;
use crate::firewall::types::alias::AliasName;
use crate::guest::vm::NetworkConfig;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IpsetScope {
    Datacenter,
    Guest,
}

impl FromStr for IpsetScope {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "+dc" => IpsetScope::Datacenter,
            "+guest" => IpsetScope::Guest,
            _ => bail!("invalid scope for ipset: {s}"),
        })
    }
}

impl Display for IpsetScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self {
            Self::Datacenter => "dc",
            Self::Guest => "guest",
        };

        f.write_str(prefix)
    }
}

#[derive(Debug, Clone, DeserializeFromStr)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct IpsetName {
    pub scope: IpsetScope,
    pub name: String,
}

impl IpsetName {
    pub fn new(scope: IpsetScope, name: impl Into<String>) -> Self {
        Self {
            scope,
            name: name.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn scope(&self) -> IpsetScope {
        self.scope
    }
}

impl FromStr for IpsetName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('/') {
            Some((prefix, name)) if !name.is_empty() => Ok(Self {
                scope: prefix.parse()?,
                name: name.to_string(),
            }),
            _ => {
                bail!("Invalid IPSet name: {s}")
            }
        }
    }
}

impl Display for IpsetName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.scope, self.name)
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum IpsetAddress {
    Alias(AliasName),
    Cidr(Cidr),
}

impl FromStr for IpsetAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if let Ok(cidr) = s.parse() {
            return Ok(IpsetAddress::Cidr(cidr));
        }

        if let Ok(name) = s.parse() {
            return Ok(IpsetAddress::Alias(name));
        }

        bail!("Invalid address in IPSet: {s}")
    }
}

impl<T: Into<Cidr>> From<T> for IpsetAddress {
    fn from(cidr: T) -> Self {
        IpsetAddress::Cidr(cidr.into())
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct IpsetEntry {
    pub nomatch: bool,
    pub address: IpsetAddress,
    pub comment: Option<String>,
}

impl<T: Into<IpsetAddress>> From<T> for IpsetEntry {
    fn from(value: T) -> Self {
        Self {
            nomatch: false,
            address: value.into(),
            comment: None,
        }
    }
}

impl FromStr for IpsetEntry {
    type Err = Error;

    fn from_str(line: &str) -> Result<Self, Error> {
        let line = line.trim_start();

        let (nomatch, line) = match line.strip_prefix('!') {
            Some(line) => (true, line),
            None => (false, line),
        };

        let (address, line) =
            match_non_whitespace(line.trim_start()).ok_or_else(|| format_err!("missing value"))?;

        let address: IpsetAddress = address.parse()?;
        let line = line.trim_start();

        let comment = match line.strip_prefix('#') {
            Some(comment) => Some(comment.trim().to_string()),
            None if !line.is_empty() => bail!("trailing characters in ipset entry: {line:?}"),
            None => None,
        };

        Ok(Self {
            nomatch,
            address,
            comment,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Ipfilter<'a> {
    index: i64,
    ipset: &'a Ipset,
}

impl Ipfilter<'_> {
    pub fn index(&self) -> i64 {
        self.index
    }

    pub fn ipset(&self) -> &Ipset {
        self.ipset
    }

    pub fn name_for_index(index: i64) -> String {
        format!("ipfilter-net{index}")
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Ipset {
    pub name: IpsetName,
    set: Vec<IpsetEntry>,
    pub comment: Option<String>,
}

impl Ipset {
    pub const fn new(name: IpsetName) -> Self {
        Self {
            name,
            set: Vec::new(),
            comment: None,
        }
    }

    pub fn name(&self) -> &IpsetName {
        &self.name
    }

    pub fn from_parts(scope: IpsetScope, name: impl Into<String>) -> Self {
        Self::new(IpsetName::new(scope, name))
    }

    pub(crate) fn parse_entry(&mut self, line: &str) -> Result<(), Error> {
        self.set.push(line.parse()?);
        Ok(())
    }

    pub fn ipfilter(&self) -> Option<Ipfilter> {
        if self.name.scope() != IpsetScope::Guest {
            return None;
        }

        let name = self.name.name();

        if let Some(key) = name.strip_prefix("ipfilter-") {
            let id = NetworkConfig::index_from_net_key(key);

            if let Ok(id) = id {
                return Some(Ipfilter {
                    index: id,
                    ipset: self,
                });
            }
        }

        None
    }
}

impl Deref for Ipset {
    type Target = Vec<IpsetEntry>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.set
    }
}

impl DerefMut for Ipset {
    #[inline]
    fn deref_mut(&mut self) -> &mut Vec<IpsetEntry> {
        &mut self.set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipset_name() {
        for test_case in [
            ("+dc/proxmox-123", IpsetScope::Datacenter, "proxmox-123"),
            ("+guest/proxmox_123", IpsetScope::Guest, "proxmox_123"),
        ] {
            let ipset_name = test_case.0.parse::<IpsetName>().expect("valid ipset name");

            assert_eq!(
                ipset_name,
                IpsetName {
                    scope: test_case.1,
                    name: test_case.2.to_string(),
                }
            )
        }

        for name in ["+dc/", "+guests/proxmox_123", "guest/proxmox_123"] {
            name.parse::<IpsetName>().expect_err("invalid ipset name");
        }
    }

    #[test]
    fn test_parse_ipset_address() {
        let mut ipset_address = "10.0.0.1"
            .parse::<IpsetAddress>()
            .expect("valid ipset address");
        assert!(matches!(ipset_address, IpsetAddress::Cidr(Cidr::Ipv4(..))));

        ipset_address = "fe80::1/64"
            .parse::<IpsetAddress>()
            .expect("valid ipset address");
        assert!(matches!(ipset_address, IpsetAddress::Cidr(Cidr::Ipv6(..))));

        ipset_address = "dc/proxmox-123"
            .parse::<IpsetAddress>()
            .expect("valid ipset address");
        assert!(matches!(ipset_address, IpsetAddress::Alias(..)));

        ipset_address = "guest/proxmox_123"
            .parse::<IpsetAddress>()
            .expect("valid ipset address");
        assert!(matches!(ipset_address, IpsetAddress::Alias(..)));
    }

    #[test]
    fn test_ipfilter() {
        let mut ipset = Ipset::from_parts(IpsetScope::Guest, "ipfilter-net0");
        ipset.ipfilter().expect("is an ipfilter");

        ipset = Ipset::from_parts(IpsetScope::Guest, "ipfilter-qwe");
        assert!(ipset.ipfilter().is_none());

        ipset = Ipset::from_parts(IpsetScope::Guest, "proxmox");
        assert!(ipset.ipfilter().is_none());

        ipset = Ipset::from_parts(IpsetScope::Datacenter, "ipfilter-net0");
        assert!(ipset.ipfilter().is_none());
    }

    #[test]
    fn test_parse_ipset_entry() {
        let mut entry = "!10.0.0.1 # qweqweasd"
            .parse::<IpsetEntry>()
            .expect("valid ipset entry");

        assert_eq!(
            entry,
            IpsetEntry {
                nomatch: true,
                comment: Some("qweqweasd".to_string()),
                address: IpsetAddress::Cidr(Cidr::new_v4([10, 0, 0, 1], 32).unwrap())
            }
        );

        entry = "fe80::1/48"
            .parse::<IpsetEntry>()
            .expect("valid ipset entry");

        assert_eq!(
            entry,
            IpsetEntry {
                nomatch: false,
                comment: None,
                address: IpsetAddress::Cidr(
                    Cidr::new_v6([0xFE80, 0, 0, 0, 0, 0, 0, 1], 48).unwrap()
                )
            }
        )
    }
}
