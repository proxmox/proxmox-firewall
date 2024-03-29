use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use anyhow::{bail, format_err, Error};
use serde::de::IntoDeserializer;

use proxmox_sortable_macro::sortable;

use crate::firewall::parse::{match_name, match_non_whitespace, SomeStr};
use crate::firewall::types::address::{Family, IpList};
use crate::firewall::types::alias::AliasName;
use crate::firewall::types::ipset::IpsetName;
use crate::firewall::types::log::LogLevel;
use crate::firewall::types::port::PortList;
use crate::firewall::types::rule::{Direction, Verdict};

#[derive(Clone, Debug, Default, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct RuleOptions {
    #[serde(alias = "p")]
    pub(crate) proto: Option<String>,

    pub(crate) dport: Option<String>,
    pub(crate) sport: Option<String>,

    pub(crate) dest: Option<String>,
    pub(crate) source: Option<String>,

    #[serde(alias = "i")]
    pub(crate) iface: Option<String>,

    pub(crate) log: Option<LogLevel>,
    pub(crate) icmp_type: Option<String>,
}

impl FromStr for RuleOptions {
    type Err = Error;

    fn from_str(mut line: &str) -> Result<Self, Self::Err> {
        let mut options = HashMap::new();

        loop {
            line = line.trim_start();

            if line.is_empty() {
                break;
            }

            line = line
                .strip_prefix('-')
                .ok_or_else(|| format_err!("expected an option starting with '-'"))?;

            // second dash is optional
            line = line.strip_prefix('-').unwrap_or(line);

            let param;
            (param, line) = match_name(line)
                .ok_or_else(|| format_err!("expected a parameter name after '-'"))?;

            let value;
            (value, line) = match_non_whitespace(line.trim_start())
                .ok_or_else(|| format_err!("expected a value for {param:?}"))?;

            if options.insert(param, SomeStr(value)).is_some() {
                bail!("duplicate option in rule: {param}")
            }
        }

        Ok(RuleOptions::deserialize(IntoDeserializer::<
            '_,
            crate::firewall::parse::SerdeStringError,
        >::into_deserializer(
            options
        ))?)
    }
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct RuleMatch {
    pub(crate) dir: Direction,
    pub(crate) verdict: Verdict,
    pub(crate) fw_macro: Option<String>,

    pub(crate) iface: Option<String>,
    pub(crate) log: Option<LogLevel>,
    pub(crate) ip: Option<IpMatch>,
    pub(crate) proto: Option<Protocol>,
}

impl RuleMatch {
    pub(crate) fn from_options(
        dir: Direction,
        verdict: Verdict,
        fw_macro: impl Into<Option<String>>,
        options: RuleOptions,
    ) -> Result<Self, Error> {
        if options.dport.is_some() && options.icmp_type.is_some() {
            bail!("dport and icmp-type are mutually exclusive");
        }

        let ip = IpMatch::from_options(&options)?;
        let proto = Protocol::from_options(&options)?;

        // todo: check protocol & IP Version compatibility

        Ok(Self {
            dir,
            verdict,
            fw_macro: fw_macro.into(),
            iface: options.iface,
            log: options.log,
            ip,
            proto,
        })
    }

    pub fn direction(&self) -> Direction {
        self.dir
    }

    pub fn iface(&self) -> Option<&str> {
        self.iface.as_deref()
    }

    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    pub fn fw_macro(&self) -> Option<&str> {
        self.fw_macro.as_deref()
    }

    pub fn log(&self) -> Option<LogLevel> {
        self.log
    }

    pub fn ip(&self) -> Option<&IpMatch> {
        self.ip.as_ref()
    }

    pub fn proto(&self) -> Option<&Protocol> {
        self.proto.as_ref()
    }
}

/// Returns `(Macro name, Verdict, RestOfTheLine)`.
fn parse_action(line: &str) -> Result<(Option<&str>, Verdict, &str), Error> {
    let (verdict, line) =
        match_name(line).ok_or_else(|| format_err!("expected a verdict or macro name"))?;

    Ok(if let Some(line) = line.strip_prefix('(') {
        // <macro>(<verdict>)

        let macro_name = verdict;
        let (verdict, line) = match_name(line).ok_or_else(|| format_err!("expected a verdict"))?;
        let line = line
            .strip_prefix(')')
            .ok_or_else(|| format_err!("expected closing ')' after verdict"))?;

        let verdict: Verdict = verdict.parse()?;

        (Some(macro_name), verdict, line.trim_start())
    } else {
        (None, verdict.parse()?, line.trim_start())
    })
}

impl FromStr for RuleMatch {
    type Err = Error;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let (dir, rest) = match_name(line).ok_or_else(|| format_err!("expected a direction"))?;

        let direction: Direction = dir.parse()?;

        let (fw_macro, verdict, rest) = parse_action(rest.trim_start())?;

        let options: RuleOptions = rest.trim_start().parse()?;

        Self::from_options(direction, verdict, fw_macro.map(str::to_string), options)
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct IpMatch {
    pub(crate) src: Option<IpAddrMatch>,
    pub(crate) dst: Option<IpAddrMatch>,
}

impl IpMatch {
    pub fn new(
        src: impl Into<Option<IpAddrMatch>>,
        dst: impl Into<Option<IpAddrMatch>>,
    ) -> Result<Self, Error> {
        let source = src.into();
        let dest = dst.into();

        if source.is_none() && dest.is_none() {
            bail!("either src or dst must be set")
        }

        if let (Some(IpAddrMatch::Ip(src)), Some(IpAddrMatch::Ip(dst))) = (&source, &dest) {
            if src.family() != dst.family() {
                bail!("src and dst family must be equal")
            }
        }

        let ip_match = Self {
            src: source,
            dst: dest,
        };

        Ok(ip_match)
    }

    fn from_options(options: &RuleOptions) -> Result<Option<Self>, Error> {
        let src = options
            .source
            .as_ref()
            .map(|elem| elem.parse::<IpAddrMatch>())
            .transpose()?;

        let dst = options
            .dest
            .as_ref()
            .map(|elem| elem.parse::<IpAddrMatch>())
            .transpose()?;

        if src.is_some() || dst.is_some() {
            Ok(Some(IpMatch::new(src, dst)?))
        } else {
            Ok(None)
        }
    }

    pub fn src(&self) -> Option<&IpAddrMatch> {
        self.src.as_ref()
    }

    pub fn dst(&self) -> Option<&IpAddrMatch> {
        self.dst.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum IpAddrMatch {
    Ip(IpList),
    Set(IpsetName),
    Alias(AliasName),
}

impl IpAddrMatch {
    pub fn family(&self) -> Option<Family> {
        if let IpAddrMatch::Ip(list) = self {
            return Some(list.family());
        }

        None
    }
}

impl FromStr for IpAddrMatch {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Error> {
        if value.is_empty() {
            bail!("empty IP specification");
        }

        if let Ok(ip_list) = value.parse() {
            return Ok(IpAddrMatch::Ip(ip_list));
        }

        if let Ok(ipset) = value.parse() {
            return Ok(IpAddrMatch::Set(ipset));
        }

        if let Ok(name) = value.parse() {
            return Ok(IpAddrMatch::Alias(name));
        }

        bail!("invalid IP specification: {value}")
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum Protocol {
    Dccp(Ports),
    Sctp(Sctp),
    Tcp(Tcp),
    Udp(Udp),
    UdpLite(Ports),
    Icmp(Icmp),
    Icmpv6(Icmpv6),
    Named(String),
    Numeric(u8),
}

impl Protocol {
    pub(crate) fn from_options(options: &RuleOptions) -> Result<Option<Self>, Error> {
        let proto = match options.proto.as_deref() {
            Some(p) => p,
            None => return Ok(None),
        };

        Ok(Some(match proto {
            "dccp" | "33" => Protocol::Dccp(Ports::from_options(options)?),
            "sctp" | "132" => Protocol::Sctp(Sctp::from_options(options)?),
            "tcp" | "6" => Protocol::Tcp(Tcp::from_options(options)?),
            "udp" | "17" => Protocol::Udp(Udp::from_options(options)?),
            "udplite" | "136" => Protocol::UdpLite(Ports::from_options(options)?),
            "icmp" | "1" => Protocol::Icmp(Icmp::from_options(options)?),
            "ipv6-icmp" | "icmpv6" | "58" => Protocol::Icmpv6(Icmpv6::from_options(options)?),
            other => match other.parse::<u8>() {
                Ok(num) => Protocol::Numeric(num),
                Err(_) => Protocol::Named(other.to_string()),
            },
        }))
    }

    pub fn family(&self) -> Option<Family> {
        match self {
            Self::Icmp(_) => Some(Family::V4),
            Self::Icmpv6(_) => Some(Family::V6),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Udp {
    ports: Ports,
}

impl Udp {
    fn from_options(options: &RuleOptions) -> Result<Self, Error> {
        Ok(Self {
            ports: Ports::from_options(options)?,
        })
    }

    pub fn new(ports: Ports) -> Self {
        Self { ports }
    }

    pub fn ports(&self) -> &Ports {
        &self.ports
    }
}

impl From<Udp> for Protocol {
    fn from(value: Udp) -> Self {
        Protocol::Udp(value)
    }
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Ports {
    sport: Option<PortList>,
    dport: Option<PortList>,
}

impl Ports {
    pub fn new(sport: impl Into<Option<PortList>>, dport: impl Into<Option<PortList>>) -> Self {
        Self {
            sport: sport.into(),
            dport: dport.into(),
        }
    }

    fn from_options(options: &RuleOptions) -> Result<Self, Error> {
        Ok(Self {
            sport: options.sport.as_deref().map(|s| s.parse()).transpose()?,
            dport: options.dport.as_deref().map(|s| s.parse()).transpose()?,
        })
    }

    pub fn from_u16(sport: impl Into<Option<u16>>, dport: impl Into<Option<u16>>) -> Self {
        Self::new(
            sport.into().map(PortList::from),
            dport.into().map(PortList::from),
        )
    }

    pub fn sport(&self) -> Option<&PortList> {
        self.sport.as_ref()
    }

    pub fn dport(&self) -> Option<&PortList> {
        self.dport.as_ref()
    }
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Tcp {
    ports: Ports,
}

impl Tcp {
    pub fn new(ports: Ports) -> Self {
        Self { ports }
    }

    fn from_options(options: &RuleOptions) -> Result<Self, Error> {
        Ok(Self {
            ports: Ports::from_options(options)?,
        })
    }

    pub fn ports(&self) -> &Ports {
        &self.ports
    }
}

impl From<Tcp> for Protocol {
    fn from(value: Tcp) -> Self {
        Protocol::Tcp(value)
    }
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Sctp {
    ports: Ports,
}

impl Sctp {
    fn from_options(options: &RuleOptions) -> Result<Self, Error> {
        Ok(Self {
            ports: Ports::from_options(options)?,
        })
    }

    pub fn ports(&self) -> &Ports {
        &self.ports
    }
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Icmp {
    ty: Option<IcmpType>,
    code: Option<IcmpCode>,
}

impl Icmp {
    pub fn new_ty(ty: IcmpType) -> Self {
        Self {
            ty: Some(ty),
            ..Default::default()
        }
    }

    pub fn new_code(code: IcmpCode) -> Self {
        Self {
            code: Some(code),
            ..Default::default()
        }
    }

    fn from_options(options: &RuleOptions) -> Result<Self, Error> {
        if let Some(ty) = &options.icmp_type {
            return ty.parse();
        }

        Ok(Self::default())
    }

    pub fn ty(&self) -> Option<&IcmpType> {
        self.ty.as_ref()
    }

    pub fn code(&self) -> Option<&IcmpCode> {
        self.code.as_ref()
    }
}

impl FromStr for Icmp {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut this = Self::default();

        if let Ok(ty) = s.parse() {
            this.ty = Some(ty);
            return Ok(this);
        }

        if let Ok(code) = s.parse() {
            this.code = Some(code);
            return Ok(this);
        }

        bail!("supplied string is neither a valid icmp type nor code");
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum IcmpType {
    Numeric(u8),
    Named(&'static str),
}

#[sortable]
const ICMP_TYPES: [(&str, u8); 15] = sorted!([
    ("address-mask-reply", 18),
    ("address-mask-request", 17),
    ("destination-unreachable", 3),
    ("echo-reply", 0),
    ("echo-request", 8),
    ("info-reply", 16),
    ("info-request", 15),
    ("parameter-problem", 12),
    ("redirect", 5),
    ("router-advertisement", 9),
    ("router-solicitation", 10),
    ("source-quench", 4),
    ("time-exceeded", 11),
    ("timestamp-reply", 14),
    ("timestamp-request", 13),
]);

impl std::str::FromStr for IcmpType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if let Ok(ty) = s.trim().parse::<u8>() {
            return Ok(Self::Numeric(ty));
        }

        if let Ok(index) = ICMP_TYPES.binary_search_by(|v| v.0.cmp(s)) {
            return Ok(Self::Named(ICMP_TYPES[index].0));
        }

        bail!("{s:?} is not a valid icmp type");
    }
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IcmpType::Numeric(ty) => write!(f, "{ty}"),
            IcmpType::Named(ty) => write!(f, "{ty}"),
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum IcmpCode {
    Numeric(u8),
    Named(&'static str),
}

#[sortable]
const ICMP_CODES: [(&str, u8); 7] = sorted!([
    ("admin-prohibited", 13),
    ("host-prohibited", 10),
    ("host-unreachable", 1),
    ("net-prohibited", 9),
    ("net-unreachable", 0),
    ("port-unreachable", 3),
    ("prot-unreachable", 2),
]);

impl std::str::FromStr for IcmpCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if let Ok(code) = s.trim().parse::<u8>() {
            return Ok(Self::Numeric(code));
        }

        if let Ok(index) = ICMP_CODES.binary_search_by(|v| v.0.cmp(s)) {
            return Ok(Self::Named(ICMP_CODES[index].0));
        }

        bail!("{s:?} is not a valid icmp code");
    }
}

impl fmt::Display for IcmpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IcmpCode::Numeric(code) => write!(f, "{code}"),
            IcmpCode::Named(code) => write!(f, "{code}"),
        }
    }
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Icmpv6 {
    pub ty: Option<Icmpv6Type>,
    pub code: Option<Icmpv6Code>,
}

impl Icmpv6 {
    pub fn new_ty(ty: Icmpv6Type) -> Self {
        Self {
            ty: Some(ty),
            ..Default::default()
        }
    }

    pub fn new_code(code: Icmpv6Code) -> Self {
        Self {
            code: Some(code),
            ..Default::default()
        }
    }

    fn from_options(options: &RuleOptions) -> Result<Self, Error> {
        if let Some(ty) = &options.icmp_type {
            return ty.parse();
        }

        Ok(Self::default())
    }

    pub fn ty(&self) -> Option<&Icmpv6Type> {
        self.ty.as_ref()
    }

    pub fn code(&self) -> Option<&Icmpv6Code> {
        self.code.as_ref()
    }
}

impl FromStr for Icmpv6 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut this = Self::default();

        if let Ok(ty) = s.parse() {
            this.ty = Some(ty);
            return Ok(this);
        }

        if let Ok(code) = s.parse() {
            this.code = Some(code);
            return Ok(this);
        }

        bail!("supplied string is neither a valid icmpv6 type nor code");
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum Icmpv6Type {
    Numeric(u8),
    Named(&'static str),
}

#[sortable]
const ICMPV6_TYPES: [(&str, u8); 19] = sorted!([
    ("destination-unreachable", 1),
    ("echo-reply", 129),
    ("echo-request", 128),
    ("ind-neighbor-advert", 142),
    ("ind-neighbor-solicit", 141),
    ("mld-listener-done", 132),
    ("mld-listener-query", 130),
    ("mld-listener-reduction", 132),
    ("mld-listener-report", 131),
    ("mld2-listener-report", 143),
    ("nd-neighbor-advert", 136),
    ("nd-neighbor-solicit", 135),
    ("nd-redirect", 137),
    ("nd-router-advert", 134),
    ("nd-router-solicit", 133),
    ("packet-too-big", 2),
    ("parameter-problem", 4),
    ("router-renumbering", 138),
    ("time-exceeded", 3),
]);

impl std::str::FromStr for Icmpv6Type {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if let Ok(ty) = s.trim().parse::<u8>() {
            return Ok(Self::Numeric(ty));
        }

        if let Ok(index) = ICMPV6_TYPES.binary_search_by(|v| v.0.cmp(s)) {
            return Ok(Self::Named(ICMPV6_TYPES[index].0));
        }

        bail!("{s:?} is not a valid icmpv6 type");
    }
}

impl fmt::Display for Icmpv6Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Icmpv6Type::Numeric(ty) => write!(f, "{ty}"),
            Icmpv6Type::Named(ty) => write!(f, "{ty}"),
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum Icmpv6Code {
    Numeric(u8),
    Named(&'static str),
}

#[sortable]
const ICMPV6_CODES: [(&str, u8); 6] = sorted!([
    ("addr-unreachable", 3),
    ("admin-prohibited", 1),
    ("no-route", 0),
    ("policy-fail", 5),
    ("port-unreachable", 4),
    ("reject-route", 6),
]);

impl std::str::FromStr for Icmpv6Code {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if let Ok(code) = s.trim().parse::<u8>() {
            return Ok(Self::Numeric(code));
        }

        if let Ok(index) = ICMPV6_CODES.binary_search_by(|v| v.0.cmp(s)) {
            return Ok(Self::Named(ICMPV6_CODES[index].0));
        }

        bail!("{s:?} is not a valid icmpv6 code");
    }
}

impl fmt::Display for Icmpv6Code {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Icmpv6Code::Numeric(code) => write!(f, "{code}"),
            Icmpv6Code::Named(code) => write!(f, "{code}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::firewall::types::{alias::AliasScope::Guest, Cidr};

    use super::*;

    #[test]
    fn test_parse_action() {
        assert_eq!(parse_action("REJECT").unwrap(), (None, Verdict::Reject, ""));

        assert_eq!(
            parse_action("SSH(ACCEPT) qweasd").unwrap(),
            (Some("SSH"), Verdict::Accept, "qweasd")
        );
    }

    #[test]
    fn test_parse_ip_addr_match() {
        for input in [
            "10.0.0.0/8",
            "10.0.0.0/8,192.168.0.0-192.168.255.255,172.16.0.1",
            "dc/test",
            "+guest/proxmox",
        ] {
            input.parse::<IpAddrMatch>().expect("valid ip match");
        }

        for input in [
            "10.0.0.0/",
            "10.0.0.0/8,192.168.256.0-192.168.255.255,172.16.0.1",
            "dcc/test",
            "+guest/",
            "",
        ] {
            input.parse::<IpAddrMatch>().expect_err("invalid ip match");
        }
    }

    #[test]
    fn test_parse_options() {
        let mut options: RuleOptions =
            "-p udp --sport 123 --dport 234 -source 127.0.0.1 --dest 127.0.0.1 -i ens1 --log crit"
                .parse()
                .expect("valid option string");

        assert_eq!(
            options,
            RuleOptions {
                proto: Some("udp".to_string()),
                sport: Some("123".to_string()),
                dport: Some("234".to_string()),
                source: Some("127.0.0.1".to_string()),
                dest: Some("127.0.0.1".to_string()),
                iface: Some("ens1".to_string()),
                log: Some(LogLevel::Critical),
                icmp_type: None,
            }
        );

        options = "".parse().expect("valid option string");

        assert_eq!(options, RuleOptions::default(),);
    }

    #[test]
    fn test_construct_ip_match() {
        IpMatch::new(
            IpAddrMatch::Ip(IpList::from(Cidr::new_v4([10, 0, 0, 0], 8).unwrap())),
            IpAddrMatch::Ip(IpList::from(Cidr::new_v4([10, 0, 0, 0], 8).unwrap())),
        )
        .expect("valid ip match");

        IpMatch::new(
            IpAddrMatch::Ip(IpList::from(Cidr::new_v4([10, 0, 0, 0], 8).unwrap())),
            IpAddrMatch::Alias(AliasName::new(Guest, "test")),
        )
        .expect("valid ip match");

        IpMatch::new(
            IpAddrMatch::Ip(IpList::from(Cidr::new_v4([10, 0, 0, 0], 8).unwrap())),
            IpAddrMatch::Ip(IpList::from(Cidr::new_v6([0x0000; 8], 8).unwrap())),
        )
        .expect_err("cannot mix ip families");

        IpMatch::new(None, None).expect_err("at least one ip must be set");
    }

    #[test]
    fn test_from_options() {
        let mut options = RuleOptions {
            proto: Some("tcp".to_string()),
            sport: Some("123".to_string()),
            dport: Some("234".to_string()),
            source: Some("192.168.0.1".to_string()),
            dest: Some("10.0.0.1".to_string()),
            iface: Some("eth123".to_string()),
            log: Some(LogLevel::Error),
            ..Default::default()
        };

        assert_eq!(
            Protocol::from_options(&options).unwrap().unwrap(),
            Protocol::Tcp(Tcp::new(Ports::from_u16(123, 234))),
        );

        assert_eq!(
            IpMatch::from_options(&options).unwrap().unwrap(),
            IpMatch::new(
                IpAddrMatch::Ip(IpList::from(Cidr::new_v4([192, 168, 0, 1], 32).unwrap()),),
                IpAddrMatch::Ip(IpList::from(Cidr::new_v4([10, 0, 0, 1], 32).unwrap()),)
            )
            .unwrap(),
        );

        options = RuleOptions::default();

        assert_eq!(Protocol::from_options(&options).unwrap(), None,);

        assert_eq!(IpMatch::from_options(&options).unwrap(), None,);

        options = RuleOptions {
            proto: Some("tcp".to_string()),
            sport: Some("qwe".to_string()),
            source: Some("qwe".to_string()),
            ..Default::default()
        };

        Protocol::from_options(&options).expect_err("invalid source port");

        IpMatch::from_options(&options).expect_err("invalid source address");

        options = RuleOptions {
            icmp_type: Some("port-unreachable".to_string()),
            dport: Some("123".to_string()),
            ..Default::default()
        };

        RuleMatch::from_options(Direction::In, Verdict::Drop, None, options)
            .expect_err("cannot mix dport and icmp-type");
    }

    #[test]
    fn test_parse_icmp() {
        let mut icmp: Icmp = "info-request".parse().expect("valid icmp type");

        assert_eq!(
            icmp,
            Icmp {
                ty: Some(IcmpType::Named("info-request")),
                code: None
            }
        );

        icmp = "12".parse().expect("valid icmp type");

        assert_eq!(
            icmp,
            Icmp {
                ty: Some(IcmpType::Numeric(12)),
                code: None
            }
        );

        icmp = "port-unreachable".parse().expect("valid icmp code");

        assert_eq!(
            icmp,
            Icmp {
                ty: None,
                code: Some(IcmpCode::Named("port-unreachable"))
            }
        );
    }

    #[test]
    fn test_parse_icmp6() {
        let mut icmp: Icmpv6 = "echo-reply".parse().expect("valid icmpv6 type");

        assert_eq!(
            icmp,
            Icmpv6 {
                ty: Some(Icmpv6Type::Named("echo-reply")),
                code: None
            }
        );

        icmp = "12".parse().expect("valid icmpv6 type");

        assert_eq!(
            icmp,
            Icmpv6 {
                ty: Some(Icmpv6Type::Numeric(12)),
                code: None
            }
        );

        icmp = "admin-prohibited".parse().expect("valid icmpv6 code");

        assert_eq!(
            icmp,
            Icmpv6 {
                ty: None,
                code: Some(Icmpv6Code::Named("admin-prohibited"))
            }
        );
    }
}
