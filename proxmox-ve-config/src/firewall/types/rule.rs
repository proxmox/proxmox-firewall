use core::fmt::Display;
use std::fmt;
use std::str::FromStr;

use anyhow::{bail, ensure, format_err, Error};

use crate::firewall::parse::match_name;
use crate::firewall::types::rule_match::RuleMatch;
use crate::firewall::types::rule_match::RuleOptions;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Direction {
    #[default]
    In,
    Out,
}

impl std::str::FromStr for Direction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        for (name, dir) in [("IN", Direction::In), ("OUT", Direction::Out)] {
            if s.eq_ignore_ascii_case(name) {
                return Ok(dir);
            }
        }

        bail!("invalid direction: {s:?}, expect 'IN' or 'OUT'");
    }
}

serde_plain::derive_deserialize_from_fromstr!(Direction, "valid packet direction");

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Direction::In => f.write_str("in"),
            Direction::Out => f.write_str("out"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Verdict {
    Accept,
    Reject,
    #[default]
    Drop,
}

impl std::str::FromStr for Verdict {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        for (name, verdict) in [
            ("ACCEPT", Verdict::Accept),
            ("REJECT", Verdict::Reject),
            ("DROP", Verdict::Drop),
        ] {
            if s.eq_ignore_ascii_case(name) {
                return Ok(verdict);
            }
        }
        bail!("invalid verdict {s:?}, expected one of 'ACCEPT', 'REJECT' or 'DROP'");
    }
}

impl Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            Verdict::Accept => "ACCEPT",
            Verdict::Drop => "DROP",
            Verdict::Reject => "REJECT",
        };

        write!(f, "{string}")
    }
}

serde_plain::derive_deserialize_from_fromstr!(Verdict, "valid verdict");

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Rule {
    pub(crate) disabled: bool,
    pub(crate) kind: Kind,
    pub(crate) comment: Option<String>,
}

impl std::ops::Deref for Rule {
    type Target = Kind;

    fn deref(&self) -> &Self::Target {
        &self.kind
    }
}

impl std::ops::DerefMut for Rule {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.kind
    }
}

impl FromStr for Rule {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.contains(['\n', '\r']) {
            bail!("rule must not contain any newlines!");
        }

        let (line, comment) = match input.rsplit_once('#') {
            Some((line, comment)) if !comment.is_empty() => (line.trim(), Some(comment.trim())),
            _ => (input.trim(), None),
        };

        let (disabled, line) = match line.strip_prefix('|') {
            Some(line) => (true, line.trim_start()),
            None => (false, line),
        };

        // todo: case insensitive?
        let kind = if line.starts_with("GROUP") {
            Kind::from(line.parse::<RuleGroup>()?)
        } else {
            Kind::from(line.parse::<RuleMatch>()?)
        };

        Ok(Self {
            disabled,
            comment: comment.map(str::to_string),
            kind,
        })
    }
}

impl Rule {
    pub fn iface(&self) -> Option<&str> {
        match &self.kind {
            Kind::Group(group) => group.iface(),
            Kind::Match(rule) => rule.iface(),
        }
    }

    pub fn disabled(&self) -> bool {
        self.disabled
    }

    pub fn kind(&self) -> &Kind {
        &self.kind
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum Kind {
    Group(RuleGroup),
    Match(RuleMatch),
}

impl Kind {
    pub fn is_group(&self) -> bool {
        matches!(self, Kind::Group(_))
    }

    pub fn is_match(&self) -> bool {
        matches!(self, Kind::Match(_))
    }
}

impl From<RuleGroup> for Kind {
    fn from(value: RuleGroup) -> Self {
        Kind::Group(value)
    }
}

impl From<RuleMatch> for Kind {
    fn from(value: RuleMatch) -> Self {
        Kind::Match(value)
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct RuleGroup {
    pub(crate) group: String,
    pub(crate) iface: Option<String>,
}

impl RuleGroup {
    pub(crate) fn from_options(group: String, options: RuleOptions) -> Result<Self, Error> {
        ensure!(
            options.proto.is_none()
                && options.dport.is_none()
                && options.sport.is_none()
                && options.dest.is_none()
                && options.source.is_none()
                && options.log.is_none()
                && options.icmp_type.is_none(),
            "only interface parameter is permitted for group rules"
        );

        Ok(Self {
            group,
            iface: options.iface,
        })
    }

    pub fn group(&self) -> &str {
        &self.group
    }

    pub fn iface(&self) -> Option<&str> {
        self.iface.as_deref()
    }
}

impl FromStr for RuleGroup {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (keyword, rest) = match_name(input)
            .ok_or_else(|| format_err!("expected a leading keyword in rule group"))?;

        if !keyword.eq_ignore_ascii_case("group") {
            bail!("Expected keyword GROUP")
        }

        let (name, rest) =
            match_name(rest.trim()).ok_or_else(|| format_err!("expected a name for rule group"))?;

        let options = rest.trim_start().parse()?;

        Self::from_options(name.to_string(), options)
    }
}

#[cfg(test)]
mod tests {
    use crate::firewall::types::{
        address::{IpEntry, IpList},
        alias::{AliasName, AliasScope},
        ipset::{IpsetName, IpsetScope},
        log::LogLevel,
        rule_match::{Icmp, IcmpCode, IpAddrMatch, IpMatch, Ports, Protocol, Udp},
        Cidr,
    };

    use super::*;

    #[test]
    fn test_parse_rule() {
        let mut rule: Rule = "|GROUP tgr -i eth0 # acomm".parse().expect("valid rule");

        assert_eq!(
            rule,
            Rule {
                disabled: true,
                comment: Some("acomm".to_string()),
                kind: Kind::Group(RuleGroup {
                    group: "tgr".to_string(),
                    iface: Some("eth0".to_string()),
                }),
            },
        );

        rule = "IN ACCEPT -p udp -dport 33 -sport 22 -log warning"
            .parse()
            .expect("valid rule");

        assert_eq!(
            rule,
            Rule {
                disabled: false,
                comment: None,
                kind: Kind::Match(RuleMatch {
                    dir: Direction::In,
                    verdict: Verdict::Accept,
                    proto: Some(Udp::new(Ports::from_u16(22, 33)).into()),
                    log: Some(LogLevel::Warning),
                    ..Default::default()
                }),
            }
        );

        rule = "IN ACCEPT --proto udp -i eth0".parse().expect("valid rule");

        assert_eq!(
            rule,
            Rule {
                disabled: false,
                comment: None,
                kind: Kind::Match(RuleMatch {
                    dir: Direction::In,
                    verdict: Verdict::Accept,
                    proto: Some(Udp::new(Ports::new(None, None)).into()),
                    iface: Some("eth0".to_string()),
                    ..Default::default()
                }),
            }
        );

        rule = " OUT DROP \
          -source 10.0.0.0/24 -dest 20.0.0.0-20.255.255.255,192.168.0.0/16 \
          -p icmp -log nolog -icmp-type port-unreachable "
            .parse()
            .expect("valid rule");

        assert_eq!(
            rule,
            Rule {
                disabled: false,
                comment: None,
                kind: Kind::Match(RuleMatch {
                    dir: Direction::Out,
                    verdict: Verdict::Drop,
                    ip: IpMatch::new(
                        IpAddrMatch::Ip(IpList::from(Cidr::new_v4([10, 0, 0, 0], 24).unwrap())),
                        IpAddrMatch::Ip(
                            IpList::new(vec![
                                IpEntry::Range([20, 0, 0, 0].into(), [20, 255, 255, 255].into()),
                                IpEntry::Cidr(Cidr::new_v4([192, 168, 0, 0], 16).unwrap()),
                            ])
                            .unwrap()
                        ),
                    )
                    .ok(),
                    proto: Some(Protocol::Icmp(Icmp::new_code(IcmpCode::Named(
                        "port-unreachable"
                    )))),
                    log: Some(LogLevel::Nolog),
                    ..Default::default()
                }),
            }
        );

        rule = "IN BGP(ACCEPT) --log crit --iface eth0"
            .parse()
            .expect("valid rule");

        assert_eq!(
            rule,
            Rule {
                disabled: false,
                comment: None,
                kind: Kind::Match(RuleMatch {
                    dir: Direction::In,
                    verdict: Verdict::Accept,
                    log: Some(LogLevel::Critical),
                    fw_macro: Some("BGP".to_string()),
                    iface: Some("eth0".to_string()),
                    ..Default::default()
                }),
            }
        );

        rule = "IN ACCEPT --source dc/test --dest +dc/test"
            .parse()
            .expect("valid rule");

        assert_eq!(
            rule,
            Rule {
                disabled: false,
                comment: None,
                kind: Kind::Match(RuleMatch {
                    dir: Direction::In,
                    verdict: Verdict::Accept,
                    ip: Some(
                        IpMatch::new(
                            IpAddrMatch::Alias(AliasName::new(AliasScope::Datacenter, "test")),
                            IpAddrMatch::Set(IpsetName::new(IpsetScope::Datacenter, "test"),),
                        )
                        .unwrap()
                    ),
                    ..Default::default()
                }),
            }
        );

        rule = "IN REJECT".parse().expect("valid rule");

        assert_eq!(
            rule,
            Rule {
                disabled: false,
                comment: None,
                kind: Kind::Match(RuleMatch {
                    dir: Direction::In,
                    verdict: Verdict::Reject,
                    ..Default::default()
                }),
            }
        );

        "IN DROP ---log crit"
            .parse::<Rule>()
            .expect_err("too many dashes in option");

        "IN DROP --log --iface eth0"
            .parse::<Rule>()
            .expect_err("no value for option");

        "IN DROP --log crit --iface"
            .parse::<Rule>()
            .expect_err("no value for option");
    }
}
