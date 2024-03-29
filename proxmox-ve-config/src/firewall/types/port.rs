use std::fmt;
use std::ops::Deref;

use anyhow::{bail, Error};
use serde_with::DeserializeFromStr;

use crate::firewall::ports::parse_named_port;

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum PortEntry {
    Port(u16),
    Range(u16, u16),
}

impl fmt::Display for PortEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Port(p) => write!(f, "{p}"),
            Self::Range(beg, end) => write!(f, "{beg}-{end}"),
        }
    }
}

fn parse_port(port: &str) -> Result<u16, Error> {
    if let Ok(port) = port.parse::<u16>() {
        return Ok(port);
    }

    if let Ok(port) = parse_named_port(port) {
        return Ok(port);
    }

    bail!("invalid port specification: {port}")
}

impl std::str::FromStr for PortEntry {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().split_once(':') {
            None => PortEntry::from(parse_port(s)?),
            Some((first, second)) => {
                PortEntry::try_from((parse_port(first)?, parse_port(second)?))?
            }
        })
    }
}

impl From<u16> for PortEntry {
    fn from(port: u16) -> Self {
        PortEntry::Port(port)
    }
}

impl TryFrom<(u16, u16)> for PortEntry {
    type Error = Error;

    fn try_from(ports: (u16, u16)) -> Result<Self, Error> {
        if ports.0 > ports.1 {
            bail!("start port is greater than end port!");
        }

        Ok(PortEntry::Range(ports.0, ports.1))
    }
}

#[derive(Clone, Debug, DeserializeFromStr)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct PortList(pub(crate) Vec<PortEntry>);

impl FromIterator<PortEntry> for PortList {
    fn from_iter<T: IntoIterator<Item = PortEntry>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<T: Into<PortEntry>> From<T> for PortList {
    fn from(value: T) -> Self {
        Self(vec![value.into()])
    }
}

impl Deref for PortList {
    type Target = Vec<PortEntry>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::str::FromStr for PortList {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            bail!("empty port specification");
        }

        let mut entries = Vec::new();

        for entry in s.trim().split(',') {
            entries.push(entry.parse()?);
        }

        if entries.is_empty() {
            bail!("invalid empty port list");
        }

        Ok(Self(entries))
    }
}

impl fmt::Display for PortList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write;
        if self.0.len() > 1 {
            f.write_char('{')?;
        }

        let mut comma = '\0';
        for entry in &self.0 {
            if std::mem::replace(&mut comma, ',') != '\0' {
                f.write_char(comma)?;
            }
            fmt::Display::fmt(entry, f)?;
        }

        if self.0.len() > 1 {
            f.write_char('}')?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_entry() {
        let mut port_entry: PortEntry = "12345".parse().expect("valid port entry");
        assert_eq!(port_entry, PortEntry::from(12345));

        port_entry = "0:65535".parse().expect("valid port entry");
        assert_eq!(port_entry, PortEntry::try_from((0, 65535)).unwrap());

        "65536".parse::<PortEntry>().unwrap_err();
        "100:100000".parse::<PortEntry>().unwrap_err();
        "qweasd".parse::<PortEntry>().unwrap_err();
        "".parse::<PortEntry>().unwrap_err();
    }

    #[test]
    fn test_parse_port_list() {
        let mut port_list: PortList = "12345".parse().expect("valid port list");
        assert_eq!(port_list, PortList::from(12345));

        port_list = "12345,0:65535,1337,ssh:80,https"
            .parse()
            .expect("valid port list");

        assert_eq!(
            port_list,
            PortList(vec![
                PortEntry::from(12345),
                PortEntry::try_from((0, 65535)).unwrap(),
                PortEntry::from(1337),
                PortEntry::try_from((22, 80)).unwrap(),
                PortEntry::from(443),
            ])
        );

        "0::1337".parse::<PortList>().unwrap_err();
        "0:1337,".parse::<PortList>().unwrap_err();
        "70000".parse::<PortList>().unwrap_err();
        "qweasd".parse::<PortList>().unwrap_err();
        "".parse::<PortList>().unwrap_err();
    }
}
