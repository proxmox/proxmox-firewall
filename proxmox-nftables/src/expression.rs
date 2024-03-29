use crate::types::{ElemConfig, Verdict};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(feature = "config-ext")]
use proxmox_ve_config::firewall::types::address::{Family, IpEntry, IpList};
#[cfg(feature = "config-ext")]
use proxmox_ve_config::firewall::types::port::{PortEntry, PortList};
#[cfg(feature = "config-ext")]
use proxmox_ve_config::firewall::types::rule_match::{IcmpCode, IcmpType, Icmpv6Code, Icmpv6Type};
#[cfg(feature = "config-ext")]
use proxmox_ve_config::firewall::types::Cidr;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Expression {
    Concat(Vec<Expression>),
    Set(Vec<Expression>),
    Range(Box<(Expression, Expression)>),
    Map(Box<Map>),
    Prefix(Prefix),
    Payload(Payload),
    Meta(Meta),
    Ct(Ct),
    Elem(Box<Element>),

    #[serde(rename = "|")]
    Or(Box<(Expression, Expression)>),
    #[serde(rename = "&")]
    And(Box<(Expression, Expression)>),
    #[serde(rename = "^")]
    Xor(Box<(Expression, Expression)>),
    #[serde(rename = "<<")]
    ShiftLeft(Box<(Expression, Expression)>),
    #[serde(rename = ">>")]
    ShiftRight(Box<(Expression, Expression)>),

    #[serde(untagged)]
    List(Vec<Expression>),

    #[serde(untagged)]
    Verdict(Verdict),

    #[serde(untagged)]
    Bool(bool),
    #[serde(untagged)]
    Number(i64),
    #[serde(untagged)]
    String(String),
}

impl Expression {
    pub fn set(expressions: impl IntoIterator<Item = Expression>) -> Self {
        Expression::Set(Vec::from_iter(expressions))
    }

    pub fn concat(expressions: impl IntoIterator<Item = Expression>) -> Self {
        Expression::Concat(Vec::from_iter(expressions))
    }
}

impl From<bool> for Expression {
    #[inline]
    fn from(v: bool) -> Self {
        Expression::Bool(v)
    }
}

impl From<i64> for Expression {
    #[inline]
    fn from(v: i64) -> Self {
        Expression::Number(v)
    }
}

impl From<u16> for Expression {
    #[inline]
    fn from(v: u16) -> Self {
        Expression::Number(v.into())
    }
}

impl From<u8> for Expression {
    #[inline]
    fn from(v: u8) -> Self {
        Expression::Number(v.into())
    }
}

impl From<&str> for Expression {
    #[inline]
    fn from(v: &str) -> Self {
        Expression::String(v.to_string())
    }
}

impl From<String> for Expression {
    #[inline]
    fn from(v: String) -> Self {
        Expression::String(v)
    }
}

impl From<Meta> for Expression {
    #[inline]
    fn from(meta: Meta) -> Self {
        Expression::Meta(meta)
    }
}

impl From<Ct> for Expression {
    #[inline]
    fn from(ct: Ct) -> Self {
        Expression::Ct(ct)
    }
}

impl From<Payload> for Expression {
    #[inline]
    fn from(payload: Payload) -> Self {
        Expression::Payload(payload)
    }
}

impl From<Prefix> for Expression {
    #[inline]
    fn from(prefix: Prefix) -> Self {
        Expression::Prefix(prefix)
    }
}

impl From<Verdict> for Expression {
    #[inline]
    fn from(value: Verdict) -> Self {
        Expression::Verdict(value)
    }
}

impl From<&IpAddr> for Expression {
    fn from(value: &IpAddr) -> Self {
        Expression::String(value.to_string())
    }
}

impl From<&Ipv6Addr> for Expression {
    fn from(address: &Ipv6Addr) -> Self {
        Expression::String(address.to_string())
    }
}

impl From<&Ipv4Addr> for Expression {
    fn from(address: &Ipv4Addr) -> Self {
        Expression::String(address.to_string())
    }
}

#[cfg(feature = "config-ext")]
impl From<&IpList> for Expression {
    fn from(value: &IpList) -> Self {
        if value.len() == 1 {
            return Expression::from(value.first().unwrap());
        }

        Expression::set(value.iter().map(Expression::from))
    }
}

#[cfg(feature = "config-ext")]
impl From<&IpEntry> for Expression {
    fn from(value: &IpEntry) -> Self {
        match value {
            IpEntry::Cidr(cidr) => Expression::from(Prefix::from(cidr)),
            IpEntry::Range(beg, end) => Expression::Range(Box::new((beg.into(), end.into()))),
        }
    }
}

#[cfg(feature = "config-ext")]
impl From<&IcmpType> for Expression {
    fn from(value: &IcmpType) -> Self {
        match value {
            IcmpType::Numeric(id) => Expression::from(*id),
            IcmpType::Named(name) => Expression::from(*name),
        }
    }
}

#[cfg(feature = "config-ext")]
impl From<&IcmpCode> for Expression {
    fn from(value: &IcmpCode) -> Self {
        match value {
            IcmpCode::Numeric(id) => Expression::from(*id),
            IcmpCode::Named(name) => Expression::from(*name),
        }
    }
}

#[cfg(feature = "config-ext")]
impl From<&Icmpv6Type> for Expression {
    fn from(value: &Icmpv6Type) -> Self {
        match value {
            Icmpv6Type::Numeric(id) => Expression::from(*id),
            Icmpv6Type::Named(name) => Expression::from(*name),
        }
    }
}

#[cfg(feature = "config-ext")]
impl From<&Icmpv6Code> for Expression {
    fn from(value: &Icmpv6Code) -> Self {
        match value {
            Icmpv6Code::Numeric(id) => Expression::from(*id),
            Icmpv6Code::Named(name) => Expression::from(*name),
        }
    }
}

#[cfg(feature = "config-ext")]
impl From<&PortEntry> for Expression {
    fn from(value: &PortEntry) -> Self {
        match value {
            PortEntry::Port(port) => Expression::from(*port),
            PortEntry::Range(beg, end) => {
                Expression::Range(Box::new(((*beg).into(), (*end).into())))
            }
        }
    }
}

#[cfg(feature = "config-ext")]
impl From<&PortList> for Expression {
    fn from(value: &PortList) -> Self {
        if value.len() == 1 {
            return Expression::from(value.first().unwrap());
        }

        Expression::set(value.iter().map(Expression::from))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Meta {
    key: String,
}

impl Meta {
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Map {
    key: Expression,
    data: Expression,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ct {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    family: Option<IpFamily>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dir: Option<CtDirection>,
}

impl Ct {
    pub fn new(key: impl Into<String>, family: impl Into<Option<IpFamily>>) -> Self {
        Self {
            key: key.into(),
            family: family.into(),
            dir: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CtDirection {
    Original,
    Reply,
}
serde_plain::derive_display_from_serialize!(CtDirection);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IpFamily {
    Ip,
    Ip6,
}

#[cfg(feature = "config-ext")]
impl From<Family> for IpFamily {
    fn from(value: Family) -> Self {
        match value {
            Family::V4 => IpFamily::Ip,
            Family::V6 => IpFamily::Ip6,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Payload {
    Raw(PayloadRaw),
    Field(PayloadField),
}

impl Payload {
    pub fn field(protocol: impl Into<String>, field: impl Into<String>) -> Self {
        Self::Field(PayloadField {
            protocol: protocol.into(),
            field: field.into(),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum PayloadBase {
    #[serde(rename = "ll")]
    Link,
    #[serde(rename = "nh")]
    Network,
    #[serde(rename = "th")]
    Transport,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PayloadRaw {
    base: PayloadBase,
    offset: i64,
    len: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PayloadField {
    protocol: String,
    field: String,
}

impl PayloadField {
    pub fn protocol_for_ip_family(family: IpFamily) -> String {
        match family {
            IpFamily::Ip => "ip".to_string(),
            IpFamily::Ip6 => "ip6".to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Prefix {
    addr: Box<Expression>,
    len: u8,
}

impl Prefix {
    pub fn new(addr: impl Into<Expression>, len: u8) -> Self {
        Self {
            addr: Box::new(addr.into()),
            len,
        }
    }
}

#[cfg(feature = "config-ext")]
impl From<&Cidr> for Prefix {
    fn from(value: &Cidr) -> Self {
        match value {
            Cidr::Ipv4(cidr) => Self::new(cidr.address(), cidr.mask()),
            Cidr::Ipv6(cidr) => Self::new(cidr.address(), cidr.mask()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Element {
    #[serde(flatten)]
    config: ElemConfig,
    val: Expression,
}
