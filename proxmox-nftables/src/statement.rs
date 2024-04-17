use anyhow::{bail, Error};
use serde::{Deserialize, Serialize};

#[cfg(feature = "config-ext")]
use proxmox_ve_config::firewall::types::log::LogLevel as ConfigLogLevel;
#[cfg(feature = "config-ext")]
use proxmox_ve_config::firewall::types::log::LogRateLimit;
#[cfg(feature = "config-ext")]
use proxmox_ve_config::firewall::types::rule::Verdict as ConfigVerdict;
#[cfg(feature = "config-ext")]
use proxmox_ve_config::guest::types::Vmid;

use crate::expression::Meta;
use crate::helper::{NfVec, Null};
use crate::types::{RateTimescale, RateUnit, Verdict};
use crate::Expression;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Statement {
    Match(Match),
    Mangle(Mangle),
    Limit(Limit),
    Notrack(Null),
    Reject(Reject),
    Set(Set),
    Log(Log),
    #[serde(rename = "ct helper")]
    CtHelper(String),
    Vmap(Vmap),
    Comment(String),

    #[serde(untagged)]
    Verdict(Verdict),
}

impl Statement {
    pub const fn make_accept() -> Self {
        Statement::Verdict(Verdict::Accept(Null))
    }

    pub const fn make_drop() -> Self {
        Statement::Verdict(Verdict::Drop(Null))
    }

    pub const fn make_return() -> Self {
        Statement::Verdict(Verdict::Return(Null))
    }

    pub const fn make_continue() -> Self {
        Statement::Verdict(Verdict::Continue(Null))
    }

    pub fn jump(target: impl Into<String>) -> Self {
        Statement::Verdict(Verdict::Jump {
            target: target.into(),
        })
    }

    pub fn goto(target: impl Into<String>) -> Self {
        Statement::Verdict(Verdict::Goto {
            target: target.into(),
        })
    }
}

impl From<Match> for Statement {
    #[inline]
    fn from(m: Match) -> Statement {
        Statement::Match(m)
    }
}

impl From<Mangle> for Statement {
    #[inline]
    fn from(m: Mangle) -> Statement {
        Statement::Mangle(m)
    }
}

impl From<Reject> for Statement {
    #[inline]
    fn from(m: Reject) -> Statement {
        Statement::Reject(m)
    }
}

impl From<Set> for Statement {
    #[inline]
    fn from(m: Set) -> Statement {
        Statement::Set(m)
    }
}

impl From<Vmap> for Statement {
    #[inline]
    fn from(m: Vmap) -> Statement {
        Statement::Vmap(m)
    }
}

impl From<Log> for Statement {
    #[inline]
    fn from(log: Log) -> Statement {
        Statement::Log(log)
    }
}

impl<T: Into<Limit>> From<T> for Statement {
    #[inline]
    fn from(limit: T) -> Statement {
        Statement::Limit(limit.into())
    }
}

#[cfg(feature = "config-ext")]
impl From<ConfigVerdict> for Statement {
    fn from(value: ConfigVerdict) -> Self {
        match value {
            ConfigVerdict::Accept => Statement::make_accept(),
            ConfigVerdict::Reject => Statement::make_drop(),
            ConfigVerdict::Drop => Statement::make_drop(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RejectType {
    #[serde(rename = "tcp reset")]
    TcpRst,
    IcmpX,
    Icmp,
    IcmpV6,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Reject {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    ty: Option<RejectType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expr: Option<Expression>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Log {
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    snaplen: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    queue_threshold: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<LogLevel>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    flags: NfVec<LogFlag>,
}

impl Log {
    #[cfg(feature = "config-ext")]
    pub fn generate_prefix(
        vmid: impl Into<Option<Vmid>>,
        log_level: LogLevel,
        chain_name: &str,
        verdict: ConfigVerdict,
    ) -> String {
        format!(
            ":{}:{}:{}: {}: ",
            vmid.into().unwrap_or(Vmid::new(0)),
            log_level.nflog_level(),
            chain_name,
            verdict,
        )
    }

    pub fn new_nflog(prefix: String, group: i64) -> Self {
        Self {
            prefix: Some(prefix),
            group: Some(group),
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Emerg,
    Alert,
    Crit,
    Err,
    Warn,
    Notice,
    Info,
    Debug,
    Audit,
}

#[cfg(feature = "config-ext")]
impl TryFrom<ConfigLogLevel> for LogLevel {
    type Error = Error;

    fn try_from(value: ConfigLogLevel) -> Result<Self, Self::Error> {
        match value {
            ConfigLogLevel::Emergency => Ok(LogLevel::Emerg),
            ConfigLogLevel::Alert => Ok(LogLevel::Alert),
            ConfigLogLevel::Critical => Ok(LogLevel::Crit),
            ConfigLogLevel::Error => Ok(LogLevel::Err),
            ConfigLogLevel::Warning => Ok(LogLevel::Warn),
            ConfigLogLevel::Notice => Ok(LogLevel::Notice),
            ConfigLogLevel::Info => Ok(LogLevel::Info),
            ConfigLogLevel::Debug => Ok(LogLevel::Debug),
            _ => bail!("cannot convert config log level to nftables"),
        }
    }
}

impl LogLevel {
    pub fn nflog_level(&self) -> u8 {
        match self {
            LogLevel::Emerg => 0,
            LogLevel::Alert => 1,
            LogLevel::Crit => 2,
            LogLevel::Err => 3,
            LogLevel::Warn => 4,
            LogLevel::Notice => 5,
            LogLevel::Info => 6,
            LogLevel::Debug => 7,
            LogLevel::Audit => 7,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFlag {
    #[serde(rename = "tcp sequence")]
    TcpSequence,
    #[serde(rename = "tcp options")]
    TcpOptions,
    #[serde(rename = "ip options")]
    IpOptions,

    Skuid,
    Ether,
    All,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Limit {
    Named(String),
    Anonymous(AnonymousLimit),
}

impl<T: Into<AnonymousLimit>> From<T> for Limit {
    fn from(value: T) -> Self {
        Limit::Anonymous(value.into())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Default)]
pub struct AnonymousLimit {
    pub rate: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_unit: Option<RateUnit>,

    pub per: RateTimescale,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst_unit: Option<RateUnit>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub inv: Option<bool>,
}

#[cfg(feature = "config-ext")]
impl From<LogRateLimit> for AnonymousLimit {
    fn from(config: LogRateLimit) -> Self {
        AnonymousLimit {
            rate: config.rate(),
            per: config.per().into(),
            rate_unit: None,
            burst: Some(config.burst()),
            burst_unit: None,
            inv: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Vmap {
    key: Expression,
    data: Expression,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Match {
    op: Operator,
    left: Expression,
    right: Expression,
}

impl Match {
    pub fn new(op: Operator, left: impl Into<Expression>, right: impl Into<Expression>) -> Self {
        Self {
            op,
            left: left.into(),
            right: right.into(),
        }
    }

    pub fn new_eq(left: impl Into<Expression>, right: impl Into<Expression>) -> Self {
        Self::new(Operator::Eq, left, right)
    }

    pub fn new_ne(left: impl Into<Expression>, right: impl Into<Expression>) -> Self {
        Self::new(Operator::Ne, left, right)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Operator {
    #[serde(rename = "&")]
    And,
    #[serde(rename = "|")]
    Or,
    #[serde(rename = "^")]
    Xor,
    #[serde(rename = "<<")]
    ShiftLeft,
    #[serde(rename = ">>")]
    ShiftRight,
    #[serde(rename = "==")]
    Eq,
    #[serde(rename = "!=")]
    Ne,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = "<=")]
    Le,
    #[serde(rename = ">=")]
    Ge,
    #[serde(rename = "in")]
    In,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Mangle {
    pub key: Expression,
    pub value: Expression,
}

impl Mangle {
    pub fn set_mark(value: impl Into<Expression>) -> Self {
        Self {
            key: Meta::new("mark").into(),
            value: value.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SetOperation {
    Add,
    Update,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Set {
    pub op: SetOperation,
    pub elem: Expression,
    pub set: String,
    pub stmt: Option<NfVec<Statement>>,
}
