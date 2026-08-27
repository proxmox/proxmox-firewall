//! Rendering of a transport protocol match into the statements that select it, which are
//! `meta l4proto` for the protocol, the transport-header ports, and the ICMP type and code.
//! The statements carry no IP family test of their own, so they work unchanged in the inet
//! and bridge families. An ICMP match still only applies to its own IP family, which is left
//! to the caller.

#[cfg(feature = "config-ext")]
use proxmox_ve_config::firewall::types::rule_match::{Ports, Protocol};

use crate::expression::{Meta, Payload};
use crate::statement::Match;
use crate::{Expression, Statement};

/// Selects a protocol by name or number.
pub fn l4proto(protocol: impl Into<Expression>) -> Statement {
    Match::new_eq(Meta::new("l4proto"), protocol.into()).into()
}

/// Selects the transport-header source and destination ports that are given.
pub fn ports(sport: Option<Expression>, dport: Option<Expression>) -> Vec<Statement> {
    let mut statements = Vec::new();
    if let Some(sport) = sport {
        statements.push(Match::new_eq(Payload::field("th", "sport"), sport).into());
    }
    if let Some(dport) = dport {
        statements.push(Match::new_eq(Payload::field("th", "dport"), dport).into());
    }
    statements
}

/// Selects an ICMP flavour by type and code. Matching either already implies the protocol, so
/// only a bare match needs the explicit `l4proto` test.
pub fn icmp(protocol: &str, ty: Option<Expression>, code: Option<Expression>) -> Vec<Statement> {
    if ty.is_none() && code.is_none() {
        return vec![l4proto(protocol)];
    }
    let mut statements = Vec::new();
    if let Some(ty) = ty {
        statements.push(Match::new_eq(Payload::field(protocol, "type"), ty).into());
    }
    if let Some(code) = code {
        statements.push(Match::new_eq(Payload::field(protocol, "code"), code).into());
    }
    statements
}

/// The statements selecting `protocol`, in evaluation order.
#[cfg(feature = "config-ext")]
pub fn matches(protocol: &Protocol) -> Vec<Statement> {
    match protocol {
        Protocol::Tcp(tcp) => with_ports("tcp", tcp.ports()),
        Protocol::Udp(udp) => with_ports("udp", udp.ports()),
        Protocol::Sctp(sctp) => with_ports("sctp", sctp.ports()),
        Protocol::Dccp(config) => with_ports("dccp", config),
        Protocol::UdpLite(config) => with_ports("udplite", config),
        Protocol::Icmp(config) => icmp(
            "icmp",
            config.ty().map(Expression::from),
            config.code().map(Expression::from),
        ),
        Protocol::Icmpv6(config) => icmp(
            "icmpv6",
            config.ty().map(Expression::from),
            config.code().map(Expression::from),
        ),
        Protocol::Named(name) => vec![l4proto(name.as_str())],
        Protocol::Numeric(id) => vec![l4proto(*id)],
    }
}

#[cfg(feature = "config-ext")]
fn with_ports(protocol: &str, config: &Ports) -> Vec<Statement> {
    let mut statements = vec![l4proto(protocol)];
    statements.extend(ports(
        config.sport().map(Expression::from),
        config.dport().map(Expression::from),
    ));
    statements
}
