use std::fmt::Display;
use std::ops::{Deref, DerefMut};

use crate::expression::IpFamily;
use crate::helper::{NfVec, Null};
use crate::{Expression, Statement};

use serde::{Deserialize, Serialize};

#[cfg(feature = "config-ext")]
use proxmox_ve_config::guest::types::Vmid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Handle(i32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TableFamily {
    Ip,
    Ip6,
    Inet,
    Arp,
    Bridge,
    Netdev,
}
serde_plain::derive_display_from_serialize!(TableFamily);

impl TableFamily {
    pub fn ip_families(&self) -> Vec<IpFamily> {
        match self {
            TableFamily::Ip => vec![IpFamily::Ip],
            TableFamily::Ip6 => vec![IpFamily::Ip6],
            _ => vec![IpFamily::Ip, IpFamily::Ip6],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElementType {
    Ifname,
    Ipv4Addr,
    Ipv6Addr,
}
serde_plain::derive_display_from_serialize!(ElementType);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    Filter,
    Nat,
    Route,
}
serde_plain::derive_display_from_serialize!(ChainType);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SetPolicy {
    Performance,
    Memory,
}
serde_plain::derive_display_from_serialize!(SetPolicy);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SetFlag {
    Constant,
    Interval,
    Timeout,
}
serde_plain::derive_display_from_serialize!(SetFlag);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputType {
    Verdict,
    Type(ElementType),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Hook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
}
serde_plain::derive_display_from_serialize!(Hook);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accept(Null),
    Drop(Null),
    Continue(Null),
    Return(Null),
    Goto { target: String },
    Jump { target: String },
}

impl Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = match self {
            Verdict::Accept(_) => "ACCEPT",
            Verdict::Drop(_) => "DROP",
            Verdict::Continue(_) => "CONTINUE",
            Verdict::Return(_) => "RETURN",
            Verdict::Jump { .. } => "JUMP",
            Verdict::Goto { .. } => "GOTO",
        };

        f.write_str(output)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainPolicy {
    Accept,
    Drop,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PriorityKeyword {
    Raw,
    Mangle,
    DstNat,
    Filter,
    Security,
    SrcNat,
    Out,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Priority {
    Keyword(PriorityKeyword),
    Number(i64),
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum RateUnit {
    Packets,
    Bytes,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
#[serde(rename_all = "lowercase")]
pub enum RateTimescale {
    #[default]
    Second,
    Minute,
    Hour,
    Day,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TableName {
    family: TableFamily,
    name: String,
}

impl TableName {
    pub fn new(family: TableFamily, name: impl Into<String>) -> Self {
        Self {
            family,
            name: name.into(),
        }
    }

    pub fn family(&self) -> &TableFamily {
        &self.family
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TablePart {
    family: TableFamily,
    table: String,
}

impl TablePart {
    pub fn new(family: TableFamily, name: impl Into<String>) -> Self {
        Self {
            family,
            table: name.into(),
        }
    }

    pub fn family(&self) -> &TableFamily {
        &self.family
    }

    pub fn table(&self) -> &str {
        &self.table
    }
}

impl From<TablePart> for TableName {
    fn from(t: TablePart) -> Self {
        Self {
            family: t.family,
            name: t.table,
        }
    }
}

impl From<TableName> for TablePart {
    fn from(t: TableName) -> Self {
        Self {
            family: t.family,
            table: t.name,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChainName {
    #[serde(flatten)]
    table: TablePart,
    name: String,
}

impl From<AddChain> for ChainName {
    fn from(value: AddChain) -> Self {
        Self {
            table: value.table,
            name: value.name,
        }
    }
}

impl From<ListChain> for ChainName {
    fn from(value: ListChain) -> Self {
        Self {
            table: value.table,
            name: value.name,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChainPart {
    #[serde(flatten)]
    table: TablePart,
    chain: String,
}

impl ChainPart {
    pub fn new(table: TablePart, chain: impl Into<String>) -> Self {
        Self {
            table,
            chain: chain.into(),
        }
    }

    pub fn table(&self) -> &TablePart {
        &self.table
    }

    pub fn name(&self) -> &str {
        &self.chain
    }
}

impl From<ChainName> for ChainPart {
    fn from(c: ChainName) -> Self {
        Self {
            table: c.table,
            chain: c.name,
        }
    }
}

impl From<ChainPart> for ChainName {
    fn from(c: ChainPart) -> Self {
        Self {
            table: c.table,
            name: c.chain,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddTable {
    family: TableFamily,
    name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<Handle>,
}

impl AddTable {
    pub fn new(family: TableFamily, name: impl Into<String>) -> Self {
        Self {
            family,
            name: name.into(),
            handle: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BaseChainConfig {
    #[serde(rename = "type")]
    ty: ChainType,
    hook: Hook,
    prio: Expression,
    policy: ChainPolicy,

    /// netdev family only
    #[serde(skip_serializing_if = "Option::is_none")]
    dev: Option<String>,
}

impl BaseChainConfig {
    pub fn new(
        ty: ChainType,
        hook: Hook,
        prio: impl Into<Expression>,
        policy: ChainPolicy,
    ) -> Self {
        Self {
            ty,
            hook,
            prio: prio.into(),
            policy,
            dev: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddChain {
    #[serde(flatten)]
    table: TablePart,
    name: String,

    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    config: Option<BaseChainConfig>,
}

impl AddChain {
    pub fn new(table: TablePart, name: impl Into<String>) -> Self {
        Self {
            table,
            name: name.into(),
            config: None,
        }
    }

    pub fn new_base_chain(
        table: TablePart,
        name: impl Into<String>,
        config: BaseChainConfig,
    ) -> Self {
        Self {
            table,
            name: name.into(),
            config: Some(config),
        }
    }
}

impl From<ChainPart> for AddChain {
    #[inline]
    fn from(part: ChainPart) -> Self {
        Self::new(part.table, part.chain)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddRule {
    #[serde(flatten)]
    chain: ChainPart,

    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<Handle>,

    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,

    expr: Vec<Statement>,
}

impl Deref for AddRule {
    type Target = Vec<Statement>;

    fn deref(&self) -> &Self::Target {
        &self.expr
    }
}

impl DerefMut for AddRule {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.expr
    }
}

impl AddRule {
    pub fn from_statement(chain: ChainPart, expression: impl Into<Statement>) -> Self {
        Self {
            chain,
            expr: vec![expression.into()],
            handle: None,
            index: None,
            comment: None,
        }
    }

    pub fn from_statements<I: IntoIterator<Item = Statement>>(
        chain: ChainPart,
        expression: I,
    ) -> Self {
        Self {
            chain,
            expr: expression.into_iter().collect(),
            handle: None,
            index: None,
            comment: None,
        }
    }

    pub fn new(chain: ChainPart) -> Self {
        Self {
            chain,
            expr: Vec::new(),
            handle: None,
            index: None,
            comment: None,
        }
    }

    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SetConfig {
    #[serde(flatten)]
    name: SetName,

    #[serde(rename = "type", default, skip_serializing_if = "Vec::is_empty")]
    ty: NfVec<ElementType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<SetPolicy>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    flags: Vec<SetFlag>,

    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    gc_interval: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<i64>,
}

impl SetConfig {
    pub fn new(name: impl Into<SetName>, ty: impl IntoIterator<Item = ElementType>) -> Self {
        Self {
            name: name.into(),
            ty: NfVec::from_iter(ty),
            flags: Vec::new(),
            policy: None,
            timeout: None,
            gc_interval: None,
            size: None,
        }
    }

    pub fn name(&self) -> &SetName {
        &self.name
    }

    pub fn with_flag(mut self, flag: SetFlag) -> Self {
        self.flags.push(flag);
        self
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AddMap {
    #[serde(flatten)]
    config: SetConfig,

    map: OutputType,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    elem: NfVec<MapElem>,
}

impl AddMap {
    pub fn new(config: SetConfig, output_type: OutputType) -> Self {
        Self {
            config,
            map: output_type,
            elem: NfVec::new(),
        }
    }
}

impl Deref for AddMap {
    type Target = Vec<MapElem>;

    fn deref(&self) -> &Self::Target {
        &self.elem
    }
}

impl DerefMut for AddMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.elem
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddSet {
    #[serde(flatten)]
    config: SetConfig,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    elem: NfVec<SetElem>,
}

impl From<SetConfig> for AddSet {
    fn from(value: SetConfig) -> Self {
        Self {
            config: value,
            elem: NfVec::new(),
        }
    }
}

impl Deref for AddSet {
    type Target = Vec<SetElem>;

    fn deref(&self) -> &Self::Target {
        &self.elem
    }
}

impl DerefMut for AddSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.elem
    }
}

impl AddSet {
    pub fn new(config: impl Into<SetConfig>, elements: impl IntoIterator<Item = SetElem>) -> Self {
        Self {
            config: config.into(),
            elem: NfVec::from_iter(elements),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetName {
    #[serde(flatten)]
    table: TablePart,
    name: String,
}

impl SetName {
    pub fn new(table: TablePart, name: impl Into<String>) -> Self {
        Self {
            table,
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetElem(Expression);

impl From<Expression> for SetElem {
    #[inline]
    fn from(value: Expression) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MapValue {
    Expression(Expression),
    Verdict(Verdict),
    // Concat
}

impl From<Verdict> for MapValue {
    #[inline]
    fn from(value: Verdict) -> Self {
        Self::Verdict(value)
    }
}

impl From<Expression> for MapValue {
    #[inline]
    fn from(value: Expression) -> Self {
        Self::Expression(value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MapElem((Expression, MapValue));

impl MapElem {
    pub fn new(key: Expression, value: impl Into<MapValue>) -> Self {
        Self((key, value.into()))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddSetElement {
    #[serde(flatten)]
    set: SetName,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    elem: Vec<SetElement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddMapElement {
    #[serde(flatten)]
    map: SetName,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    elem: Vec<MapElement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AddElement {
    Set(AddSetElement),
    Map(AddMapElement),
}

impl AddElement {
    pub fn map_from_expressions(
        map: SetName,
        elem: impl IntoIterator<Item = (Expression, MapValue)>,
    ) -> Self {
        Self::Map(AddMapElement {
            map,
            elem: Vec::from_iter(
                elem.into_iter()
                    .map(|(key, value)| MapElem::new(key, value).into()),
            ),
        })
    }

    pub fn set_from_expressions(set: SetName, elem: impl IntoIterator<Item = Expression>) -> Self {
        Self::Set(AddSetElement {
            set,
            elem: Vec::from_iter(elem.into_iter().map(SetElement::from)),
        })
    }
}

impl From<AddSetElement> for AddElement {
    fn from(value: AddSetElement) -> Self {
        AddElement::Set(value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ElemConfig {
    timeout: Option<i64>,
    expires: Option<i64>,
    comment: Option<String>,
}

impl ElemConfig {
    pub fn new(
        timeout: impl Into<Option<i64>>,
        expires: impl Into<Option<i64>>,
        comment: impl Into<Option<String>>,
    ) -> Self {
        Self {
            timeout: timeout.into(),
            expires: expires.into(),
            comment: comment.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetElemObject {
    #[serde(flatten)]
    config: ElemConfig,
    elem: SetElem,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MapElemObject {
    #[serde(flatten)]
    config: ElemConfig,
    elem: MapElem,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum MapElement {
    #[serde(rename = "elem")]
    Object(MapElemObject),
    #[serde(untagged)]
    Value(MapElem),
}

impl From<MapElem> for MapElement {
    fn from(value: MapElem) -> Self {
        Self::Value(value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SetElement {
    #[serde(rename = "elem")]
    Object(SetElemObject),
    #[serde(untagged)]
    Value(SetElem),
}

impl From<Expression> for SetElement {
    #[inline]
    fn from(value: Expression) -> Self {
        Self::Value(SetElem::from(value))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct AddLimit {
    #[serde(flatten)]
    table: TablePart,

    name: String,

    rate: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    unit: Option<RateUnit>,

    #[serde(skip_serializing_if = "Option::is_none")]
    per: Option<RateTimescale>,

    #[serde(skip_serializing_if = "Option::is_none")]
    burst: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    inv: Option<bool>,
}

impl AddLimit {
    pub fn new(table: TablePart, name: String, rate: i64) -> Self {
        Self {
            table,
            name,
            rate,
            unit: None,
            per: None,
            burst: None,
            inv: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum L3Protocol {
    Ip,
    Ip6,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CtHelperProtocol {
    TCP,
    UDP,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename = "ct helper")]
pub struct AddCtHelper {
    #[serde(flatten)]
    pub table: TablePart,
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub protocol: CtHelperProtocol,
    pub l3proto: Option<L3Protocol>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ListChain {
    #[serde(flatten)]
    table: TablePart,
    name: String,
    handle: i64,

    #[serde(flatten)]
    config: Option<BaseChainConfig>,
}

impl ListChain {
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ListSet {
    #[serde(flatten)]
    name: SetName,
}

impl ListSet {
    pub fn name(&self) -> &SetName {
        &self.name
    }
}
