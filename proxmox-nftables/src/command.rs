use std::ops::{Deref, DerefMut};

use crate::helper::Null;
use crate::types::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Commands {
    nftables: Vec<Command>,
}

impl Commands {
    pub fn new(commands: Vec<Command>) -> Self {
        Self { nftables: commands }
    }
}

impl Deref for Commands {
    type Target = Vec<Command>;

    fn deref(&self) -> &Self::Target {
        &self.nftables
    }
}

impl DerefMut for Commands {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.nftables
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Command {
    Add(Add),
    Create(Add),
    Delete(Delete),
    Flush(Flush),
    List(List),
    // Insert(super::Rule),
    // Rename(RenameChain),
    // Replace(super::Rule),
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum List {
    Chains(Null),
    Sets(Null),
}

impl List {
    #[inline]
    pub fn chains() -> Command {
        Command::List(List::Chains(Null))
    }

    #[inline]
    pub fn sets() -> Command {
        Command::List(List::Sets(Null))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Add {
    Table(AddTable),
    Chain(AddChain),
    Rule(AddRule),
    Set(AddSet),
    Map(AddMap),
    Limit(AddLimit),
    Element(AddElement),
    #[serde(rename = "ct helper")]
    CtHelper(AddCtHelper),
}

impl Add {
    #[inline]
    pub fn table(table: impl Into<AddTable>) -> Command {
        Command::Add(Add::Table(table.into()))
    }

    #[inline]
    pub fn chain(chain: impl Into<AddChain>) -> Command {
        Command::Add(Add::Chain(chain.into()))
    }

    #[inline]
    pub fn rule(rule: impl Into<AddRule>) -> Command {
        Command::Add(Add::Rule(rule.into()))
    }

    #[inline]
    pub fn set(set: impl Into<AddSet>) -> Command {
        Command::Add(Add::Set(set.into()))
    }

    #[inline]
    pub fn map(map: impl Into<AddMap>) -> Command {
        Command::Add(Add::Map(map.into()))
    }

    #[inline]
    pub fn limit(limit: impl Into<AddLimit>) -> Command {
        Command::Add(Add::Limit(limit.into()))
    }

    #[inline]
    pub fn element(element: impl Into<AddElement>) -> Command {
        Command::Add(Add::Element(element.into()))
    }

    #[inline]
    pub fn ct_helper(ct_helper: impl Into<AddCtHelper>) -> Command {
        Command::Add(Add::CtHelper(ct_helper.into()))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Flush {
    Table(TableName),
    Chain(ChainName),
    Set(SetName),
    Map(SetName),
    Ruleset(Null),
}

impl Flush {
    #[inline]
    pub fn table(table: impl Into<TableName>) -> Command {
        Command::Flush(Flush::Table(table.into()))
    }

    #[inline]
    pub fn chain(chain: impl Into<ChainName>) -> Command {
        Command::Flush(Flush::Chain(chain.into()))
    }

    #[inline]
    pub fn set(set: impl Into<SetName>) -> Command {
        Command::Flush(Flush::Set(set.into()))
    }

    #[inline]
    pub fn map(map: impl Into<SetName>) -> Command {
        Command::Flush(Flush::Map(map.into()))
    }

    #[inline]
    pub fn ruleset() -> Command {
        Command::Flush(Flush::Ruleset(Null))
    }
}

impl From<TableName> for Flush {
    #[inline]
    fn from(value: TableName) -> Self {
        Flush::Table(value)
    }
}

impl From<ChainName> for Flush {
    #[inline]
    fn from(value: ChainName) -> Self {
        Flush::Chain(value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Delete {
    Table(TableName),
    Chain(ChainName),
    Set(SetName),
}

impl Delete {
    #[inline]
    pub fn table(table: impl Into<TableName>) -> Command {
        Command::Delete(Delete::Table(table.into()))
    }

    #[inline]
    pub fn chain(chain: impl Into<ChainName>) -> Command {
        Command::Delete(Delete::Chain(chain.into()))
    }

    #[inline]
    pub fn set(set: impl Into<SetName>) -> Command {
        Command::Delete(Delete::Set(set.into()))
    }
}

impl From<TableName> for Delete {
    #[inline]
    fn from(value: TableName) -> Self {
        Delete::Table(value)
    }
}

impl From<ChainName> for Delete {
    #[inline]
    fn from(value: ChainName) -> Self {
        Delete::Chain(value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListOutput {
    Metainfo(serde_json::Value),
    // Table(super::AddTable),
    Chain(ListChain),
    // Rule(super::Rule),
    Set(ListSet),
    // Map(super::Map),
    // Element(super::SetElement),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommandOutput {
    pub nftables: Vec<ListOutput>,
}

impl Deref for CommandOutput {
    type Target = Vec<ListOutput>;

    fn deref(&self) -> &Self::Target {
        &self.nftables
    }
}
