use std::collections::{BTreeMap, HashMap};
use std::io;

use anyhow::{bail, format_err, Error};
use serde::de::IntoDeserializer;

use crate::firewall::parse::{parse_named_section_tail, split_key_value, SomeString};
use crate::firewall::types::ipset::{IpsetName, IpsetScope};
use crate::firewall::types::{Alias, Group, Ipset, Rule};

#[derive(Debug, Default)]
pub struct Config<O>
where
    O: Default + std::fmt::Debug + serde::de::DeserializeOwned,
{
    pub(crate) options: O,
    pub(crate) rules: Vec<Rule>,
    pub(crate) aliases: BTreeMap<String, Alias>,
    pub(crate) ipsets: BTreeMap<String, Ipset>,
    pub(crate) groups: BTreeMap<String, Group>,
}

enum Sec {
    None,
    Options,
    Aliases,
    Rules,
    Ipset(String, Ipset),
    Group(String, Group),
}

#[derive(Default)]
pub struct ParserConfig {
    /// Network interfaces must be of the form `netX`.
    pub guest_iface_names: bool,
    pub ipset_scope: Option<IpsetScope>,
}

impl<O> Config<O>
where
    O: Default + std::fmt::Debug + serde::de::DeserializeOwned,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse<R: io::BufRead>(input: R, parser_cfg: &ParserConfig) -> Result<Self, Error> {
        let mut section = Sec::None;

        let mut this = Self::new();
        let mut options = HashMap::new();

        for line in input.lines() {
            let line = line?;
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            log::trace!("parsing config line {line}");

            if line.eq_ignore_ascii_case("[OPTIONS]") {
                this.set_section(&mut section, Sec::Options)?;
            } else if line.eq_ignore_ascii_case("[ALIASES]") {
                this.set_section(&mut section, Sec::Aliases)?;
            } else if line.eq_ignore_ascii_case("[RULES]") {
                this.set_section(&mut section, Sec::Rules)?;
            } else if let Some(line) = line.strip_prefix("[IPSET") {
                let (name, comment) = parse_named_section_tail("ipset", line)?;

                let scope = parser_cfg.ipset_scope.ok_or_else(|| {
                    format_err!("IPSET in config, but no scope set in parser config")
                })?;

                let ipset_name = IpsetName::new(scope, name.to_string());
                let mut ipset = Ipset::new(ipset_name);
                ipset.comment = comment.map(str::to_owned);

                this.set_section(&mut section, Sec::Ipset(name.to_string(), ipset))?;
            } else if let Some(line) = line.strip_prefix("[group") {
                let (name, comment) = parse_named_section_tail("group", line)?;
                let mut group = Group::new();

                group.set_comment(comment.map(str::to_owned));

                this.set_section(&mut section, Sec::Group(name.to_owned(), group))?;
            } else if line.starts_with('[') {
                bail!("invalid section {line:?}");
            } else {
                match &mut section {
                    Sec::None => bail!("config line with no section: {line:?}"),
                    Sec::Options => Self::parse_option(line, &mut options)?,
                    Sec::Aliases => this.parse_alias(line)?,
                    Sec::Rules => this.parse_rule(line, parser_cfg)?,
                    Sec::Ipset(_name, ipset) => ipset.parse_entry(line)?,
                    Sec::Group(_name, group) => group.parse_entry(line)?,
                }
            }
        }
        this.set_section(&mut section, Sec::None)?;

        this.options = O::deserialize(IntoDeserializer::<
            '_,
            crate::firewall::parse::SerdeStringError,
        >::into_deserializer(options))?;

        Ok(this)
    }

    fn parse_option(line: &str, options: &mut HashMap<String, SomeString>) -> Result<(), Error> {
        let (key, value) = split_key_value(line)
            .ok_or_else(|| format_err!("expected colon separated key and value, found {line:?}"))?;

        if options.insert(key.to_string(), value.into()).is_some() {
            bail!("duplicate option {key:?}");
        }

        Ok(())
    }

    fn parse_alias(&mut self, line: &str) -> Result<(), Error> {
        let alias: Alias = line.parse()?;

        if self
            .aliases
            .insert(alias.name().to_string(), alias)
            .is_some()
        {
            bail!("duplicate alias: {line}");
        }

        Ok(())
    }

    fn parse_rule(&mut self, line: &str, parser_cfg: &ParserConfig) -> Result<(), Error> {
        let rule: Rule = line.parse()?;

        if parser_cfg.guest_iface_names {
            if let Some(iface) = rule.iface() {
                let _ = iface
                    .strip_prefix("net")
                    .ok_or_else(|| {
                        format_err!("interface name must be of the form \"net<number>\"")
                    })?
                    .parse::<u16>()
                    .map_err(|_| {
                        format_err!("interface name must be of the form \"net<number>\"")
                    })?;
            }
        }

        self.rules.push(rule);
        Ok(())
    }

    fn set_section(&mut self, sec: &mut Sec, to: Sec) -> Result<(), Error> {
        let prev = std::mem::replace(sec, to);

        match prev {
            Sec::Ipset(name, ipset) => {
                if self.ipsets.insert(name.clone(), ipset).is_some() {
                    bail!("duplicate ipset: {name:?}");
                }
            }
            Sec::Group(name, group) => {
                if self.groups.insert(name.clone(), group).is_some() {
                    bail!("duplicate group: {name:?}");
                }
            }
            _ => (),
        }

        Ok(())
    }

    pub fn ipsets(&self) -> &BTreeMap<String, Ipset> {
        &self.ipsets
    }

    pub fn alias(&self, name: &str) -> Option<&Alias> {
        self.aliases.get(name)
    }
}
