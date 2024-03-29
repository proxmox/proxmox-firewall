use anyhow::Error;

use crate::firewall::types::Rule;

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Group {
    rules: Vec<Rule>,
    comment: Option<String>,
}

impl Group {
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            comment: None,
        }
    }

    pub fn rules(&self) -> &Vec<Rule> {
        &self.rules
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }

    pub(crate) fn parse_entry(&mut self, line: &str) -> Result<(), Error> {
        self.rules.push(line.parse()?);
        Ok(())
    }
}
