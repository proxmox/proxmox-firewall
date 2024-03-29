use anyhow::{bail, Error};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::firewall::types::address::Family;
use crate::firewall::types::rule_match::{Ports, Protocol, Tcp, Udp};

#[derive(Clone, Debug, Deserialize)]
pub struct CtHelperMacroJson {
    pub v4: Option<bool>,
    pub v6: Option<bool>,
    pub name: String,
    pub tcp: Option<u16>,
    pub udp: Option<u16>,
}

impl TryFrom<CtHelperMacroJson> for CtHelperMacro {
    type Error = Error;

    fn try_from(value: CtHelperMacroJson) -> Result<Self, Self::Error> {
        if value.tcp.is_none() && value.udp.is_none() {
            bail!("Neither TCP nor UDP port set in CT helper!");
        }

        let family = match (value.v4, value.v6) {
            (Some(true), Some(true)) => None,
            (Some(true), _) => Some(Family::V4),
            (_, Some(true)) => Some(Family::V6),
            _ => bail!("Neither v4 nor v6 set in CT Helper Macro!"),
        };

        let mut ct_helper = CtHelperMacro {
            family,
            name: value.name,
            tcp: None,
            udp: None,
        };

        if let Some(dport) = value.tcp {
            let ports = Ports::from_u16(None, dport);
            ct_helper.tcp = Some(Tcp::new(ports).into());
        }

        if let Some(dport) = value.udp {
            let ports = Ports::from_u16(None, dport);
            ct_helper.udp = Some(Udp::new(ports).into());
        }

        Ok(ct_helper)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "CtHelperMacroJson")]
pub struct CtHelperMacro {
    family: Option<Family>,
    name: String,
    tcp: Option<Protocol>,
    udp: Option<Protocol>,
}

impl CtHelperMacro {
    fn helper_name(&self, protocol: &str) -> String {
        format!("helper-{}-{protocol}", self.name)
    }

    pub fn tcp_helper_name(&self) -> String {
        self.helper_name("tcp")
    }

    pub fn udp_helper_name(&self) -> String {
        self.helper_name("udp")
    }

    pub fn family(&self) -> Option<Family> {
        self.family
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn tcp(&self) -> Option<&Protocol> {
        self.tcp.as_ref()
    }

    pub fn udp(&self) -> Option<&Protocol> {
        self.udp.as_ref()
    }
}

fn hashmap() -> &'static HashMap<String, CtHelperMacro> {
    const MACROS: &str = include_str!("../../resources/ct_helper.json");
    static HASHMAP: OnceLock<HashMap<String, CtHelperMacro>> = OnceLock::new();

    HASHMAP.get_or_init(|| {
        let macro_data: Vec<CtHelperMacro> = match serde_json::from_str(MACROS) {
            Ok(data) => data,
            Err(err) => {
                log::error!("could not load data for ct helpers: {err}");
                Vec::new()
            }
        };

        macro_data
            .into_iter()
            .map(|elem| (elem.name.clone(), elem))
            .collect()
    })
}

pub fn get_cthelper(name: &str) -> Option<&'static CtHelperMacro> {
    hashmap().get(name)
}
