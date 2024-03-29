use std::collections::HashMap;

use serde::Deserialize;
use std::sync::OnceLock;

use crate::firewall::types::rule_match::Protocol;

use super::types::rule_match::RuleOptions;

#[derive(Clone, Debug, Default, Deserialize)]
struct FwMacroData {
    #[serde(rename = "desc")]
    pub description: &'static str,
    pub code: Vec<RuleOptions>,
}

#[derive(Clone, Debug, Default)]
pub struct FwMacro {
    pub _description: &'static str,
    pub code: Vec<Protocol>,
}

fn macros() -> &'static HashMap<String, FwMacro> {
    const MACROS: &str = include_str!("../../resources/macros.json");
    static HASHMAP: OnceLock<HashMap<String, FwMacro>> = OnceLock::new();

    HASHMAP.get_or_init(|| {
        let macro_data: HashMap<String, FwMacroData> = match serde_json::from_str(MACROS) {
            Ok(m) => m,
            Err(err) => {
                log::error!("could not load data for macros: {err}");
                HashMap::new()
            }
        };

        let mut macros = HashMap::new();

        'outer: for (name, data) in macro_data {
            let mut code = Vec::new();

            for c in data.code {
                match Protocol::from_options(&c) {
                    Ok(Some(p)) => code.push(p),
                    Ok(None) => {
                        continue 'outer;
                    }
                    Err(err) => {
                        log::error!("could not parse data for macro {name}: {err}");
                        continue 'outer;
                    }
                }
            }

            macros.insert(
                name,
                FwMacro {
                    _description: data.description,
                    code,
                },
            );
        }

        macros
    })
}

pub fn get_macro(name: &str) -> Option<&'static FwMacro> {
    macros().get(name)
}
