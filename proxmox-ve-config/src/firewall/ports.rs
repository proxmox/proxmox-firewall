use anyhow::{format_err, Error};
use std::sync::OnceLock;

#[derive(Default)]
struct NamedPorts {
    ports: std::collections::HashMap<String, u16>,
}

impl NamedPorts {
    fn new() -> Self {
        use std::io::BufRead;

        log::trace!("loading /etc/services");

        let mut this = Self::default();

        let file = match std::fs::File::open("/etc/services") {
            Ok(file) => file,
            Err(_) => return this,
        };

        for line in std::io::BufReader::new(file).lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => break,
            };

            let line = line.trim_start();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let mut parts = line.split_ascii_whitespace();

            let name = match parts.next() {
                None => continue,
                Some(name) => name.to_string(),
            };

            let proto: u16 = match parts.next() {
                None => continue,
                Some(proto) => match proto.split('/').next() {
                    None => continue,
                    Some(num) => match num.parse() {
                        Ok(num) => num,
                        Err(_) => continue,
                    },
                },
            };

            this.ports.insert(name, proto);
            for alias in parts {
                if alias.starts_with('#') {
                    break;
                }
                this.ports.insert(alias.to_string(), proto);
            }
        }

        this
    }

    fn find(&self, name: &str) -> Option<u16> {
        self.ports.get(name).copied()
    }
}

fn named_ports() -> &'static NamedPorts {
    static NAMED_PORTS: OnceLock<NamedPorts> = OnceLock::new();

    NAMED_PORTS.get_or_init(NamedPorts::new)
}

/// Parse a named port with the help of `/etc/services`.
pub fn parse_named_port(name: &str) -> Result<u16, Error> {
    named_ports()
        .find(name)
        .ok_or_else(|| format_err!("unknown port name {name:?}"))
}
