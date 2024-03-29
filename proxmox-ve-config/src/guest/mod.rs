use core::ops::Deref;
use std::collections::HashMap;

use anyhow::{Context, Error};
use serde::Deserialize;

use proxmox_sys::nodename;
use types::Vmid;

pub mod types;
pub mod vm;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
pub enum GuestType {
    #[serde(rename = "qemu")]
    Vm,
    #[serde(rename = "lxc")]
    Ct,
}

impl GuestType {
    pub fn iface_prefix(self) -> &'static str {
        match self {
            GuestType::Vm => "tap",
            GuestType::Ct => "veth",
        }
    }

    fn config_folder(&self) -> &'static str {
        match self {
            GuestType::Vm => "qemu-server",
            GuestType::Ct => "lxc",
        }
    }
}

#[derive(Deserialize)]
pub struct GuestEntry {
    node: String,

    #[serde(rename = "type")]
    ty: GuestType,

    #[serde(rename = "version")]
    _version: usize,
}

impl GuestEntry {
    pub fn new(node: String, ty: GuestType) -> Self {
        Self {
            node,
            ty,
            _version: Default::default(),
        }
    }

    pub fn is_local(&self) -> bool {
        nodename() == self.node
    }

    pub fn ty(&self) -> &GuestType {
        &self.ty
    }
}

const VMLIST_CONFIG_PATH: &str = "/etc/pve/.vmlist";

#[derive(Deserialize)]
pub struct GuestMap {
    #[serde(rename = "version")]
    _version: usize,
    #[serde(rename = "ids", default)]
    guests: HashMap<Vmid, GuestEntry>,
}

impl From<HashMap<Vmid, GuestEntry>> for GuestMap {
    fn from(guests: HashMap<Vmid, GuestEntry>) -> Self {
        Self {
            guests,
            _version: Default::default(),
        }
    }
}

impl Deref for GuestMap {
    type Target = HashMap<Vmid, GuestEntry>;

    fn deref(&self) -> &Self::Target {
        &self.guests
    }
}

impl GuestMap {
    pub fn new() -> Result<Self, Error> {
        let data = std::fs::read(VMLIST_CONFIG_PATH)
            .with_context(|| format!("failed to read guest map from {VMLIST_CONFIG_PATH}"))?;

        serde_json::from_slice(&data).with_context(|| "failed to parse guest map".to_owned())
    }

    pub fn firewall_config_path(vmid: &Vmid) -> String {
        format!("/etc/pve/firewall/{}.fw", vmid)
    }

    /// returns the local configuration path for a given Vmid.
    ///
    /// The caller must ensure that the given Vmid exists and is local to the node
    pub fn config_path(vmid: &Vmid, entry: &GuestEntry) -> String {
        format!(
            "/etc/pve/local/{}/{}.conf",
            entry.ty().config_folder(),
            vmid
        )
    }
}
