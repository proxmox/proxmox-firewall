use anyhow::{bail, Error};
use core::fmt::Display;
use std::io;
use std::str::FromStr;
use std::{collections::HashMap, net::Ipv6Addr};

use proxmox_schema::property_string::PropertyIterator;

use crate::firewall::parse::{match_digits, parse_bool};
use crate::firewall::types::address::{Ipv4Cidr, Ipv6Cidr};

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct MacAddress([u8; 6]);

static LOCAL_PART: [u8; 8] = [0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
static EUI64_MIDDLE_PART: [u8; 2] = [0xFF, 0xFE];

impl MacAddress {
    /// generates a link local IPv6-address according to RFC 4291 (Appendix A)
    pub fn eui64_link_local_address(&self) -> Ipv6Addr {
        let head = &self.0[..3];
        let tail = &self.0[3..];

        let mut eui64_address: Vec<u8> = LOCAL_PART
            .iter()
            .chain(head.iter())
            .chain(EUI64_MIDDLE_PART.iter())
            .chain(tail.iter())
            .copied()
            .collect();

        // we need to flip the 7th bit of the first eui64 byte
        eui64_address[8] ^= 0x02;

        Ipv6Addr::from(
            TryInto::<[u8; 16]>::try_into(eui64_address).expect("is an u8 array with 16 entries"),
        )
    }
}

impl FromStr for MacAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split = s.split(':');

        let parsed = split
            .into_iter()
            .map(|elem| u8::from_str_radix(elem, 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(Error::msg)?;

        if parsed.len() != 6 {
            bail!("Invalid amount of elements in MAC address!");
        }

        let address = &parsed.as_slice()[0..6];
        Ok(Self(address.try_into().unwrap()))
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:<02X}:{:<02X}:{:<02X}:{:<02X}:{:<02X}:{:<02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum NetworkDeviceModel {
    VirtIO,
    Veth,
    E1000,
    Vmxnet3,
    RTL8139,
}

impl FromStr for NetworkDeviceModel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "virtio" => Ok(NetworkDeviceModel::VirtIO),
            "e1000" => Ok(NetworkDeviceModel::E1000),
            "rtl8139" => Ok(NetworkDeviceModel::RTL8139),
            "vmxnet3" => Ok(NetworkDeviceModel::Vmxnet3),
            "veth" => Ok(NetworkDeviceModel::Veth),
            _ => bail!("Invalid network device model: {s}"),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct NetworkDevice {
    model: NetworkDeviceModel,
    mac_address: MacAddress,
    firewall: bool,
    ip: Option<Ipv4Cidr>,
    ip6: Option<Ipv6Cidr>,
}

impl NetworkDevice {
    pub fn model(&self) -> NetworkDeviceModel {
        self.model
    }

    pub fn mac_address(&self) -> &MacAddress {
        &self.mac_address
    }

    pub fn ip(&self) -> Option<&Ipv4Cidr> {
        self.ip.as_ref()
    }

    pub fn ip6(&self) -> Option<&Ipv6Cidr> {
        self.ip6.as_ref()
    }

    pub fn has_firewall(&self) -> bool {
        self.firewall
    }
}

impl FromStr for NetworkDevice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (mut ty, mut hwaddr, mut firewall, mut ip, mut ip6) = (None, None, true, None, None);

        for entry in PropertyIterator::new(s) {
            let (key, value) = entry.unwrap();

            if let Some(key) = key {
                match key {
                    "type" | "model" => {
                        ty = Some(NetworkDeviceModel::from_str(&value)?);
                    }
                    "hwaddr" | "macaddr" => {
                        hwaddr = Some(MacAddress::from_str(&value)?);
                    }
                    "firewall" => {
                        firewall = parse_bool(&value)?;
                    }
                    "ip" => {
                        if value == "dhcp" {
                            continue;
                        }

                        ip = Some(Ipv4Cidr::from_str(&value)?);
                    }
                    "ip6" => {
                        if value == "dhcp" || value == "auto" {
                            continue;
                        }

                        ip6 = Some(Ipv6Cidr::from_str(&value)?);
                    }
                    _ => {
                        if let Ok(model) = NetworkDeviceModel::from_str(key) {
                            ty = Some(model);
                            hwaddr = Some(MacAddress::from_str(&value)?);
                        }
                    }
                }
            }
        }

        if let (Some(ty), Some(hwaddr)) = (ty, hwaddr) {
            return Ok(NetworkDevice {
                model: ty,
                mac_address: hwaddr,
                firewall,
                ip,
                ip6,
            });
        }

        bail!("No valid network device detected in string {s}");
    }
}

#[derive(Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct NetworkConfig {
    network_devices: HashMap<i64, NetworkDevice>,
}

impl NetworkConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn index_from_net_key(key: &str) -> Result<i64, Error> {
        if let Some(digits) = key.strip_prefix("net") {
            if let Some((digits, rest)) = match_digits(digits) {
                let index: i64 = digits.parse()?;

                if (0..31).contains(&index) && rest.is_empty() {
                    return Ok(index);
                }
            }
        }

        bail!("No index found in net key string: {key}")
    }

    pub fn network_devices(&self) -> &HashMap<i64, NetworkDevice> {
        &self.network_devices
    }

    pub fn parse<R: io::BufRead>(input: R) -> Result<Self, Error> {
        let mut network_devices = HashMap::new();

        for line in input.lines() {
            let line = line?;
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with('[') {
                break;
            }

            if line.starts_with("net") {
                log::trace!("parsing net config line: {line}");

                if let Some((mut key, mut value)) = line.split_once(':') {
                    if key.is_empty() || value.is_empty() {
                        continue;
                    }

                    key = key.trim();
                    value = value.trim();

                    if let Ok(index) = Self::index_from_net_key(key) {
                        let network_device = NetworkDevice::from_str(value)?;

                        let exists = network_devices.insert(index, network_device);

                        if exists.is_some() {
                            bail!("Duplicated config key detected: {key}");
                        }
                    } else {
                        bail!("Encountered invalid net key in cfg: {key}");
                    }
                }
            }
        }

        Ok(Self { network_devices })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_address() {
        for input in [
            "aa:aa:aa:11:22:33",
            "AA:BB:FF:11:22:33",
            "bc:24:11:AA:bb:Ef",
        ] {
            let mac_address = input.parse::<MacAddress>().expect("valid mac address");

            assert_eq!(input.to_uppercase(), mac_address.to_string());
        }

        for input in [
            "aa:aa:aa:11:22:33:aa",
            "AA:BB:FF:11:22",
            "AA:BB:GG:11:22:33",
            "AABBGG112233",
            "",
        ] {
            input
                .parse::<MacAddress>()
                .expect_err("invalid mac address");
        }
    }

    #[test]
    fn test_eui64_link_local_address() {
        let mac_address: MacAddress = "BC:24:11:49:8D:75".parse().expect("valid MAC address");

        let link_local_address =
            Ipv6Addr::from_str("fe80::be24:11ff:fe49:8d75").expect("valid IPv6 address");

        assert_eq!(link_local_address, mac_address.eui64_link_local_address());
    }

    #[test]
    fn test_parse_network_device() {
        let mut network_device: NetworkDevice =
            "virtio=AA:AA:AA:17:19:81,bridge=public,firewall=1,queues=4"
                .parse()
                .expect("valid network configuration");

        assert_eq!(
            network_device,
            NetworkDevice {
                model: NetworkDeviceModel::VirtIO,
                mac_address: MacAddress([0xAA, 0xAA, 0xAA, 0x17, 0x19, 0x81]),
                firewall: true,
                ip: None,
                ip6: None,
            }
        );

        network_device = "model=virtio,macaddr=AA:AA:AA:17:19:81,bridge=public,firewall=1,queues=4"
            .parse()
            .expect("valid network configuration");

        assert_eq!(
            network_device,
            NetworkDevice {
                model: NetworkDeviceModel::VirtIO,
                mac_address: MacAddress([0xAA, 0xAA, 0xAA, 0x17, 0x19, 0x81]),
                firewall: true,
                ip: None,
                ip6: None,
            }
        );

        network_device =
            "name=eth0,bridge=public,firewall=0,hwaddr=AA:AA:AA:E2:3E:24,ip=dhcp,type=veth"
                .parse()
                .expect("valid network configuration");

        assert_eq!(
            network_device,
            NetworkDevice {
                model: NetworkDeviceModel::Veth,
                mac_address: MacAddress([0xAA, 0xAA, 0xAA, 0xE2, 0x3E, 0x24]),
                firewall: false,
                ip: None,
                ip6: None,
            }
        );

        "model=virtio"
            .parse::<NetworkDevice>()
            .expect_err("invalid network configuration");

        "bridge=public,firewall=0"
            .parse::<NetworkDevice>()
            .expect_err("invalid network configuration");

        "".parse::<NetworkDevice>()
            .expect_err("invalid network configuration");

        "name=eth0,bridge=public,firewall=0,hwaddr=AA:AA:AG:E2:3E:24,ip=dhcp,type=veth"
            .parse::<NetworkDevice>()
            .expect_err("invalid network configuration");
    }

    #[test]
    fn test_parse_network_confg() {
        let mut guest_config = "\
boot: order=scsi0;net0
cores: 4
cpu: host
memory: 8192
meta: creation-qemu=8.0.2,ctime=1700141675
name: hoan-sdn
net0: virtio=AA:BB:CC:F2:FE:75,bridge=public
numa: 0
ostype: l26
parent: uwu
scsi0: local-lvm:vm-999-disk-0,discard=on,iothread=1,size=32G
scsihw: virtio-scsi-single
smbios1: uuid=addb0cc6-0393-4269-a504-1eb46604cb8a
sockets: 1
vmgenid: 13bcbb05-3608-4d74-bf4f-d5d20c3538e8

[snapshot]
boot: order=scsi0;ide2;net0
cores: 4
cpu: x86-64-v2-AES
ide2: NFS-iso:iso/proxmox-ve_8.0-2.iso,media=cdrom,size=1166488K
memory: 8192
meta: creation-qemu=8.0.2,ctime=1700141675
name: test
net2: virtio=AA:AA:AA:F2:FE:75,bridge=public,firewall=1
numa: 0
ostype: l26
parent: pre-SDN
scsi0: local-lvm:vm-999-disk-0,discard=on,iothread=1,size=32G
scsihw: virtio-scsi-single
smbios1: uuid=addb0cc6-0393-4269-a504-1eb46604cb8a
snaptime: 1700143513
sockets: 1
vmgenid: 706fbe99-d28b-4047-a9cd-3677c859ca8a

[snapshott]
boot: order=scsi0;ide2;net0
cores: 4
cpu: host
ide2: NFS-iso:iso/proxmox-ve_8.0-2.iso,media=cdrom,size=1166488K
memory: 8192
meta: creation-qemu=8.0.2,ctime=1700141675
name: hoan-sdn
net0: virtio=AA:AA:FF:F2:FE:75,bridge=public,firewall=0
numa: 0
ostype: l26
parent: SDN
scsi0: local-lvm:vm-999-disk-0,discard=on,iothread=1,size=32G
scsihw: virtio-scsi-single
smbios1: uuid=addb0cc6-0393-4269-a504-1eb46604cb8a
snaptime: 1700158473
sockets: 1
vmgenid: 706fbe99-d28b-4047-a9cd-3677c859ca8a"
            .as_bytes();

        let mut network_config: NetworkConfig =
            NetworkConfig::parse(guest_config).expect("valid network configuration");

        assert_eq!(network_config.network_devices().len(), 1);

        assert_eq!(
            network_config.network_devices()[&0],
            NetworkDevice {
                model: NetworkDeviceModel::VirtIO,
                mac_address: MacAddress([0xAA, 0xBB, 0xCC, 0xF2, 0xFE, 0x75]),
                firewall: true,
                ip: None,
                ip6: None,
            }
        );

        guest_config = "\
arch: amd64
cores: 1
features: nesting=1
hostname: dnsct
memory: 512
net0: name=eth0,bridge=data,firewall=1,hwaddr=BC:24:11:47:83:11,ip=dhcp,type=veth
net2:   name=eth0,bridge=data,firewall=0,hwaddr=BC:24:11:47:83:12,ip=123.123.123.123/24,type=veth  
net5: name=eth0,bridge=data,firewall=1,hwaddr=BC:24:11:47:83:13,ip6=fd80::1/64,type=veth
ostype: alpine
rootfs: local-lvm:vm-10001-disk-0,size=1G
swap: 512
unprivileged: 1"
            .as_bytes();

        network_config = NetworkConfig::parse(guest_config).expect("valid network configuration");

        assert_eq!(network_config.network_devices().len(), 3);

        assert_eq!(
            network_config.network_devices()[&0],
            NetworkDevice {
                model: NetworkDeviceModel::Veth,
                mac_address: MacAddress([0xBC, 0x24, 0x11, 0x47, 0x83, 0x11]),
                firewall: true,
                ip: None,
                ip6: None,
            }
        );

        assert_eq!(
            network_config.network_devices()[&2],
            NetworkDevice {
                model: NetworkDeviceModel::Veth,
                mac_address: MacAddress([0xBC, 0x24, 0x11, 0x47, 0x83, 0x12]),
                firewall: false,
                ip: Some(Ipv4Cidr::from_str("123.123.123.123/24").expect("valid ipv4")),
                ip6: None,
            }
        );

        assert_eq!(
            network_config.network_devices()[&5],
            NetworkDevice {
                model: NetworkDeviceModel::Veth,
                mac_address: MacAddress([0xBC, 0x24, 0x11, 0x47, 0x83, 0x13]),
                firewall: true,
                ip: None,
                ip6: Some(Ipv6Cidr::from_str("fd80::1/64").expect("valid ipv6")),
            }
        );

        NetworkConfig::parse(
            "netqwe: name=eth0,bridge=data,firewall=1,hwaddr=BC:24:11:47:83:11,ip=dhcp,type=veth"
                .as_bytes(),
        )
        .expect_err("invalid net key");

        NetworkConfig::parse(
            "net0 name=eth0,bridge=data,firewall=1,hwaddr=BC:24:11:47:83:11,ip=dhcp,type=veth"
                .as_bytes(),
        )
        .expect_err("invalid net key");

        NetworkConfig::parse(
            "net33: name=eth0,bridge=data,firewall=1,hwaddr=BC:24:11:47:83:11,ip=dhcp,type=veth"
                .as_bytes(),
        )
        .expect_err("invalid net key");
    }
}
