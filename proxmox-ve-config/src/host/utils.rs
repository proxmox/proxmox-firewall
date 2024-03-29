use std::net::{IpAddr, ToSocketAddrs};

use crate::firewall::types::Cidr;

use nix::sys::socket::{AddressFamily, SockaddrLike};
use proxmox_sys::nodename;

/// gets a list of IPs that the hostname of this node resolves to
///
/// panics if the local hostname is not resolvable
pub fn host_ips() -> Vec<IpAddr> {
    let hostname = nodename();

    log::trace!("resolving hostname");

    format!("{hostname}:0")
        .to_socket_addrs()
        .expect("local hostname is resolvable")
        .map(|addr| addr.ip())
        .collect()
}

/// gets a list of all configured CIDRs on all network interfaces of this host
///
/// panics if unable to query the current network configuration
pub fn network_interface_cidrs() -> Vec<Cidr> {
    use nix::ifaddrs::getifaddrs;

    log::trace!("reading networking interface list");

    let mut cidrs = Vec::new();

    let interfaces = getifaddrs().expect("should be able to query network interfaces");

    for interface in interfaces {
        if let (Some(address), Some(netmask)) = (interface.address, interface.netmask) {
            match (address.family(), netmask.family()) {
                (Some(AddressFamily::Inet), Some(AddressFamily::Inet)) => {
                    let address = address.as_sockaddr_in().expect("is an IPv4 address").ip();

                    let netmask = netmask
                        .as_sockaddr_in()
                        .expect("is an IPv4 address")
                        .ip()
                        .count_ones()
                        .try_into()
                        .expect("count_ones of u32 is < u8_max");

                    cidrs.push(Cidr::new_v4(address, netmask).expect("netmask is valid"));
                }
                (Some(AddressFamily::Inet6), Some(AddressFamily::Inet6)) => {
                    let address = address.as_sockaddr_in6().expect("is an IPv6 address").ip();

                    let netmask_address =
                        netmask.as_sockaddr_in6().expect("is an IPv6 address").ip();

                    let netmask = u128::from_be_bytes(netmask_address.octets())
                        .count_ones()
                        .try_into()
                        .expect("count_ones of u128 is < u8_max");

                    cidrs.push(Cidr::new_v6(address, netmask).expect("netmask is valid"));
                }
                _ => continue,
            }
        }
    }

    cidrs
}
