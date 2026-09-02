# Firewall databases

The JSON databases provide a versioned set of service, IP protocol, and
EtherType names without depending on changes to the host's netbase files.

## Regeneration and tests

The JSON was generated from Debian netbase 6.5. To regenerate it from an
extracted netbase package, run:

```sh
./generate.pl services --source /path/to/netbase/etc/services
./generate.pl protocols --source /path/to/netbase/etc/protocols
./generate.pl ethertypes --source /path/to/netbase/etc/ethertypes
prove -v tests/*.t
```

The generator and tests require `libpve-common-perl` and `libjson-perl`.
Without `--source`, each command reads the corresponding file in `/etc`.
The default output is `data/<command>.json`; `--output` overrides it.
Input errors and databases without supported entries cause the command to
fail without replacing the output.

Use stock netbase files rather than a customized host configuration. Review
removed names and changed mappings before updating the packaged data; preserve
previously supported mappings rather than inheriting upstream removals.

## JSON format

Each database contains `byid` and `byname` objects. Primary names are
indexed in `byname`. Services and EtherTypes also include the aliases listed
in the source file. Names are case-sensitive.

- Services use decimal port strings as `byid` keys. Entries contain `name`,
  `port` (a decimal string), and a value of `1` for each supported transport
  (`tcp`, `udp`, or `sctp`). Each `byname` entry contains the same record as
  its corresponding `byid` entry. Other transports, such as AppleTalk DDP,
  are excluded.
- Protocols use decimal protocol strings as `byid` keys. Each value contains
  `name`; each `byname` value contains `id`, also a decimal string. Only
  primary source names and the `icmpv6` alias are indexed, since consumers
  attach protocol-specific behavior to those names. Both `ipv6-icmp` and
  `icmpv6` resolve to `58`. Values above 255, such as the Linux socket protocol
  identifier MPTCP (`262`), are excluded because they cannot appear in an IP
  header.
- EtherTypes use four-digit uppercase hexadecimal strings, including leading
  zeros, as `byid` keys. Each value contains `name`; each `byname` value
  contains `id` in the same hexadecimal format. For example, `IPv4` maps to
  `0800`, and `IPv6` maps to `86DD`.

When multiple primary names share an identifier, the last primary name in the
source determines the `byid` name. Services sharing a port combine their
transport flags. This preserves the original Perl service database's behavior.
