#!/usr/bin/perl

use strict;
use warnings;

package FirewallDataParser {
    use JSON;

    use PVE::Tools;

    use PVE::CLIHandler;
    use base qw(PVE::CLIHandler);

    my sub parse_database {
        my ($filename, $parse_entry) = @_;

        my $entries = { byid => {}, byname => {} };
        my $line_number = 0;

        for my $line (split(/\n/, PVE::Tools::file_get_contents($filename))) {
            $line_number++;
            $line =~ s/#.*$//;
            $line =~ s/^\s+|\s+$//g;
            next if !length($line);

            $parse_entry->($entries, $line, "$filename:$line_number");
        }

        die "no supported entries in '$filename'\n" if !keys($entries->{byid}->%*);

        return $entries;
    }

    my sub get_etc_services {
        my ($filename) = @_;

        return parse_database(
            $filename,
            sub {
                my ($services, $line, $location) = @_;
                my ($name, $port_protocol, @aliases) = split(/\s+/, $line);

                die "invalid service entry at $location\n"
                    if !defined($port_protocol) || $port_protocol !~ m!^([0-9]+)/(\S+)$!;
                my ($port, $protocol) = ($1, $2);
                die "invalid port at $location: $port\n" if $port > 65535;

                # netbase also contains non-IP services, such as AppleTalk DDP.
                return if $protocol !~ m/^(tcp|udp|sctp)$/;

                my $entry = $services->{byid}->{$port} //= { port => $port };
                $entry->{name} = $name;
                $entry->{$protocol} = 1;
                for my $alias ($name, @aliases) {
                    $services->{byname}->{$alias} = $entry;
                }
            },
        );
    }

    my sub parse_protocol_file {
        my ($filename, $hexadecimal) = @_;
        my $id_pattern = $hexadecimal ? qr/[0-9A-Fa-f]{4}/ : qr/[0-9]+/;

        return parse_database(
            $filename,
            sub {
                my ($protocols, $line, $location) = @_;
                my ($name, $id, @aliases) = split(/\s+/, $line);

                die "invalid protocol entry at $location\n"
                    if !defined($id) || $id !~ m/^$id_pattern$/;
                # Linux socket protocol IDs, such as MPTCP (262), do not fit the 8-bit IP header field.
                return if !$hexadecimal && $id > 255;
                $id = uc($id);

                $protocols->{byid}->{$id}->{name} = $name;
                $protocols->{byname}->{$name} = { id => $id };

                # IP protocol consumers attach semantics to primary names, not arbitrary aliases.
                if ($hexadecimal) {
                    for my $alias (@aliases) {
                        $protocols->{byname}->{$alias} = { id => $id };
                    }
                }
            },
        );
    }

    my sub get_etc_protocols {
        my ($filename) = @_;

        my $protocols = parse_protocol_file($filename, 0);

        # Keep the iptables spelling available alongside netbase's ipv6-icmp.
        $protocols->{byid}->{58} //= { name => 'ipv6-icmp' };
        $protocols->{byname}->{'ipv6-icmp'} //= { id => '58' };
        $protocols->{byname}->{icmpv6} = { id => '58' };

        return $protocols;
    }

    my sub get_etc_ethertypes {
        my ($filename) = @_;
        return parse_protocol_file($filename, 1);
    }

    __PACKAGE__->register_method({
        name => 'generate_protocols',
        path => 'generate_protocols',
        method => 'POST',
        description => 'Generates a new JSON with data from a protocols file.',
        parameters => {
            additionalProperties => 0,
            properties => {
                source => {
                    description => 'The file to use as the source for generating the JSON.',
                    default => '/etc/protocols',
                    type => 'string',
                    optional => 1,
                },
                output => {
                    description => 'The file where the generated JSON should get written to.',
                    default => 'data/protocols.json',
                    type => 'string',
                    optional => 1,
                },
            },
        },
        returns => {
            type => 'null',
        },
        code => sub {
            my ($params) = @_;

            my $source = $params->{source} // '/etc/protocols';
            my $output = $params->{output} // 'data/protocols.json';

            my $protocols_json =
                to_json(get_etc_protocols($source), { utf8 => 1, pretty => 1, canonical => 1 });
            PVE::Tools::file_set_contents($output, $protocols_json);

            return;
        },
    });

    __PACKAGE__->register_method({
        name => 'generate_ethertypes',
        path => 'generate_ethertypes',
        method => 'POST',
        description => 'Generates a new JSON with data from an ethertypes file.',
        parameters => {
            additionalProperties => 0,
            properties => {
                source => {
                    description => 'The file to use as the source for generating the JSON.',
                    default => '/etc/ethertypes',
                    type => 'string',
                    optional => 1,
                },
                output => {
                    description => 'The file where the generated JSON should get written to.',
                    default => 'data/ethertypes.json',
                    type => 'string',
                    optional => 1,
                },
            },
        },
        returns => {
            type => 'null',
        },
        code => sub {
            my ($params) = @_;

            my $source = $params->{source} // '/etc/ethertypes';
            my $output = $params->{output} // 'data/ethertypes.json';

            my $ethertypes_json =
                to_json(get_etc_ethertypes($source), { utf8 => 1, pretty => 1, canonical => 1 });
            PVE::Tools::file_set_contents($output, $ethertypes_json);

            return;
        },
    });

    __PACKAGE__->register_method({
        name => 'generate_services',
        path => 'generate_services',
        method => 'POST',
        description => 'Generates a new JSON with data from a services file.',
        parameters => {
            additionalProperties => 0,
            properties => {
                source => {
                    description => 'The file to use as the source for generating the JSON.',
                    default => '/etc/services',
                    type => 'string',
                    optional => 1,
                },
                output => {
                    description => 'The file where the generated JSON should get written to.',
                    default => 'data/services.json',
                    type => 'string',
                    optional => 1,
                },
            },
        },
        returns => {
            type => 'null',
        },
        code => sub {
            my ($params) = @_;

            my $source = $params->{source} // '/etc/services';
            my $output = $params->{output} // 'data/services.json';

            my $services_json =
                to_json(get_etc_services($source), { utf8 => 1, pretty => 1, canonical => 1 });
            PVE::Tools::file_set_contents($output, $services_json);

            return;
        },
    });

    our $cmddef = {
        ethertypes => [__PACKAGE__, 'generate_ethertypes', []],
        protocols => [__PACKAGE__, 'generate_protocols', []],
        services => [__PACKAGE__, 'generate_services', []],
    };
}

FirewallDataParser->run_cli_handler();

1;
