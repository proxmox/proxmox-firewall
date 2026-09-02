use strict;
use warnings;

use File::Temp qw(tempdir);
use FindBin;
use JSON qw(decode_json);
use Test::More;

use PVE::Tools qw(file_get_contents file_set_contents run_command);

my $root = "$FindBin::Bin/..";
my $directory = tempdir(CLEANUP => 1, TMPDIR => 1);
my $output = "$directory/output.json";

sub run_generator {
    my ($kind, $source) = @_;
    my $stderr = '';
    my $status = run_command(
        [$^X, "$root/generate.pl", $kind, '--source', $source, '--output', $output],
        noerr => 1,
        errfunc => sub { $stderr .= "$_[0]\n"; },
    );
    return ($status, $stderr);
}

sub generate {
    my ($kind, $input) = @_;
    my $source = "$directory/$kind";
    file_set_contents($source, $input);
    my ($status, $stderr) = run_generator($kind, $source);
    is($status, 0, "$kind generation succeeds") or diag($stderr);
    return decode_json(file_get_contents($output));
}

my $services = generate(
    'services',
    "  http 80/tcp www web # not-an-alias\nrtmp 1/ddp\nacr-nema 104/tcp dicom\ndicom 11112/tcp\n",
);
my $http = { name => 'http', port => '80', tcp => 1 };
is_deeply(
    $services->{byname},
    {
        http => $http,
        www => $http,
        web => $http,
        'acr-nema' => { name => 'acr-nema', port => '104', tcp => 1 },
        dicom => { name => 'dicom', port => '11112', tcp => 1 },
    },
    'indexes service aliases with last-wins precedence, excluding comments and unsupported transports',
);

my $protocols = generate('protocols', "tcp 6 TCP\nipv6-icmp 58 IPv6-ICMP\nmptcp 262 MPTCP\n");
is_deeply(
    $protocols,
    {
        byid => { 6 => { name => 'tcp' }, 58 => { name => 'ipv6-icmp' } },
        byname => {
            tcp => { id => '6' },
            'ipv6-icmp' => { id => '58' },
            icmpv6 => { id => '58' },
        },
    },
    'excludes socket protocol IDs and arbitrary IP protocol aliases',
);

my $ethertypes = generate('ethertypes', "IPv4 0800 ip\nIPv6 86dd ip6\n");
is_deeply(
    $ethertypes->{byname},
    {
        IPv4 => { id => '0800' },
        ip => { id => '0800' },
        IPv6 => { id => '86DD' },
        ip6 => { id => '86DD' },
    },
    'preserves leading zeros and resolves hexadecimal EtherTypes and aliases',
);

for my $case (
    ['missing source', 'services', undef],
    ['empty database', 'protocols', ''],
    ['malformed record after valid input', 'ethertypes', "IPv4 0800\ninvalid\n"],
) {
    my ($name, $kind, $input) = @$case;
    my $source = "$directory/missing";
    if (defined($input)) {
        $source = "$directory/input";
        file_set_contents($source, $input);
    }
    file_set_contents($output, "keep existing data\n");
    my ($status) = run_generator($kind, $source);
    isnt($status, 0, "$name fails");
    is(file_get_contents($output), "keep existing data\n", "$name preserves output");
}

# Package builds install the checked-in JSON rather than regenerating it.
my %packaged = map { $_ => decode_json(file_get_contents("$root/data/$_.json")) }
    qw(services protocols ethertypes);
is_deeply(
    {
        service => $packaged{services}->{byname}->{www}->{port},
        protocol => $packaged{protocols}->{byname}->{icmpv6}->{id},
        non_ip_protocol_ids => [grep { $_ > 255 } keys $packaged{protocols}->{byid}->%*],
        ethertype => $packaged{ethertypes}->{byname}->{IPv6}->{id},
    },
    { service => '80', protocol => '58', non_ip_protocol_ids => [], ethertype => '86DD' },
    'packaged data contains the corrected service, protocol, and EtherType mappings',
);

done_testing();
