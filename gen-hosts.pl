#!/usr/bin/perl
use JSON;
use Data::Dumper;
my $json = JSON->new->allow_nonref;
my $top = '
127.0.0.1       localhost
::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
';
open(FILE,"/root/saws-info.json") || die "Failed to open /root/saws-info.json\n";
my $json_text;
while(<FILE>) {
        $json_text .= $_;
}
close(FILE);
my $info = $json->decode( $json_text );
open(HOSTS,">/etc/hosts") || die "Failed to open /etc/hosts\n";
print HOSTS $top;
foreach my $host (@{$info}) {
        my $hostname = $$host{'Tags'}[0]{'Value'};
        my $ip = $$host{'PrivateIPAddress'};
        print HOSTS "$ip $hostname\n";
}
close(HOSTS);

