package CIF::Client::Plugin::Iptables;
use CIF::Client::Support qw(confor);

use Regexp::Common qw/net/;

sub type { return 'output'; }
sub write_out {
    my $self = shift;
    my $config = shift;
    my $feed = shift;
    my @array = @{$feed->{'feed'}->{'entry'}};
    
     my @config_search_path = ('claoverride',  $feed->{'query'}, 'client' );

    my $text = "iptables -N CIF_IN\n";
    $text .= "iptables -F CIF_IN\n";
    $text .= "iptables -N CIF_OUT\n";
    $text .= "iptables -F CIF_OUT\n";
    my $warning = 0;
    foreach (@array){
        unless($_->{'address'} =~ /^$RE{'net'}{'IPv4'}/){
            warn 'WARNING: Currently this plugin only supports IPv4 addresses'."\n";
            return '';
        }
        $_->{'address'} = normalize_address($_->{'address'});
        $text .= "iptables -A CIF_IN -s $_->{'address'} -j DROP\n";
        $text .= "iptables -A CIF_OUT -d $_->{'address'} -j DROP\n";
    }

    $text .= "iptables -A INPUT -j CIF_IN\n";
    $text .= "iptables -A CIF_IN -j LOG --log-level 6 --log-prefix '[IPTABLES] cif dropped'\n";
    $text .= "iptables -A OUTPUT -j CIF_OUT\n";
    $text .= "iptables -A CIF_OUT -j LOG --log-level 6 --log-prefix '[IPTABLES cif dropped'\n";

    return $text;
}

sub normalize_address {
    my $addr = shift;

    my @bits = split(/\./,$addr);
    foreach(@bits){
        next unless(/^0{1,2}/);
        $_ =~ s/^0{1,2}//;
    }
    return join('.',@bits);
}   
        
1;
