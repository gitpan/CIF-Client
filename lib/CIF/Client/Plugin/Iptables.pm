package CIF::Client::Plugin::Iptables;
use CIF::Client::Support qw(confor);

sub type { return 'output'; }
sub write_out {
    my $self = shift;
    my $config = shift;
    my $feed = shift;
    my @array = @{$feed->{'feed'}->{'entry'}};

    my @config_search_path = ( $feed->{'query'}, 'client' );

	# fyi
	#   my $cfg_csv_noseparator = confor($config, \@config_search_path, 'csv_noseparator', undef);

        
    my $text = "iptables -N CIF_IN\n";
    $text .= "iptables -F CIF_IN\n";
    $text .= "iptables -N CIF_OUT\n";
    $text .= "iptables -F CIF_OUT\n";
    foreach (@array){
        $text .= "iptables -A CIF_IN -s $_->{'address'} -j DROP\n";
        $text .= "iptables -A CIF_OUT -d $_->{'address'} -j DROP\n";
    }

    $text .= "iptables -A INPUT -j CIF_IN\n";
    $text .= "iptables -A CIF_IN -j LOG --log-level 6 --log-prefix '[IPTABLES] cif dropped'\n";
    $text .= "iptables -A OUTPUT -j CIF_OUT\n";
    $text .= "iptables -A CIF_OUT -j LOG --log-level 6 --log-prefix '[IPTABLES cif dropped'\n";

    return $text;
}
1;
