package CIF::Client::Plugin::Bro;
use CIF::Client::Support qw(confor);

use Regexp::Common qw/net/;
use Regexp::Common qw /URI/;
use Regexp::Common::net::CIDR ();

sub type { return 'output'; }

sub write_out {
    my $self = shift;
    my $config = shift;
    my $feed = shift;
    my $hash = $feed->{'feed'};
    my @array = @{$feed->{'feed'}->{'entry'}};

    my @config_search_path = ('claoverride',  $feed->{'query'}, 'client' );

    $result = "#fields\thost\tnet\tstr\tstr_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.cif_impact\tmeta.cif_severity\tmeta.cif_confidence\n";

    foreach my $a (@array){
        my $ip = 0;
        my $net = 0;
        my $domain = 0;
        my $url = 0;

        if(exists($a->{'address'}) and $a->{'address'}) {
            if($a->{'address'} =~ m/^$RE{URI}{HTTP}{-scheme=>'https?'}{-keep}$/i){
                if( $3 and $5 ){ $url = $3.$5; }
                elsif( $3 ){ $url = $3; }
            }
            elsif($a->{'address'} =~ m/^$RE{URI}{FTP}{-keep}$/){
                if( $3 and $5 ){ $url = $3.$5; }
                elsif( $3 ){ $url = $3; }
            }
            elsif($a->{'address'} =~ m/^$RE{net}{domain}$/){$domain = $a->{'address'};}

            # TODO: Add IPv6 support when that gets added to CIF                                                                                                                                                                                                                
            elsif($a->{'address'} =~ m/$RE{net}{CIDR}{IPv4}/){$net = $a->{'address'};}
            elsif($a->{'address'} =~ m/$RE{net}{IPv4}/){$ip = $a->{'address'};}

            # host    net    str   str_type                                                                                                                                                                                                                                     

            if($domain){ $result .= "-\t-\t".$domain."\tIntel::DOMAIN\t"; }
            if($url){    $result .= "-\t-\t".$url."\tIntel::URL\t"; }
            if($ip){     $result .= $ip."\t-\t-\t-\t"; }
            if($net){    $result .= "-\t".$net."\t-\t-\t"; }
        }

        if($ip or $net or $domain or $url) {
            $result .= "CIF - ";
            if(exists($a->{'restriction'}) and $a->{'restriction'}) { $result .= $a->{'restriction'}."\t"; }
            else { $result .= "Unknown\t"; }

            if(exists($a->{'description'}) and $a->{'description'}) { $result .= $a->{'description'}."\t"; }
            else { $result .= "-\t"; }

            if(exists($a->{'alternativeid'}) and $a->{'alternativeid'}) { $result .= $a->{'alternativeid'}." "; }
            else { $result .= "- "; }

            if(exists($a->{'alternativeid_restriction'}) and $a->{'alternativeid_restriction'}) { $result .= "(".$a->{'alternativeid_restriction'}.")\t"; }
            else { $result .= "(Unknown)\t"; }

            if(exists($a->{'impact'}) and $a->{'impact'}) { $result .= $a->{'impact'}."\t"; }
            else { $result .= "-\t"; }

            if(exists($a->{'severity'}) and $a->{'severity'}) { $result .= $a->{'severity'}."\t"; }
            else { $result .= "-\t"; }

            if(exists($a->{'confidence'}) and $a->{'confidence'}) { $result .= $a->{'confidence'}."\n"; }
            else { $result .= "-\n"; }
        }
    }
    return $result;
}
1;