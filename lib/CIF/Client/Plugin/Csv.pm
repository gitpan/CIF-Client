package CIF::Client::Plugin::Csv;
use CIF::Client::Support qw(confor);

use Regexp::Common qw/net/;

sub type { return 'output'; }

sub write_out {
    my $self = shift;
    my $config = shift;
    my $feed = shift;
    my $hash = $feed->{'feed'};
    my $group_map = ($config->{'group_map'}) ? $hash->{'group_map'} : undef;
    my $feed_guid = $hash->{'guid'};
    my @array = @{$feed->{'feed'}->{'entry'}};
    
    my @config_search_path = ('claoverride',  $feed->{'query'}, 'client' );

    # i preserved wes' original spelling of the config variable so as to not break
    # existing configs.
    my $cfg_csv_noseparator = confor($config, \@config_search_path, 'csv_noseperator', undef);
    
    #my @header = keys(%{$array[0]});
    my @header;
    # skip things like arrays and hashrefs for now
    foreach (keys %{$array[0]}){
        next unless(!ref($array[0]{$_}));
        push(@header,$_);
    }
    @header = sort { $a cmp $b } @header;
    my $body = '';
    if($group_map){
        map { $_->{'guid'} = $group_map->{$_->{'guid'}} } @array;
    }
    foreach my $a (@array){
        delete($a->{'message'}); 
        # there's no clean way to do this just yet
        foreach (@header){
            if($a->{$_} && !ref($a->{$_})){
                # deal with , in the field
                if($cfg_csv_noseparator){
                    $a->{$_} =~ s/,/ /g;
                    $a->{$_} =~ s/\s+/ /g;
                } else {
                    $a->{$_} =~ s/,/_/g;
                }
                # strip out non-ascii (typically unicode) chars
                # there are better ways to do this, but this works for now
                $a->{$_} =~ tr/\000-\177//cd;
            }
        }
        # the !ref() bits skip things like arrays and hashref's for now...
        $body .= join(',', map { ($a->{$_} && !ref($a->{$_})) ? $a->{$_} : ''} @header)."\n";
    }
    my $text = '# '.join(',',@header);
    $text .= "\n".$body;

    return $text;
}
1;
