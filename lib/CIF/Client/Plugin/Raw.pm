package CIF::Client::Plugin::Raw;
use base 'CIF::Client::Plugin::Output';
use CIF::Client::Support qw(confor);

require JSON;

sub write_out {
    my $self = shift;
    my $config = shift;
    my $feed = shift;
    my $json;
    
    my @config_search_path = ( $feed->{'query'}, 'client' );

	# fyi
	#   my $cfg_csv_noseparator = confor($config, \@config_search_path, 'csv_noseparator', undef);
        
    if(1 || $config->{'stream'}){
        my @array = @{$feed->{'feed'}->{'entry'}};
        return unless(keys(%{$array[0]}));
        my @json_stream;
        foreach(@array){
            push(@json_stream,JSON::to_json($_));
        }
        $json = join("\n",@json_stream);
    } else {
        return unless($feed->{'feed'}->{'entry'});
        $json = JSON::to_json($feed->{'feed'}->{'entry'});
    }
    return $json."\n";
}
1;
