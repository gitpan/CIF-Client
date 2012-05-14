package CIF::Client::Plugin::Snort;
use base 'CIF::Client::Plugin::Output';

use Snort::Rule;
use Regexp::Common qw/net/;

sub write_out {
    my $self = shift;
    my $config = shift;
    my $feed = shift;
    my @array = @{$feed->{'feed'}->{'entry'}};
    return '' unless(exists($array[0]->{'address'}));
	
    $config = $config->{'config'};
    
    # allow override of snort rule params
    my $tag = confor($config, 'snort_tag', undef);
    my $pri = confor($config, 'snort_priority', undef);
    my $sid = confor($config, 'snort_startsid', 1);
    my $thresh = confor($config,'snort_threshold', 'type limit,track by_src,count 1,seconds 3600');
    my $classtype = confor($config, 'snort_classtype', undef);
    my $srcnet = confor($config, 'snort_srcnet', 'any');
    my $srcport = confor($config, 'snort_srcport', 'any');

    my $rules = '';

    foreach (@array){
        next unless($_->{'address'});

        if(exists($_->{'rdata'})){
            $_->{'portlist'} = 53;
        }

        my $portlist = ($_->{'portlist'}) ? $_->{'portlist'} : 'any';		

        my $priority = 1;
        for(lc($_->{'severity'})){
            $priority = 5 if(/medium/);
            $priority = 9 if(/high/);
        }

        my $r = Snort::Rule->new(
            -action => 'alert',
            -proto  => translate_proto($_->{'protocol'}),
            -src    => $srcnet,
            -sport  => $srcport,
            -dst    => $_->{'address'},
            -dport  => $portlist,
            -dir    => '->',
        );
        $r->opts('msg',$_->{'restriction'}.' - '.$_->{'impact'}.' '.$_->{'description'});
        $r->opts('threshold', $thresh) if $thresh;
        $r->opts('tag', $tag) if $tag;
        $r->opts('classtype', $classtype) if $classtype;
        $r->opts('sid', $sid++);
        $r->opts('reference',$_->{'alternativeid'}) if($_->{'alternativeid'});
        $r->opts('priority', $pri || $priority);
        $rules .= $r->string()."\n";
    }
    return $rules;
}

sub translate_proto {
	my $protonum = shift;	
	my $protos = { 6 => 'tcp', 17 => 'udp', 1 => 'icmp' }; # snort only supports these, default is 'ip'
	return $protos->{$protonum} if (defined($protonum) && exists($protos->{$protonum}));
	return 'ip';
}

sub confor {
	my $conf = shift;
	my $name = shift;
	my $def = shift;

	# handle
	# snort_foo = 1,2,3
	# snort_foo = "1,2,3"

	if (exists($conf->{$name}) && defined($conf->{$name})) {
		return ref($conf->{$name} eq "ARRAY") ? join(', ', @{$conf->{$name}}) : $conf->{$name};
	}
	return $def;
}
1;
