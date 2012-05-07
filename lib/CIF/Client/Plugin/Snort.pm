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

    $config = $config->{'config'}->param(-block => $feed->{'query'});
    
    if (isempty($config)) { # just use the top level
    	$config = $config->{'config'}; 	
    }

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
        	$_->{'protocol'} = 17; #UDP just to be sure
            $_->{'portlist'} = 53;
        }

        my $portlist = ($_->{'portlist'}) ? $_->{'portlist'} : 'any';		

        my $priority = 1;
        for(lc($_->{'severity'})){
            $priority = 5 if(/medium/);
            $priority = 9 if(/high/);
        }

		my $dstnet = 'any';
		my $dstport = 'any';
		my $urlhost = undef;
		my ($urlport, $urlfile);
		
		if (isipv4($_->{'address'})) {
			$dstnet = $_->{'address'};
			$dstport = $portlist;	
		}
		else {
			($urlhost, $urlport, $urlfile) = isurl($_->{'address'});
			if (defined($urlhost)) {
				my $urlisip = isipv4($urlhost);
				$_->{'protocol'} = 6; # TCP by definition
				$dstnet = ($urlisip ? $urlhost : 'any'); # $EXTERNAL_NET?
				$dstport = $urlport || '$HTTP_PORTS';
			}
			else {
				$rules .= "### sorry. not sure what to do with address: " . $_->{'address'} . " so i'm skipping this one.\n\n";
				next;
			}
		}
		
        my $r = Snort::Rule->new(
            -action => 'alert',
            -proto  => translate_proto($_->{'protocol'}),
            -src    => $srcnet,
            -sport  => $srcport,
            -dst    => $dstnet,
            -dport  => $dstport,
            -dir    => '->',
        );
        
        $r->opts('msg',$_->{'restriction'}.' - '.$_->{'impact'}.' '.
        		$_->{'description'}
        		);
        $r->opts('threshold', $thresh) if $thresh;
        $r->opts('tag', $tag) if $tag;
        $r->opts('classtype', $classtype) if $classtype;
        $r->opts('sid', $sid++);
        $r->opts('reference',$_->{'alternativeid'}) if($_->{'alternativeid'});
        $r->opts('priority', $pri || $priority);
        
        #alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (Msg: "Mal_URI
		#www.badsite.com/malware.pl"; flow: to_server, established;
		#content:"Host|3A| www.basesite.com"; nocase;
		#content:"/malware.pl"; http_uri; nocase; sid:23424234;)

        if ($urlhost) {
        	$r->opts('flow', 'to_server');
        	if (!isipv4($urlhost)) {
        		$r->opts('content', 'Host|3A| ' . $urlhost);
        		$r->opts('http_header');
        		$r->opts('nocase');
        	}
        	if ($urlfile) {
        		$r->opts('content', $urlfile);
        		$r->opts('http_uri');
        		$r->opts('nocase');
        	}
        }
        $rules .= "# " . $_->{'address'} . "\n";
        $rules .= $r->string()."\n\n";
    }
    return $rules;
}


sub isipv4 {
	my ($i, $m) = (shift, 32);
	($i, $m) = split('/', $i) if ($i =~ /\//);
	return 1 if ( 
		($i =~ /^0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])(\.0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])){3}$/) &&
		($m > 0 && $m < 33)
	    );
	return 0;
}

sub isurl {
	my $x = shift;
	return (undef, undef, undef) unless $x;
	
	# it only makes sense to try to look for http: urls
	# https will be encrypted, ftp doesnt contain header fields to trigger on, etc
	
	if ($x =~ /http:\/\/([^\/]+)[\/]{0,1}(.*)/) {
		my ($h, $p) = split(':', $1);
		my $d = ($2 ? '/'.$2 : '');
		return ($h, $p, $d);
	}
	return (undef, undef, undef); 
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

sub isempty {
	my $h = shift;
	return 1 unless ref($h) eq "HASH";
	my @k = keys %$h;
	return 1 if $#k == -1;
	return 0;
}

1;
