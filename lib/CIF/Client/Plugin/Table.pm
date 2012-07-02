package CIF::Client::Plugin::Table;
use base 'CIF::Client::Plugin::Output';
use CIF::Client::Support qw(confor);

use Text::Table;

sub write_out {
    my $self = shift;
    my $config = shift;
    my $feed = shift;
    my $summary = shift;
    my $reverse = shift;

    my $query = $feed->{'query'};
    my $hash = $feed->{'feed'};
    my $group_map = ($config->{'group_map'}) ? $hash->{'group_map'} : undef;
    my $feed_guid = $hash->{'guid'};
    
    # we will look for each variable in the [query] section
    # if it isnt there, we will check the [client] section.
    # if it's not there either, we'll use the default

    my @config_search_path = ( 'claoverride', $feed->{'query'}, 'client' );
    my $cfg_fields = confor($config, \@config_search_path, 'fields', undef);
    my $cfg_display = confor($config, \@config_search_path, 'display', undef);
    my $cfg_compress_address = confor($config, \@config_search_path, 'compress_address', undef);
    my $cfg_description = confor($config, \@config_search_path, 'description', undef);
    my $cfg_table_nowarning = confor($config, \@config_search_path, 'table_nowarning', undef);

    my $created = $hash->{'created'} || $hash->{'detecttime'};
    my $feedid = $hash->{'id'};
    my @a = @{$hash->{'entry'}};
    return unless(keys(%{$a[0]}));
    my @cols;
    if($::uuid){
        push(@cols,'uuid');
    }
    if($::relateduuid){
        push(@cols,'relatedid');
    }
    push(@cols,(
        'restriction',
        'guid',
        'severity',
        'confidence',
        'detecttime',
    ));
    unless($summary){
        my $t = $a[$#a];
        if(exists($t->{'address'})){
            push(@cols,('address'));
        }
        if(exists($t->{'protocol'})){
            push(@cols,'protocol');
        }
        if(exists($t->{'portlist'})){
            push(@cols,'portlist');
        }
        if(exists($t->{'rdata'})) {
            push(@cols,('rdata','type'));
        } 
        if(exists($t->{'asn'})) {
            push(@cols,'asn','prefix');
        } 
        if(exists($t->{'rir'})){
            push(@cols,'rir');
        }
        if(exists($t->{'malware_md5'})){
            push(@cols,('malware_md5','malware_sha1'));
        } elsif(exists($t->{'md5'}) && $t->{'impact'} ne 'malware'){
            push(@cols,('md5','sha1'));
        } 
        if(exists($t->{'cc'})){
            push(@cols,'cc');
        }
    }
    unless($a[0]->{'count'}){
        push(@cols,(
            'impact',
            'description',
            'alternativeid_restriction',
            'alternativeid',
        ));
   }
   if($cfg_fields){
        @cols = @{$cfg_fields};
    }
    if($cfg_display){
        @cols = split(',',$cfg_display);
    }

    my @header = map { $_, { is_sep => 1, title => '|' } } @cols;
    pop(@header);
    my $table = Text::Table->new(@header);

    if(my $max = $self->{'max_desc'}){
        map { $_->{'description'} = substr($_->{'description'},0,$max) } @a;
    }
    if($group_map){
        map { $_->{'guid'} = $group_map->{$_->{'guid'}} } @a;
    }
    @a = reverse(@a) if($reverse);
    foreach my $r (@a){
        if($r->{'address'} && $cfg_compress_address && length($r->{'address'}) > 32){
            $r->{'address'} = substr($r->{'address'},0,31);
            $r->{'address'} .= '...';
        }
        # strip out non-ascii (typically unicode) chars
        # there are better ways to do this, but this works for now
        $r->{'description'} =~ tr/\000-\177//cd;
        $table->load([ map { $r->{$_} } @cols]);
    }
    if($created){
        $table = "Feed Created: ".$created."\n\n".$table;
    }
    if(my $r = $hash->{'restriction'}){
        $table = "Feed Restriction: ".$r."\n".$table;
    }
    if(my $s = $hash->{'severity'}){
        $table = 'Feed Severity: '.$s."\n".$table;
    }
    if($feedid){
        $table = 'Feed Id: '.$feedid."\n".$table;
    }
    if($cfg_description){
        $table = 'Description: '.$cfg_description."\n".$table;
    }
    if($feed_guid){
        $feed_guid = $group_map->{$feed_guid} if($group_map);
        $table = 'Feed Group ID: '.$feed_guid."\n".$table;
    }
    $table = "Query: ".$query."\n".$table;
    unless($cfg_table_nowarning){
        $table = 'WARNING: Turn off this warning by adding: \'table_nowarning = 1\' to your ~/.cif config'."\n\n".$table;
        $table = 'WARNING: This table output not to be used for parsing, see "-p plugins" (via cif -h)'."\n".$table;
    }
    return "\n".$table;
}

1;
