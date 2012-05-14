package CIF::Client::Plugin::Html;
use base 'CIF::Client::Plugin::Output';
use CIF::Client::Support qw(confor);

use HTML::Table;

sub write_out {
    my $self = shift;
    my $config = shift;
    my $feed = shift;
    my $summary = shift;
    my $reverse = shift;

    my $query = $feed->{'query'};
    my $hash = $feed->{'feed'};
    my $group_map = ($config->{'group_map'}) ? $hash->{'group_map'} : undef;

    my @config_search_path = ( $feed->{'query'}, 'client' );

    # fields class evenrowclass oddrowclass display
    
    my $cfg_fields = confor($config, \@config_search_path, 'fields', undef);
    my $cfg_display = confor($config, \@config_search_path, 'display', undef);
    my $cfg_class = confor($config, \@config_search_path, 'class', undef);
    my $cfg_evenrowclass = confor($config, \@config_search_path, 'evenrowclass', undef);
    my $cfg_oddrowclass = confor($config, \@config_search_path, 'oddrowclass', undef);
    
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
        if(exists($t->{'rdata'})){
            push(@cols,'rdata');
        }
        if(exists($t->{'protocol'})){
            push(@cols,'protocol');
        }
        if(exists($t->{'portlist'})){
            push(@cols,'portlist');
        }
        if($t->{'address'} && $t->{'address'} =~ /^[a-z0-9.-]+\.[a-z]{2,5}$/){
            push(@cols,'rdata','type');
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
    
    if(my $c = $cfg_display){
        @cols = @$c;
    }

    my $table = HTML::Table->new(
        -head           => \@cols,
        -class          => $cfg_class || '',
        -evenrowclass   => $cfg_evenrowclass || '',
        -oddrowclass    => $cfg_oddrowclass || '',
    );

    if(my $max = $self->{'max_desc'}){
        map { $_->{'description'} = substr($_->{'description'},0,$max) } @a;
    }
    if($group_map){
        map { $_->{'guid'} = $group_map->{$_->{'guid'}} } @a;
    }
    @a = reverse(@a) if($reverse);
    foreach my $r (@a){
        foreach(@cols){
            if($_ eq 'alternativeid' && $r->{$_} && lc($r->{$_}) =~ /[a-z0-9.-]+\.[a-z]{2,5}/){
                my $addr = ($r->{$_} =~ /^http/) ? $r->{$_} : 'http://'.$r->{$_};
                $r->{$_} = "<a target='_blank' href='$addr'>$addr</a>";
            }
        }
        my @row = map { $r->{$_} } @cols;
        $table->addRow(@row);
    }
    return $table->getTable();
}

1;
