package CIF::Client;
use base 'REST::Client';
use base qw(Class::Accessor);

use 5.008008;
use strict;
use warnings;

use JSON;
use Text::Table;
use Config::Simple;
use Compress::Zlib;
use Data::Dumper;
use Encode qw/decode_utf8/;
use Digest::SHA1 qw/sha1_hex/;
use MIME::Base64;
use Module::Pluggable search_path => ['CIF::Client::Plugin'], require => 1, except => qr/Plugin::\S+::/;
use URI::Escape;

__PACKAGE__->mk_accessors(qw/apikey config/);

our $VERSION = '0.20';
$VERSION = eval $VERSION;  # see L<perlmodstyle>

# Preloaded methods go here.

sub _plugins {
    my @plugs;
    foreach (plugins()){
        next unless($_->type() eq 'output');
        $_ =~ s/CIF::Client::Plugin:://;
        $_ = lc($_);
        next if($_ eq 'output');
        push(@plugs,$_);
    }
    return (@plugs);
}

sub new {
    my $class = shift;
    my $args = shift;

    return(undef,'missing config file') unless($args->{'config'} || $args->{'host'});

    my ($cfg, $clientcfg);
    
    if($args->{'config'}){
        $cfg = Config::Simple->new($args->{'config'}) || return(undef,'missing config file');
        $clientcfg = $cfg->param(-block => 'client');
    }

    my $apikey = $args->{'apikey'} || $clientcfg->{'apikey'};
    unless($args->{'host'}){
        $args->{'host'} = $clientcfg->{'host'} || return(undef,'missing host');
    }

    my $self = REST::Client->new($args);
    bless($self,$class);

    $self->{'apikey'}           = $apikey;
    $self->{'config'}           = $cfg;
    $self->{'clientconfig'}     = $clientcfg;
    $self->{'max_desc'}         = $args->{'max_desc'};
    $self->{'restriction'}      = $clientcfg->{'restriction'};
    $self->{'severity'}         = $clientcfg->{'severity'};
    $self->{'nolog'}            = $clientcfg->{'nolog'};
    $self->{'restriction'}      = $args->{'restriction'} || $clientcfg->{'restriction'};
    $self->{'simple_hashes'}    = $args->{'simple_hashes'} || $clientcfg->{'simple_hashes'};

    $self->{'verify_tls'}       = (defined($args->{'verify_tls'})) ? $args->{'verify_tls'} : $clientcfg->{'verify_tls'};
    $self->{'guid'}             = $args->{'guid'} || $clientcfg->{'default_guid'};
    $self->{'limit'}            = $args->{'limit'} || $clientcfg->{'limit'};
    $self->{'group_map'}        = (defined($args->{'group_map'})) ? $args->{'group_map'} : $clientcfg->{'group_map'};
    $self->{'compress_address'} = $args->{'compress_address'} || $clientcfg->{'compress_address'};
    $self->{'round_confidence'} = $args->{'round_confidence'} || $clientcfg->{'round_confidence'};
    
    $cfg->param('claoverride.compress_address', $args->{'compress_address'}) if $args->{'compress_address'};
    $cfg->param('claoverride.round_confidence', $args->{'round_confidence'}) if $args->{'round_confidence'};
    $cfg->param('claoverride.fields', $args->{'fields'}) if (exists $args->{'fields'} && defined($args->{'fields'}));

    $self->{'proxy'}            = $args->{'proxy'} || $cfg->{'proxy'};
    
    if($args->{'fields'}){
        @{$self->{'fields'}} = split(/,/,$args->{'fields'}); 
    }

    if(defined($self->{'verify_tls'}) && $self->{'verify_tls'} == 0){
        $self->getUseragent->ssl_opts(verify_hostname => 0);
    }

    if($self->{'proxy'}){
        warn 'setting proxy' if($::debug);
        $self->getUseragent->proxy(['http','https'],$self->{'proxy'});
    }

    return($self);
}

sub POST {
    my $self = shift;
    my $data = shift;
    return unless($data);

    $data = JSON::to_json($data);

    my $rest = '/?apikey='.$self->apikey();
    $self->SUPER::POST($rest,$data);
    return $self->responseCode();
}
sub GET {
    my $self = shift;
    my %args = @_;

    my $q = $args{'query'};
    if(lc($q) =~ /^http(s)?:\/\//){
        $q =~ s/\/$//g;
        ## escape unsafe chars, that's what the data-warehouse does
        ## TODO -- doc this
        $q = uri_escape_utf8($q,'\x00-\x1f\x7f-\xff');
        $q = lc($q);
        $q = sha1_hex($q);
    }
    my $rest = '/'.$q.'?apikey='.$self->apikey();
    my $severity = ($args{'severity'}) ? $args{'severity'} : $self->{'severity'};
    my $restriction = ($args{'restriction'}) ? $args{'restriction'} : $self->{'restriction'};
    my $nolog = ($args{'nolog'}) ? $args{'nolog'} : $self->{'nolog'};
    my $nomap = ($args{'nomap'}) ? $args{'nomap'} : $self->{'nomap'};
    my $confidence = ($args{'confidence'}) ? $args{'confidence'} : $self->{'confidence'};
    my $guid = $args{'guid'} || $self->{'guid'};
    my $limit = $args{'limit'} || $self->{'limit'};

    $rest .= '&severity='.$severity if($severity);
    $rest .= '&restriction='.$restriction if($restriction);
    $rest .= '&nolog='.$nolog if($nolog);
    $rest .= '&nomap=1' if($nomap);
    $rest .= '&confidence='.$confidence if($confidence);
    $rest .= '&guid='.$guid if($guid);
    $rest .= '&limit='.$limit if($limit);

    $self->SUPER::GET($rest);
    my $content = $self->{'_res'}->{'_content'};
    return unless($content);
    return unless($self->responseCode == 200);
    my $text = $self->responseContent();
    my $hash = from_json($content, {utf8 => 1});
    my $t = ref(@{$hash->{'data'}->{'feed'}->{'entry'}}[0]);
    unless($t eq 'HASH'){
        my $r = @{$hash->{'data'}->{'feed'}->{'entry'}}[0];
        return unless($r);
        $r = uncompress(decode_base64($r));
        $r = from_json($r);
        $hash->{'data'}->{'feed'}->{'entry'} = $r;
    }
    ## TODO -- finish implementing this into the config
    if($self->{'simple_hashes'}){
        $self->hash_simple($hash);
        if($self->{'round_confidence'}){
            foreach (@{$hash->{'data'}->{'feed'}->{'entry'}}){
                # we're rouding down on purpose
                $_->{'confidence'} = int($_->{'confidence'});
            }
        }
    }
    
    return($hash->{'data'});
}       

sub hash_simple {
    my $self = shift;
    my $hash = shift;
    my @entries = @{$hash->{'data'}->{'feed'}->{'entry'}};

    my @plugs = $self->plugins();
    my @a;
    foreach (@plugs){
        next if(/Parser$/);
        push(@a,$_) if($_->type eq 'parser');
    }
    @plugs = @a;
    my @return;
    foreach my $p (@plugs){
        foreach my $e (@entries){
            if($p->prepare($e)){
                my @ary = @{$p->hash_simple($e)};
                push(@return,@ary);
            } else {
                push(@return,$e);
            }
        }
    }
    return unless(@return);
    @{$hash->{'data'}->{'feed'}->{'entry'}} = @return;
    return($hash);
}


1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

CIF::Client - Perl extension that extends REST::Client for use with the CI-Framework REST interface 

=head1 SYNOPSIS

  use CIF::Client;
  my $client = CIF::Client->new({
    host        => $url,
    timeout     => 60,
    apikey      => $apikey,
  });

  $client->search($query);
  die('request failed with code: '.$client->responseCode()) unless($client->responseCode == 200);

  my $text = $client->responseContent();

  print $client->table($text) || die('no records')

=head1 COMMAND-LINE

  $> cif -h
  $> cif -q example.com
  $> cif -q domain -p bindzone
  $> cif -q 192.168.1.0/24
  $> cif -q infrastructure/network -p snort
  $> cif -q url -s low | grep -v private

=head1 CONFIG FILE

Your config should be stored in ~/.cif (default)

  [client]
  host = https://example.com:443/api
  apikey = xx-xx-xx-xx-xx
  timeout = 60
  #severity = medium

=head1 DESCRIPTION

Simple extension of REST::Client for use with the CI-Framework REST based interface. Implements apikeys support and sample table output.

=head1 SEE ALSO

CIF::DBI, REST::Client

http://code.google.com/p/collective-intelligence-framework/

Wes Young, E<lt>wes@barely3am.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by REN-ISAC and The Trustees of Indiana University 
Copyright (C) 2010 by Wes Young

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
