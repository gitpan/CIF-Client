use inc::Module::Install;

name        'CIF-Client';
all_from    'lib/CIF/Client.pm';

requires    'Module::Install'   => '1.00';
requires    'REST::Client'      => '243';
requires    'Text::Table'       => '1.114';
requires    'HTML::Table'       => '2.08';
requires    'JSON'              => '2.07';
requires    'Compress::Zlib'    => '2.008';
requires    'Config::Simple'    => '4.58';
requires    'Snort::Rule'       => '1.07';
requires    'Class::Accessor'   => '0.31';
requires    'Digest::MD5'       => '2.36';
requires    'Digest::SHA1'      => '2.11';
requires    'Module::Pluggable'             => '3.6';
requires    'Regexp::Common::net'           => '2.108';
requires    'Regexp::Common::net::CIDR'     => '0.02';
requires    'LWP::Protocol::https'          => undef;
requires    'HTTP::Server::Simple'          => 0;
requires    'Parse::Range'                  => '0.96';

install_script 'cif';

WriteAll();
