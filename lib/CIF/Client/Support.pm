package CIF::Client::Support;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(confor);

# confor($conf, ['infrastructure/botnet', 'client'], 'massively_cool_output', 0)
#
# search the given sections, in order, for the given config param. if found, 
# return its value or the default one specified.

sub confor {
	my $conf = shift;
	my $sections = shift;
	my $name = shift;
	my $def = shift;

	# handle
	# snort_foo = 1,2,3
	# snort_foo = "1,2,3"

	foreach my $s (@$sections) { 
		my $sec = $conf->{'config'}->param(-block => $s);
		next if isempty($sec);
		next if !exists $sec->{$name};
		if (defined($sec->{$name})) {
			return ref($sec->{$name} eq "ARRAY") ? join(', ', @{$sec->{$name}}) : $sec->{$name};
		} else {
			return $def;
		}
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
