package Plack::Middleware::Authentication::Data;
use Bytes::Random::Secure qw(random_string_from);

sub get_user_groups {
 	my ($file, $uname) = @_;
 	open FH, $file or die "could not open '$file'!";
 	while(<FH>){
 		if($_ =~ m/^$uname:\S+:([a-z0-9-_ ]+)$/m){
			my @groups = split ":", $1;
 			return \@groups;
 		}
 	}
 	return undef;
}

sub authenticate {
	my ($file, $uname, $pwd) = @_;
	open FH, $file or die "could not open '$file'!";
 	while(<FH>){
 		if($_ =~ m/^$uname:$pwd:([a-z0-9_:-]+)$/m){ #TODO clean up
 			return split(":", $1);
 		}
 	}
	return undef;
}

sub remove_token {
	my ($file, $token) = @_;
	open FH , '<', $file or die "Can't open '$file'!\n";
	my @lines;
	while(<FH>){
		push @lines, $_ unless /^$token\s/;
	}
	close FH;
	open FH, '>', $file or die "Can't write to $file!\n";
	print FH @lines;
	close FH;
}

sub add_new_token {
	my ($file, $uname, $time, $directive, $token) = @_;
	$token = random_string_from("abcdefghijklmnopqrstuvwxyz0123456789-_", 8) unless $token;
	open(FH, ">>", $file);
	print FH generate_token_row($token, $uname, $time, $directive);
	close FH;
	return $token;
}

sub get_valid_token {
 	my ($file, $token) = @_;
	open FH, $file or die "could not open '$file'\n";
	while(<FH>){
		if($_ =~ m/^$token\s/){
			my @fields = parse_token_fields($_);
			return undef unless @fields;
			return undef if $fields[-1] eq "x" or $fields[1] < time();
			return @fields;
		}
	}
	return undef;
}

sub parse_token_fields {
	$_ = shift;
	return ($1, $2, $3) if $_ =~ m/^[a-z0-9_\-]+\s+([a-z0-9_\-]+)\s+([\d+]+)(?:\s+([a-z0-9_\-]+))?/i;
	return undef;
}

sub generate_token_row {
	return join(" ", @_) . "\n";
}

1;