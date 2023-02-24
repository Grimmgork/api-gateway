package Data;
use Bytes::Random::Secure qw(random_string_from);

sub new {
    my $class = shift;
    my $self = {
		loginfile => shift || "login.txt",
		tokenfile => shift || "tokens.txt"
    };
    return bless $self, $class;
}

sub get_user_groups {
 	my ($self, $uname) = @_;
	my $file = $self->{loginfile};
 	open FH, $file or die "could not open '$file'!";
 	while(<FH>){
 		if($_ =~ m/^$uname:\S+:([a-z0-9-_ ]+)$/m){
			my @groups = split ":", $1;
			close FH;
 			return \@groups;
 		}
 	}
	close FH;
 	return undef;
}

sub authenticate {
	my ($self, $uname, $pwd) = @_;
	my $file = $self->{loginfile};
	open FH, $file or die "could not open '$file'!";
 	while(<FH>){
 		if($_ =~ m/^$uname:$pwd:([a-z0-9_:-]+)$/m){ #TODO clean up
			close FH;
 			return split(":", $1);
 		}
 	}
	close FH;
	return undef;
}

sub remove_token {
	my ($self, $token) = @_;
	my $file = $self->{tokenfile};
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
	my ($self, $uname, $time, $directive, $token) = @_;
	my $file = $self->{tokenfile};
	$token = random_string_from("abcdefghijklmnopqrstuvwxyz0123456789-_", 8) unless $token;
	open(FH, ">>", $file);
	print FH generate_token_row($token, $uname, $time, $directive);
	close FH;
	return $token;
}

sub get_token_fields {
 	my ($self, $token) = @_;
	my $file = $self->{tokenfile};
	open FH, $file or die "could not open '$file'\n";
	my $res;
	while(<FH>){
		if($_ =~ m/^$token\s/){
			$res = parse_token_fields($_);
			last;
		}
	}
	close FH;
	return $res;
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