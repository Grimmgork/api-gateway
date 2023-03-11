package Data;
use Bytes::Random::Secure qw(random_string_from);
use MIME::Base64;

use DBI;

sub new {
    my $class = shift;
    my $self = {
		loginfile => shift || "login.txt",
		tokenfile => shift || "tokens.txt"
    };
    my $dbh = DBI->connect("dbi:SQLite:dbname=state.db","","");
    my $sth = $dbh->prepare("INSERT INTO login (username, password) VALUES (?, ?)");
	$sth->execute("root", "password");
    
    return bless $self, $class;
}

sub get_user_groups {
 	my ($self, $uname) = @_;
	my $file = $self->{loginfile};
 	open FH, $file or die "could not open '$file'!";
 	while(<FH>){
 		if($_ =~ m/^$uname:[a-zA-Z0-9+\/=]+:([a-zA-Z0-9_\-:]*)$/){
			print "match!\n";
			my @groups = split ":", $1;
			@groups = grep { $_ ne ''} @groups;
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
	my $res;
 	while(<FH>){
 		if($_ =~ m/^$uname:$pwd:[a-zA-Z0-9_\-:]+$/) {
			close FH;
			return 1;
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
		push @lines, $_ unless /^$token:/;
	}
	close FH;
	open FH, '>', $file or die "Can't write to $file!\n";
	print FH @lines;
	close FH;
}

sub add_new_token {
	my ($self, $uname, $time, @directives) = @_;
	my $file = $self->{tokenfile};
	my $token = random_string_from("abcdefghijklmnopqrstuvwxyz0123456789-_", 8);
	open(FH, ">>", $file);
	print FH "$token:$uname:$time:" . join(":", @directives) . "\n";
	close FH;
	return $token;
}

sub get_token_fields {
 	my ($self, $token) = @_;
	my $file = $self->{tokenfile};
	open FH, $file or die "could not open '$file'\n";
	my @res;
	while(<FH>){
		if($_ =~ m/^$token:/){
			@res = parse_token_fields($_);
			last;
		}
	}
	close FH;
	return @res;
}

sub parse_token_fields {
	$_ = shift;
	if($_ =~ m/^[a-z0-9_\-]+:([a-z0-9_\-]+):([\d]+):([a-z0-9_\-:]*)$/i){
		my @directives = split(":", $3);
		@directives = grep { $_ ne '' } @directives;
		return ($1, int($2), @directives);
	}
	return undef;
}

1;