package Data;
use Bytes::Random::Secure qw(random_string_from);
use MIME::Base64;
use DBI;

sub new {
    my $class = shift;
    my $self = {
		filename => shift || "state.db"
    };
    return bless $self, $class;
}

sub get_dbh {
	my $self = shift;
	unless($self->{dbh}){
		# connecting the database if not connected
		$self->{dbh} = prepare_connection($self->{filename});
		print "new database connection!\n";
	}
	return $self->{dbh};
}

sub prepare_connection {
	my $filename = shift;
	my $dbh = DBI->connect("dbi:SQLite:dbname=$filename","","");
	$dbh->do("PRAGMA foreign_keys = ON");
	$dbh->do("create table if not exists users (username text primary key)");
	$dbh->do("create table if not exists passwords (username text primary key, password text not null, foreign key(username) references users(username) ON UPDATE CASCADE ON DELETE CASCADE)");
	$dbh->do("create table if not exists tokens (token text primary key, username text not null, expiration integer not null, foreign key(username) references users(username) ON UPDATE CASCADE ON DELETE CASCADE)");
	$dbh->do("create table if not exists apikeys (apikey text primary key, username text not null, foreign key(username) references users(username) ON UPDATE CASCADE ON DELETE CASCADE)");
	$dbh->do("create table if not exists groups (groupname text primary key)");
	$dbh->do("create table if not exists user_groups (username text, groupname text, foreign key(username) references users(username) ON UPDATE CASCADE ON DELETE CASCADE, foreign key(groupname) references groups(groupname) ON UPDATE CASCADE ON DELETE CASCADE)");
	return $dbh;
}

sub get_user_groups {
 	my ($self, $uname) = @_;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("select (groupname) from user_groups where username=?");
	$sth->execute($uname);
	my @groups;
	my $gname;
	while($gname = $sth->fetchrow_array()){
		push @groups, $gname;
	}
	$sth->finish;
 	return @groups;
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