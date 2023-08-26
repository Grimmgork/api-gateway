package Data;
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
		remove_expired_tokens($self, time()); # clean up the database, maybe move it into external script
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
	$dbh->do("create table if not exists tokens (token text primary key, terminator text not null, username text not null, expiration integer not null, foreign key(username) references users(username) ON UPDATE CASCADE ON DELETE CASCADE)");
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

sub login_password {
	my ($self, $uname, $pwd) = @_;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("select (username) from passwords where username=? and password=?");
	$sth->execute($uname, $pwd);
	my $login = $sth->fetchrow_array();
	$sth->finish;
	return $login;
}

sub login_apikey {
	my ($self, $apikey) = @_;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("select (username) from apikeys where apikey=?");
	$sth->execute($apikey);
	my $uname = $sth->fetchrow_array();
	$sth->finish;
	return $uname;
}

sub remove_token {
	my ($self, $token) = @_;
	return unless $token;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("delete from tokens where token=?");
	$sth->execute($token);
	$sth->finish;
}

sub add_new_token {
	my ($self, $token, $terminator, $uname, $time, $directives) = @_;
	return undef unless $uname and $time and $token;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("insert into tokens (token, terminator, username, expiration) values (?, ?, ?, ?)");
	my $res = $sth->execute($token, $terminator, $uname, $time);
	$sth->finish;
	return $token if $res;
	return undef;
}

sub terminate_token {
	my ($self, $terminator) = @_;
	return undef unless $terminator;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("delete from tokens where terminator=?");
	my $res = $sth->execute($terminator);
	$sth->finish;
	return $sth->rows;
}

sub find_token {
 	my ($self, $token) = @_;
	return undef unless $token;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("select token, terminator, username, expiration from tokens where token=?");
	$sth->execute($token);
	return $sth->fetchrow_array();
}

sub rotate_token {
	my ($self, $token, $ntoken) = @_;
	return undef unless $token and $ntoken;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("update tokens set token=? where token=?");
	$sth->execute($ntoken, $token);
	return $ntoken;
}

sub add_user {
	my ($self, $uname) = @_;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("insert into users (username) values (?)");
	my $res = $sth->execute($uname);
	$sth->finish;
	return $res;
}

sub add_group {
	my ($self, $gname) = @_;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("insert into groups (groupname) values (?)");
	my $res = $sth->execute($gname);
	$sth->finish;
	return $res;
}

sub add_group_to_user {
	my ($self, $gname, $uname) = @_;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("insert into user_groups (username, groupname) values (?, ?)");
	$sth->execute($uname, $gname);
	$sth->finish;
}

sub remove_group_from_user {
	my ($self, $gname, $uname) = @_;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("delete from user_groups where username=? and groupname=?");
	$sth->execute($uname, $gname);
	$sth->finish;
}

sub remove_user {
	my ($self, $uname) = @_;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("delete from users where username=?");
	$sth->execute($uname);
	$sth->finish;
}

sub remove_group {
	my ($self, $gname) = @_;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("delete from groups where groupname=?");
	$sth->execute($gname);
	$sth->finish;
}

sub remove_expired_tokens {
	my ($self, $time) = @_;
	return unless $time;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("delete from tokens where expiration < ?");
	$sth->execute($time);
}

1;