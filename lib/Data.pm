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
}

sub add_new_token {
	my ($self, $token, $uname, $time, $directives) = @_;
	return undef unless $token and $uname and $time; 
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("insert into tokens (token, username, expiration) values (?, ?, ?)");
	my $res = $sth->execute($token, $uname, $time);
	$sth->finish;
	return $token if $res;
	return undef;
}

sub find_token {
 	my ($self, $token) = @_;
	return undef unless $token;
	my $dbh = get_dbh($self);
	my $sth = $dbh->prepare("select token, username, expiration from tokens where token=?");
	$sth->execute($token);
	return $sth->fetchrow_array();
}

1;