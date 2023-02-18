package Plack::Middleware::MyAuth::Shared;
use Bytes::Random::Secure qw(random_string_from);

sub get_user_groups {
 	my ($file, $uname) = @_;
 	open FH, $file or die "could not open '$file'!";
 	while(<FH>){
 		if($_ =~ m/^$uname:\S+:([a-z0-9-_ ]+)$/m){
 			return split ":", $1;
 		}
 	}
 	return undef;
}

sub authenticate {
	my ($uname, $pwd) = @_;
	open FH, $file or die "could not open '$file'!";
 	while(<FH>){
 		if($_ =~ m/^$uname $pwd ([a-z0-9_-]+)$/m){
 			return split ":", $1;
 		}
 	}
	return undef;
}

sub get_new_token {
	my ($file, $uname, $timeout, $directive) = @_;
	
	return $jwt;
}

sub get_valid_token_content {
 	my ($file, $token) = @_;
	open FH, $file or die "could not open '$whitelist'\n";
	while(<FH>){
		print "line\n";
		if($_ =~ m/^$token\s/){
			if($_ =~ m/^[a-z0-9_\-]+\s+([a-z0-9_\-]+)\s+([\d+]+)(?:\s+([a-z0-9_\-]+))?/i){
				return ($1, $2, $3, $4);
			}
		}
	}
	return undef;
}

1;