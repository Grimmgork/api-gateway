package Plack::Middleware::Auth;
use parent qw(Plack::Middleware);

use Plack::Middleware::Data;
use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	if($env->{HTTP_COOKIE} =~ m/^token=([a-z0-9+\/]+)(?:\;|$)/i){
		if(my @fields = Plack::Middleware::Data::get_valid_token("./tokens.txt", $1)){
			# find corresponding username
			my $uname = $fields[0];
			print "valid token! logged in as $uname\n";
			$env->{LOGIN} = $uname;
			$env->{GROUPS} = Plack::Middleware::Data::get_user_groups("./login.txt", $uname);
			return $self->app->($env);
		}
	}

	return [401, [], ["unauthorized!"]];
}

1;