package Plack::Middleware::Authentication::Auth;
use parent qw(Plack::Middleware);

use Plack::Middleware::Authentication::Data;
use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	$env->{LOGIN} = undef;
	$env->{GROUPS} = undef;
	# while ( ($k,$v) = each %{$env} ) {
    	# 	print "$k => $v\n";
	# }

	if($env->{HTTP_COOKIE} =~ m/^token=([a-z0-9+\/]+)(?:\;|$)/i){
		if(my @fields = get_valid_token("./tokens.txt", $1)){
			# find corresponding username
			my $uname = $fields[0];
			print "valid token! logged in as $uname\n";
			$env->{LOGIN} = uname;
			$env->{GROUPS} = get_user_groups("./login.txt", $uname);
			return $self->app->($env);
		}
	}

	return [401, [], ["unauthorized!"]];
}

1;