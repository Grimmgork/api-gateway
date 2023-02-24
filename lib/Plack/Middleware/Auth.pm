package Plack::Middleware::Auth;
use parent qw(Plack::Middleware);

use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	if($env->{HTTP_COOKIE} =~ m/^token=([a-z0-9+\/]+)(?:\;|$)/i){
		my $data = $self->{data};
		if(my @fields = $data->get_token_fields($1)){
			# find corresponding username
			my $uname = $fields[0];
			print "login: $uname\n";
			$env->{LOGIN} = $uname;
			$env->{GROUPS} = $data->get_user_groups($uname);
			return $self->app->($env);
		}
	}

	return [401, [], ["unauthorized!"]];
}

1;