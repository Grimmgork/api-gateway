package Plack::Middleware::Auth;
use parent qw(Plack::Middleware);

use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	if(my $token = $req->cookies->{token}){
		return [400, [], ["bad token!"]] unless $token =~ m/^[a-z0-9_-]+$/i;
		my $data = $self->{data};
		if(my @fields = $data->get_token_fields($token)){

			# todo
			my $uname = shift @fields;
			my $exptime = shift @fields;
			# check for expiration delete if expired
			if(time() > $exptime){
				$data->delete_token($token);
				goto UNAUTHORIZED;
			}
			
			# delete token on x directive (onetime use)
			if(grep "x" @fields){
				$data->delete_token($token);
			}
			
			print @fields, "\n";
			print "login: $uname\n";
			$env->{LOGIN} = $uname;
			$env->{GROUPS} = $data->get_user_groups($uname);
			return $self->app->($env);
		}
	}

	UNAUTHORIZED:
	return [401, [], ["unauthorized!"]];
}

1;