package Plack::Middleware::Apikey;
use parent qw(Plack::Middleware);

use HTML::Template;
use Plack::Util;
use MIME::Base64;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	my $data = $self->{data};
	my $env_login = $self->{env_login} || "login";
	
	unless($env->{$env_login}){
		if($req->headers->header('authorization') =~ m/^bearer +([a-z0-9]+)$/i){
			if(my $username = $data->login_apikey($1)){
				$env->{$env_login} = $username;
				return $self->app->($env);
			}
			return [401, [], ["invalid apikey!"]];
		}
	}
	return $self->app->($env);
}

1;