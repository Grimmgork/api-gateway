package Plack::Middleware::Apikey;
use parent qw(Plack::Middleware);

use HTML::Template;
use Plack::Util;
use MIME::Base64;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	my $data = $self->{data};
	
	unless($env->{LOGIN}){
		if($req->headers->header('authorization') =~ m/^bearer +([a-z0-9]+)$/i){
			if(my $username = $data->login_apikey($1)){
				$self->{logger}->log("$username apikey " . substr($1, 0, 5) . "...\n") if $self->{logger};
				$env->{LOGIN} = $username;
				return $self->app->($env);
			}
			return [401, [], ["invalid apikey!"]];
		}
	}
	return $self->app->($env);
}

1;