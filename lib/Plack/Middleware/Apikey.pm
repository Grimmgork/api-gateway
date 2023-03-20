package Plack::Middleware::Apikey;
use parent qw(Plack::Middleware);

use HTML::Template;
use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	my $data = $self->{data};
	
	unless($env->{LOGIN}){
		if(my $apikey = $req->header("apikey")){
			if(my $username = $data->login_apikey($apikey)){
				print "logged in as $username with apikey $apikey\n";
				$env->{LOGIN} = $username;
			}
			return [401, [], []];
		}
	}
	return $self->app->($env);
}

1;