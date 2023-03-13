package Plack::Middleware::CondRedirect;
use parent qw(Plack::Middleware);
use Plack::Request;
use Plack::Util;

sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);

	my $no_apikey;
	$no_apikey = 1 unless $req->header("apikey");
	my $res = $self->app->($env);
	if($res->[0] == 401 and $no_apikey){
		return [307, ["location" => "/login"], []];
	}
	
	return $res; # normal behavior
}

1;