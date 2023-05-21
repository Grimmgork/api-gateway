package Plack::Middleware::HostSwitch;
use parent qw(Plack::Middleware);

use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	if($req->uri->host eq $self->{host}){
		return $self->{next}->($env);
	}
	return $self->app->($env);
}

1;