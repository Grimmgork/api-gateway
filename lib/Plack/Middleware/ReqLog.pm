package Plack::Middleware::ReqLog;
use parent qw(Plack::Middleware);
use Plack::Util;
use Sys::Syslog;
 
sub call {
	my($self, $env) = @_;
	if($self->{logger}){
		my $req = Plack::Request->new($env);

		my $addr = $req->header("X-Forwarded-For") || $req->address;
		my $method = $req->method;
		my $path = $req->path;

		$self->{logger}->log("$addr $method $path");
	}
	return $self->app->($env);
}

1;