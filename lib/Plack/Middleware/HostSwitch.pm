package Plack::Middleware::HostSwitch;
use parent qw(Plack::Middleware);

use HTML::Template;
use Plack::Util;
use MIME::Base64;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	if($req->uri->host eq "mclip.grmgrk.com"){
		return $self->{next}->($env);
	}
	return $self->app->($env);
}

1;