package Plack::Middleware::Token;
use parent qw(Plack::Middleware);
use Cookie::Baker;

use Plack::Util;

sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	if(my $token = $req->cookies->{'token'}){
		if(my $uname = $self->{get_login}($token)){
			$env->{'login'} = $uname;
			$env->{'token'} = $token;
		}
	}

	my $res = $self->app->($env);
	$self->response_cb($res, sub {
     	my $res = shift;
		if(my $token = $env->{'token'}){
			my $cookie = bake_cookie('token', {
    				value => $env->{'token'} || "",
				domain => $self->{domain} || "",
				httponly => 1
			});
			$h = HTTP::Headers->new($res->[1]);
			$h->push_header( 'set-cookie' => $cookie );
			my @headers = $h->flatten();
			$res->[1] = \@headers;
		}
	});
}

1;