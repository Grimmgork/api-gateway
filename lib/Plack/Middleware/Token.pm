package Plack::Middleware::Token;
use parent qw(Plack::Middleware);

use HTML::Template;
use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	my $data = $self->{data};

	unless($env->{LOGIN}){
		if(my $token = $req->cookies->{token}){
			if(my $uname = authenticate_token($data, $token)){
				$env->{LOGIN} = $uname;
				$env->{TOKEN} = $token; # add token reference for logging out
			}
		}
	}

	return $self->app->($env);
}

sub authenticate_token {
	my $data = shift;
	my $token = shift;

	return undef unless $token =~ m/^[a-z0-9_-]+$/i;
	if(my @fields = $data->find_token($token)){
		shift @fields;
		my $uname = shift @fields;
		my $exptime = shift @fields;

		# check for expiration delete if expired
		if(time() > $exptime){
			$data->remove_token($token);
			return undef;
		}

		return $uname;
	}

	return undef;
}

1;