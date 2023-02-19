package Plack::Middleware::Authentication::Login;
use parent qw(Plack::Middleware);

use Plack::Middleware::Authentication::Data;
use Plack::Util;

sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	print $req->path, "\n";

	if($env->{REQUEST_METHOD} eq "GET"){
		return [307, ["location" => $self->{loginpage}], []];
	}

	if($env->{REQUEST_METHOD} eq "POST" and $env->{HTTP_AUTH} =~ m/^([^\s:]+):([^\s:]+)$/){
		if(Plack::Middleware::Authentication::Data::authenticate("./login.txt", $1, $2)){
			my $token = Plack::Middleware::Authentication::Data::add_new_token("./tokens.txt", $1, time() + 60*60);
			return [200, ["set-cookie" => "token=$token"], ["logged in!"]];
		}
	}
	return [401, [],["unauthorized!"]];
}

1;