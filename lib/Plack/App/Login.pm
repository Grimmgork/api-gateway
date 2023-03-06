package Plack::App::Login;
use parent qw(Plack::Component); # inherit from plack::component

use Plack::Util;

sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);

	if($env->{REQUEST_METHOD} eq "GET"){
		return [307, ["location" => $self->{loginpage}], []];
	}

	if($env->{REQUEST_METHOD} eq "POST" and $env->{HTTP_AUTH} =~ m/^([a-z0-9-_]+):([a-z0-9-_]+)$/i){
		my $data = $self->{data};
		if($data->authenticate($1, $2)){
			print "logged in as $1!\n";
			my $token = $data->add_new_token($1, time() + 60*60);
			return [200, ["set-cookie" => "token=$token"], ["logged in!"]];
		}
	}

	return [401, [],["unauthorized!"]];
}

1;