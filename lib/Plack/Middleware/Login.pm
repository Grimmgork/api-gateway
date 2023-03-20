package Plack::Middleware::Login;
use parent qw(Plack::Middleware);

use MIME::Base64;
use HTML::Template;
use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	my $data = $self->{data};

	return $self->app->($env) if $env->{LOGIN}; # nothing to do here, next middleware

	# try login with token
	my $login_token;
	if(my $token = $req->cookies->{token}){
		if(my $uname = authenticate_token($data, $token)){
			$env->{LOGIN} = $uname;
			$login_token = $token;
		}
	}

	if($req->path eq "/login"){
		if($req->method eq "GET"){
			# login page
			if($login_token){ # logout if logged in
				$data->remove_token($login_token);
			}
			my $referer = $req->query_parameters->{"referer"};
			return [200, ["content-type" => "text/html", "set-cookie" => "token="], [$self->{page_content}->({ referer => $referer })]];
		}

		if($req->method eq "POST"){
			# authenticate with credentials and return token as cookie
			if($req->headers->header('auth') =~ m/^([a-z0-9-_]+):([a-z0-9=+\/]+)$/i){
				if(my $login = $data->login_password($1, decode_base64($2))){
					print "logged in as $login!\n";
					$env->{logger}->log("logged in as $login") if $env->{logger};
					my $token = $data->add_new_token($login, time() + 60*5);
					return [200, ["set-cookie" => "token=$token", "content-type" => "text/plain"], ["login successful!"]];
				}
				return [401, ["content-type" => "text/plain"], ["invalid credentials!"]];
			}
			return [400, ["content-type" => "text/plain"], ["malformed request!"]];
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