package Plack::Middleware::Login;
use parent qw(Plack::Middleware);

use MIME::Base64;
use HTML::Template;
use Plack::Util;
use URI;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	my $data = $self->{data};
	my $env_login = $self->{env_login} || "login";

	return $self->app->($env) if $env->{$env_login}; # nothing to do here, next middleware

	# try login with token
	my $login_token;
	if(my $token = $req->cookies->{token}){
		if(my $uname = authenticate_token($data, $token)){
			$env->{$env_login} = $uname;
			$login_token = $token;
		}
	}

	if($req->path eq "/login"){
		if($req->method eq "GET"){
			# login page
			if($login_token){ # logout if logged in
				$data->remove_token($login_token);
			}
			my $url = URI->new($req->query_parameters->{"redirect"} || $self->{redirect} || "/");
			return [400, ["content-type" => "text/plain"], ["malformed request!"]] if $url->path eq "/login"; # prevent a login, logout loop ...
			return [200, ["content-type" => "text/html", "set-cookie" => "token=", "cache-control" => "no-cache"], [$self->{page_content}->($url->path_query)]];
		}

		if($req->method eq "POST"){
			# authenticate with credentials and return token as cookie
			if($req->headers->header('authorization') =~ m/^basic +([a-z0-9+\/]+=*)$/i){
				my ($uname, $pwd) = split ":", decode_base64($1), 2;
				if(my $login = $data->login_password($uname, $pwd)){
					print "logged in as $login!\n";
					$self->{logger}->log("$login") if $self->{logger};
					my $token = $data->add_new_token($login, time() + 60*60*60);
					return [200, ["set-cookie" => "token=$token; httponly; SameSite=Strict", "content-type" => "text/plain"], ["login successful!"]];
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