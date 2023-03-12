package Plack::Middleware::Auth;
use parent qw(Plack::Middleware);

use HTML::Template;
use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	my $data = $self->{data};

	# login
	if($req->path eq "/login"){
		# loginpage
		if($req->method eq "GET"){
			my $tmpl = new HTML::Template(filename => "./templates/login.tmpl.html");
			return [200, ["content-type" => "text/html"], [$tmpl->output]];
		}

		# login
		if($req->method eq "POST" ){
			if($req->headers->header('auth') =~ m/^([a-z0-9-_]+):([a-z0-9=+\/]+)$/i){
				print "$1 $2\n";
				if($data->authenticate($1, $2)){
					print "logged in as $1!\n";
					my $token = $data->add_new_token($1, time() + 60*60);
					return [200, ["set-cookie" => "token=$token", "content-type" => "text/plain"], ["logged in!"]];
				}
			}
			return [400, ["content-type" => "text/plain"], ["malformed password!"]];
		}
	}

	# token login
	if(my $token = $req->cookies->{token}){
		if(my $uname = authenticate_token($data, $token)){
			$env->{LOGIN} = $uname;
			$env->{GROUPS} = $data->get_user_groups($uname);

			# logout
			if($req->path eq "/logout"){
				$data->remove_token($token);
				return [200, ["content-type" => "text/plain"], ["logged out!"]];
			}

			return $self->app->($env);
		}
	}

	my $tmpl = new HTML::Template(filename => "./templates/login.tmpl.html");
	return [401, ["content-type" => "text/html"], [$tmpl->output]];
}

sub authenticate_token {
	my $data = shift;
	my $token = shift;

	return undef unless $token =~ m/^[a-z0-9_-]+$/i;
	if(my @fields = $data->get_token_fields($token)){
		my $uname = shift @fields;
		my $exptime = shift @fields;

		# check for expiration delete if expired
		if(time() > $exptime){
			$data->delete_token($token);
			return undef;
		}
			
		# delete token on x directive (onetime use)
		if(grep "x", @fields){
			$data->delete_token($token);
		}

		return $uname;
	}

	return undef;
}

1;