use Plack::Builder;
use Plack::Request;
use Plack::App::File;
use Plack::App::Proxy;
use Bytes::Random::Secure qw(random_string_from);
use MIME::Base64;

use lib './lib';

use Plack::Middleware::Apikey;
use Plack::Middleware::Token;
use Plack::Middleware::Sentinel;
use Plack::Middleware::ReqLog;

use Plack::App::Redirect;

use Data;
use SysLogger;

use constant MCLIPD_HOST	=> "http://127.0.0.1:5000";
use constant FILE_POLICY	=> "policy.txt";
use constant FILE_DB	=> "state.db";

use constant DATA => Data->new(FILE_DB);
use constant LOG_LOGIN => SysLogger->new("login", "local0", "notice");

my $mclip = sub {
     my $env = shift;
	return [ 200, ["content-type" => "text/plain"], ["hello from the mclip service!"] ];
};

my $login = sub { # todo referer location as query parameter
	my $env = shift;
	my $req = Plack::Request->new($env);

	# loginpage
	if($req->method eq "GET"){
		# logout if already logged in
		if(my $token = $env->{TOKEN}){
			DATA->remove_token($token);
		}

		my $tmpl = new HTML::Template(filename => "./templates/login.html");
		return [200, ["content-type" => "text/html"], [$tmpl->output]];
	}

	# login
	if($req->method eq "POST" ){
		# remove token if it already has one
		if(my $token = $env->{TOKEN}){
			DATA->remove_token($token);
		}
		if($req->headers->header('auth') =~ m/^([a-z0-9-_]+):([a-z0-9=+\/]+)$/i){
			if(DATA->login_password($1, decode_base64($2))){
				print "logged in as $1!\n";
				LOG_LOGIN->log("login as $1");
				my $token = generate_new_token();
				DATA->add_new_token($token, $1, time() + 60*5);
				return [200, ["set-cookie" => "token=$token", "content-type" => "text/plain"], ["login successful!"]];
			}
			return [401, ["content-type" => "text/plain"], ["invalid credentials!"]];
		}
		return [400, ["content-type" => "text/plain"], ["malformed request!"]];
	}
	return [404, [], []];
};

sub generate_new_token {
	return random_string_from("abcdefghijklmnopqrstuvwxyz0123456789_-", 15);
}

builder {
	enable "Plack::Middleware::ReqLog", logger => SysLogger->new("request", "local0", "debug");
	enable "Plack::Middleware::Token", data => DATA, token_gen => \&generate_new_token;
	enable "Plack::Middleware::Apikey", data => DATA;
	mount "/favicon.ico" => Plack::App::File->new(file => './static/public/favicon.ico')->to_app;
	mount "/" => Plack::App::Redirect->new(redirect_url => "/static/index.html")->to_app;
	mount "/static" => Plack::App::File->new(root => "./static/public")->to_app;
	mount "/login" => $login;
	mount "/api" => builder {
		enable "Plack::Middleware::Sentinel", data => DATA, file => FILE_POLICY; # authorization
		# mount "/mclip" => Plack::App::Proxy->new(remote => MCLIPD_HOST)->to_app;
		mount "/mclip" => $mclip;
	}
};
