use Plack::Builder;
use Plack::Request;
use Plack::Response;
use Plack::App::Proxy;
use Plack::Util;
use URI;
use URI::Escape;
use MIME::Base64;
use Bytes::Random::Secure qw(random_string_from);

use lib './lib';

use Plack::Middleware::Token;
use Plack::Middleware::Sentinel;
use Plack::Middleware::ReqLog;
use Plack::Middleware::HostSwitch;

use Data; 
use SysLogger;

use constant HOST_MCLIPD  => "http://127.0.0.1:5000";
use constant HOST_LOGD    => "http://127.0.0.1:5500";
use constant DOMAIN		 => "grmgrk.com";
use constant FILE_LOGIN   => "./templates/login.html";

use constant DATA => Data->new("state.db");

use constant LOG_REQUEST => SysLogger->new("request", "local0", "debug");
use constant LOG_LOGIN   => SysLogger->new("login", "local0", "info");


my $log_login = sub {
	my $app = shift;
	sub {
		my $env = shift;
		if(my $login = $env->{"login"}){
			LOG_LOGIN->log($login);
		}
		return $app->($env);
	};
};

my $rotate_token = sub {
	my $app = shift;
	sub {
		my $env = shift;
		if(my $token = $env->{'token'}){
			$env->{'token'} = DATA->rotate_token($token, new_tokenid());
		}
		return $app->($env);
	};
};

my $apikey = sub {
	my $app = shift;
	sub {
		my $env = shift;
		my $req = Plack::Request->new($env);
		return $app->($env) if $env->{'login'};
		if($req->headers->header('authorization') =~ m/^bearer +([a-z0-9]+)$/i){
			if(my $uname = DATA->login_apikey($1)){
				$env->{'login'} = $uname;
				return $app->($env);
			}
			return [401, [], ["invalid apikey!"]];
		}
		return $app->($env);
	};
};

my $permissions = sub {
	my $app = shift;
	sub {
		my $env = shift;
		if(my $uname = $env->{'login'}){
			my @groups = DATA->get_user_groups($uname);
			$env->{'permissions'} = \@groups;
		}
		return $app->($env);
	};
};

sub template_login_page {
	my $templ = HTML::Template->new(filename => FILE_LOGIN);
	$templ->param(REDIRECT => shift);
	return $templ->output;
}

my $login = sub {
	my $app = shift;
	sub {
		my $env = shift;
		return $app->($env) if $env->{'login'};

		my $req = Plack::Request->new($env);
		if($req->method eq "GET" and $req->path eq "/login"){
			if(my $token = $env->{'token'}){
				DATA->remove_token($token);
				$env->{'token'} = undef;
			}
			my $url = URI->new($req->query_parameters->{"redirect"} || $self->{redirect} || "/");
			if($url->path eq "/login") { # prevent a login, logout loop ...
				return [400, ["content-type" => "text/plain"], ["malformed request!"]];
			} 
			return [200, ["content-type" => "text/html", "cache-control" => "no-cache"], [template_login_page($url->path_query)]];
		}

		if($req->method eq "POST" and $req->path eq "/login"){
			# authenticate with credentials and return token as cookie
			if($req->headers->header('authorization') =~ m/^basic +([a-z0-9+\/]+=*)$/i){
				my ($uname, $pwd) = split ":", decode_base64($1), 2;
				if(my $login = DATA->login_password($uname, $pwd)){
					print "logged in as $login!\n";
					$env->{'token'} = DATA->add_new_token(new_tokenid(), $login, time() + 60*10);
					return [200, ["content-type" => "text/plain"], ["login successful!"]];
				}
				return [401, ["content-type" => "text/plain"], ["invalid credentials!"]];
			}
			return [400, ["content-type" => "text/plain"], ["malformed request!"]];
		}

		unless($env->{"login"}) {
			my $redirect = uri_escape(URI->new($req->uri)->path_query);
			return [307, ["location" => "/login?redirect=$redirect"], []];
		}
		return $app->($env);
	};
};

my $mclip = builder {
	enable "Sentinel", key => "permissions", perm => "mclip_owner";
	Plack::App::Proxy->new(remote => HOST_MCLIPD)->to_app;
};

my $logd = builder {
	enable "Sentinel", key => "permissions", perm => "logd_owner";
	Plack::App::Proxy->new(remote => HOST_LOGD)->to_app;
};

builder {
	enable "ReqLog", logger => LOG_REQUEST;
	enable $apikey;
	enable "Token", get_login => \&authenticate_token, domain => DOMAIN;
	enable $rotate_token;
	enable $login;
	enable $log_login;
	enable $permissions; # load permissions to env
	enable "Sentinel", key => "permissions"; # authenticated?
	enable "HostSwitch", host => "mclip.".DOMAIN, next => $mclip; # mclip 
	enable "HostSwitch", host => "log.".DOMAIN, next => $logd; # logd
	sub {
		return [ 404, ["content-type" => "text/plain"], ["nothing to see here ..."]];
	};
};

sub new_tokenid {
	return random_string_from("abcdefghijklmnopqrstuvwxyz0123456789_-", 15);
}

sub authenticate_token {
	my $token = shift;
	return undef unless $token =~ m/^[a-z0-9_-]+$/i;
	if(my @fields = DATA->find_token($token)){
		shift @fields;
		my $uname = shift @fields;
		my $exptime = shift @fields;

		# check for expiration delete if expired
		if(time() > $exptime){
			DATA->remove_token($token);
			return undef;
		}

		return $uname;
	}
	return undef;
};