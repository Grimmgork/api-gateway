use Plack::Builder;
use Plack::Request;
use Plack::Response;
use Plack::App::Proxy;
use Plack::Util;
use URI;
use URI::Escape;

use lib './lib';

use Plack::Middleware::Apikey;
use Plack::Middleware::Login;
use Plack::Middleware::Sentinel;
use Plack::Middleware::ReqLog;

use Plack::App::Redirect;

use Data;
use SysLogger;

use constant MCLIPD_HOST	 => "http://127.0.0.1:5000";
use constant LOGD_HOST    => "http://127.0.0.1:5500";
use constant FILE_POLICY	 => "./policy.txt";
use constant FILE_LOGIN   => "./templates/login.html";

use constant DATA => Data->new("state.db");

use constant LOG_REQUEST => SysLogger->new("request", "local0", "debug");
use constant LOG_LOGIN   => SysLogger->new("login", "local0", "info");

my $mount_redirect_host = sub { # rewrite redirects from proxy to mount on own host
     my $app = shift;
     sub {
          my $env = shift;
		return Plack::Util::response_cb($app->($env), sub {
			my $res = shift;
			my %rules = (
				&MCLIPD_HOST => "/mclip",
				&LOGD_HOST   => "/logd"
			);
			if(my $loc = Plack::Util::header_get($res->[1], "location")){
				foreach my $host (keys %rules)
				{
					my $mount = $rules{$host};
					$loc =~ s/^${host}/${mount}/;
					Plack::Util::header_set($res->[1], "location", $loc);
				}
			}
		});
     };
};

my $red_to_login = sub { # redirect to login page if login is missing
	my $app = shift;
	sub {
		my $env = shift;
		my $req = Plack::Request->new($env);
		unless($env->{"login"}) {
			my $redirect = uri_escape(URI->new($req->uri)->path_query);
			return [307, ["location" => "/login?redirect=$redirect"], []];
		}
     	return $app->($env);
	};
};

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

builder {
	enable "Plack::Middleware::ReqLog", logger => LOG_REQUEST;
	enable "Plack::Middleware::Apikey", data => DATA, env_login => "login"; # apikey login
	enable "Plack::Middleware::Login", data => DATA, env_login => "login", page_content => \&login_page, redirect => "/mclip"; # login
	enable $red_to_login;
	enable $log_login;
	enable "Plack::Middleware::Sentinel", data => DATA, env_login => "login", file => FILE_POLICY; # authorization
	enable $mount_redirect_host;
	mount "/mclip" => Plack::App::Proxy->new(remote => MCLIPD_HOST)->to_app;
	mount "/logd" => Plack::App::Proxy->new(remote => LOGD_HOST)->to_app;
};

sub login_page {
	my $templ = HTML::Template->new(filename => FILE_LOGIN, cache => 1);
	$templ->param(REDIRECT => shift);
	return $templ->output;
}