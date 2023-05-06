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
use Plack::Middleware::HostSwitch;

use Plack::App::Redirect;

use Data;
use SysLogger;

use constant HOST_MCLIPD  => "http://127.0.0.1:5000";
use constant HOST_LOGD    => "http://127.0.0.1:5500";
use constant FILE_POLICY	 => "./policy.txt";
use constant FILE_LOGIN   => "./templates/login.html";

use constant DATA => Data->new("state.db");

use constant LOG_REQUEST => SysLogger->new("request", "local0", "debug");
use constant LOG_LOGIN   => SysLogger->new("login", "local0", "info");

use constant GROUP_MCLIP_OWNER => "mclip_owner";
use constant GROUP_LOGD_OWNER => "mclip_owner";

my $mount_redirect_host = sub { # rewrite redirects from proxy to mount on own host
     my $app = shift;
     sub {
          my $env = shift;
		return Plack::Util::response_cb($app->($env), sub {
			my $res = shift;
			my %rules = (
				&HOST_MCLIPD => "/mclip",
				&HOST_LOGD   => "/logd"
			);
			if(my $loc = Plack::Util::header_get($res->[1], "location")){
				foreach my $host (keys %rules) {
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

my $app = sub {
     my $env = shift;
     return [ 200, ["content-type" => "text/plain"], ["hello there!"] ];
};

my $mclip = builder {
	enable "Sentinel", group => GROUP_MCLIP_OWNER;
	Plack::App::Proxy->new(remote => HOST_MCLIPD)->to_app;
};

my $logd = builder {
	enable "Sentinel", group => GROUP_LOGD_OWNER;
	Plack::App::Proxy->new(remote => HOST_LOGD)->to_app;
};

builder {
	enable "ReqLog", logger => LOG_REQUEST;
	enable "Apikey", data => DATA; # apikey login
	enable "Login", data => DATA, page_content => \&login_page, redirect => "/"; # login
	enable $red_to_login;
	enable $log_login;
	enable "Sentinel"; # authenticated?
	enable "HostSwitch", host => "mclip.grmgrk.com", next => $mclip; # mclip 
	enable "HostSwitch", host => "logd.grmgrk.com", next => $logd; # logd
	sub {
		return [ 404, ["content-type" => "text/plain"], ["nothing to see here ..."]];
	};
};

sub login_page {
	my $templ = HTML::Template->new(filename => FILE_LOGIN);
	$templ->param(REDIRECT => shift);
	return $templ->output;
}