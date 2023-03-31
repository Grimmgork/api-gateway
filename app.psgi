use Plack::Builder;
use Plack::Request;
use Plack::Response;
use Plack::App::File;
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
use constant ENV_USERID   => "login";
use constant FILE_POLICY	 => "./policy.txt";
use constant FILE_FAVICON => "./public/favicon.ico";
use constant FILE_LOGIN   => "./templates/login.html";
use constant STATIC_ROOT  => "./public";

use constant DATA => Data->new("state.db");

use constant LOG_REQUEST => SysLogger->new("request", "local0", "debug");
use constant LOG_LOGIN   => SysLogger->new("login", "local0", "info");
use constant LOG_APIKEY  => SysLogger->new("login", "local0", "info");

#my $mclip = sub {
#     my $env = shift;
#	return [ 200, ["content-type" => "text/plain"], ["hello from the mclip service!"] ];
#};

my $loc_proxy = sub { # rewrite redirects from proxy to own host
     my $app = shift;
     sub {
          my $env = shift;
		return Plack::Util::response_cb($app->($env), sub {
			my $res = shift;
			my $host = MCLIPD_HOST;
			my $mount = "/api/mclip";
			if($res->[0] == 307){
		 		if(Plack::Util::header_exists($res->[1], "location")) {
					my $loc = Plack::Util::header_get($res->[1], "location");
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
		unless($env->{&ENV_USERID}) {
			print "no login!\n";
			my $redirect = uri_escape(URI->new($req->uri)->path_query);
			return [307, ["location" => "/api/login?redirect=$redirect"], []];
		}
     	return $app->($env);
	};
};

my $test = sub {
     my $env = shift;
     return sub {
     	my $res = shift;
     	my $w = $res->([200, [ 'Content-Type' => 'text/plain', 'X-Content-Type-Options' => 'nosniff', 'cache-control' => "no-cache" ]]);
     	foreach(1..5){
               # sleep 0.3;
          	$w->write("this is a chunk ~ !\n");
     	}
     	$w->close();
	};
};


builder {
	enable "Plack::Middleware::ReqLog", logger => LOG_REQUEST;
	mount "/favicon.ico" => Plack::App::File->new(file => FILE_FAVICON)->to_app;
	mount "/static" => Plack::App::File->new(root => STATIC_ROOT)->to_app;
	mount "/api" => builder {
		enable "Plack::Middleware::Apikey", data => DATA, env_login => ENV_USERID, logger => LOG_APIKEY; # apikey login
		enable "Plack::Middleware::Login", data => DATA, env_login => ENV_USERID, page_content => \&login_page, logger => LOG_LOGIN, redirect => "/api/mclip"; # login
		enable $red_to_login;
		enable "Plack::Middleware::Sentinel", data => DATA, env_login => ENV_USERID, file => FILE_POLICY; # authorization
		enable $loc_proxy;
		mount "/mclip" => $test; # Plack::App::Proxy->new(remote => MCLIPD_HOST, preserve_host_header => 1)->to_app;
	}
};

sub login_page {
	my $templ = HTML::Template->new(filename => FILE_LOGIN);
	$templ->param(REDIRECT => shift);
	return $templ->output;
}