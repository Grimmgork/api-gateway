use Plack::Builder;
use Plack::Request;
use Plack::App::File;
use Plack::App::Proxy;
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
use constant FILE_POLICY	 => "./policy.txt";
use constant FILE_FAVICON => "./public/favicon.ico";
use constant FILE_LOGIN   => "./templates/login.html";
use constant STATIC_ROOT  => "./public";

use constant DATA => Data->new("state.db");
use constant LOG_LOGIN => SysLogger->new("login", "local0", "notice");

my $mclip = sub {
     my $env = shift;
	return [ 200, ["content-type" => "text/plain"], ["hello from the mclip service!"] ];
};

builder {
	enable "Plack::Middleware::ReqLog", logger => SysLogger->new("request", "local0", "debug");
	mount "/favicon.ico" => Plack::App::File->new(file => FILE_FAVICON)->to_app;
	mount "/static" => Plack::App::File->new(root => STATIC_ROOT)->to_app;
	mount "/login" => Plack::App::Redirect->new(location => "/api/login")->to_app;
	mount "/api" => builder {
		enable "Plack::Middleware::Apikey", data => DATA, logger => SysLogger->new("login", "local0", "info");
		enable "Plack::Middleware::Login", data => DATA, page_content => \&login_page, logger => SysLogger->new("login", "local0", "info"), redirect => "/api/mclip";
		enable sub { # redirect to login page if login is missing
			my $app = shift;
			sub {
				my $env = shift;
				my $req = Plack::Request->new($env);
				unless($env->{LOGIN}){
					my $redirect = uri_escape(URI->new($req->uri)->path_query);
					return [307, ["location" => "/api/login?redirect=$redirect"], []];
				}
     			return $app->($env);
			};
		};
		enable "Plack::Middleware::Sentinel", data => DATA, file => FILE_POLICY; # authorization
		mount "/mclip" => $mclip;
		# mount "/mclip" => Plack::App::Proxy->new(remote => MCLIPD_HOST)->to_app;
	}
};

sub login_page {
	my $templ = HTML::Template->new(filename => FILE_LOGIN);
	$templ->param(REDIRECT => shift);
	return $templ->output;
}