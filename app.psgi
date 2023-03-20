use Plack::Builder;
use Plack::Request;
use Plack::App::File;
use Plack::App::Proxy;

use lib './lib';

use Plack::Middleware::Apikey;
use Plack::Middleware::Login;
use Plack::Middleware::Sentinel;
use Plack::Middleware::ReqLog;

use Plack::App::Redirect;

use Data;
use SysLogger;

use constant MCLIPD_HOST	=> "http://127.0.0.1:5000";
use constant FILE_POLICY	=> "./policy.txt";
use constant FILE_FAVICON => "./public/favicon.ico";
use constant STATIC_ROOT => "./public";

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
		enable "Plack::Middleware::Apikey", data => DATA;
		enable "Plack::Middleware::Login", data => DATA, page_content => \&generate_login_page, logger => SysLogger->new("login", "local0", "info");
		# login redirect
		enable "Plack::Middleware::Sentinel", data => DATA, file => FILE_POLICY; # authorization
		mount "/mclip" => $mclip;
		# mount "/mclip" => Plack::App::Proxy->new(remote => MCLIPD_HOST)->to_app;
	}
};

sub generate_login_page {
	my $templ = HTML::Template->new(filename => './templates/login.html');
	$templ->param(shift);
	return $templ->output;
}