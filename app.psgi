use Plack::Builder;
use Plack::App::File;

use lib './lib';
use Plack::Middleware::Authentication::Auth;
use Plack::Middleware::Authentication::Login;
use Plack::Middleware::Authorization::Sentinel;
use Plack::Request;

my $mclip = sub {
    my $env = shift;
    # ...
    return [ 200, ["content-type" => "text/plain"], ["hello there from mclip!"] ];
};

my $mlog = sub {
    my $env = shift;
    # ...
    return [ 200, ["content-type" => "text/plain"], ["hello there from mlog!"] ];
};

builder {
	mount "/login.html" => Plack::App::File->new(file => './static/login.html')->to_app;
	mount "/favicon.ico" => Plack::App::File->new(file => './static/favicon.ico')->to_app;
	mount "/login" => builder{
		enable "Plack::Middleware::Authentication::Login", loginpage => "/login.html"; # is not a real middleware??
	};

	mount "/private" => builder {
		enable "Plack::Middleware::Authentication::Auth", file => "./login.txt"; # authentication
		enable "Plack::Middleware::Authorization::Sentinel", file => "./policy.txt"; # check authorization
		mount "/mclip" => $mclip;
		mount "/log" => $mlog;
	};
};
