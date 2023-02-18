use Plack::Builder;
use Plack::App::File;

use lib './lib';
use Plack::Middleware::MyAuth::Auth;
use Plack::Middleware::MyAuth::Login;
use Plack::Middleware::MyPolicy;
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
		enable "Plack::Middleware::MyAuth::Login", loginpage => "/login.html"; # is not a real middleware??
	};

	mount "/private" => builder {
		enable "Plack::Middleware::MyAuth::Auth", file => "./login.txt"; # authentication
		enable "Plack::Middleware::MyPolicy", file => "./policy.txt"; # check authorization
		mount "/mclip" => $mclip;
		mount "/log" => $mlog;
	};
};