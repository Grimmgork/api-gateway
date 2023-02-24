use Plack::Builder;
use Plack::App::File;

use lib './lib';
use Data;
use Plack::Middleware::Auth;
use Plack::App::Login;
use Plack::Middleware::Sentinel;
use Plack::Request;

my $mclip = sub {
    my $env = shift;
    # ... unshare()
    return [ 200, ["content-type" => "text/plain"], ["hello there from mclip!"] ];
};

my $data = Data->new("./login.txt", "./tokens.txt");

builder {
	mount "/login.html" => Plack::App::File->new(file => './static/login.html')->to_app;
	mount "/favicon.ico" => Plack::App::File->new(file => './static/favicon.ico')->to_app;
	mount "/login" => Plack::App::Login->new(data => $data)->to_app;

	mount "/private" => builder {
		enable "Plack::Middleware::Auth", data => $data; # authentication
		enable "Plack::Middleware::Sentinel", file => "./policy.txt"; # authorization
		mount "/mclip" => builder {
			mount "/" => $mclip;
		};
	};
};