use Plack::Builder;
use Plack::App::File;

use lib './lib';
use Plack::Middleware::Auth;
use Plack::App::Login;
use Plack::Middleware::Sentinel;
use Plack::Request;

my $mclip = sub {
    my $env = shift;
    # ...
    return [ 200, ["content-type" => "text/plain"], ["hello there from mclip!"] ];
};

my $test = sub {
	my $env = shift;
	open(my $fh, '<', "./static/lorem.txt") or die $!;
	return sub {
        my $res = shift;
        my $w = $res->([200, [ 'Content-Type', 'application/json' ]]);
        while(<$fh>){
			$w->write($_);
	   }
	   close $fh;
        $w->close();
    };
};

builder {
	mount "/login.html" => Plack::App::File->new(file => './static/login.html')->to_app;
	mount "/favicon.ico" => Plack::App::File->new(file => './static/favicon.ico')->to_app;
	mount "/login" => builder{
		 Plack::App::Login->new(loginpage => "/login.html")->to_app; # is not a real middleware??
	};

	mount "/private" => builder {
		enable "Plack::Middleware::Auth", file => "./login.txt"; # authentication
		enable "Plack::Middleware::Sentinel", file => "./policy.txt"; # check authorization
		mount "/mclip" => $mclip;
	};

	mount "/test" => builder {
		enable "Plack::Middleware::Chunked";
		$test;
	};
};
