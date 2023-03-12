use Plack::Builder;
use Plack::App::File;

use lib './lib';
use Data;

use Plack::Middleware::Auth;
use Plack::App::Login;
use Plack::App::Proxy;
use Plack::Middleware::Sentinel;
use Plack::Request;

use constant MCLIPD_HOST	=> "http://127.0.0.1:5000";
use constant FILE_POLICY	=> "policy.txt";
use constant FILE_DB	=> "state.db";

use constant DATA => Data->new(FILE_DB);


print "starting ...\n";
foreach(1..3000){
	DATA->get_user_groups("root");
}
print "done!\n";

my $mclip = sub {
     my $env = shift;
	return [ 200, ["content-type" => "text/plain"], ["hello there from mclip!"] ];
};

builder {
	mount "/favicon.ico" => Plack::App::File->new(file => './static/favicon.ico')->to_app;
	mount "/static" => Plack::App::File->new(root => "./static")->to_app;
	mount "/api" => builder {
		enable "Plack::Middleware::Auth", data => $data; # authentication
		enable "Plack::Middleware::Sentinel", file => FILE_POLICY; # authorization
		mount "/mclip" => $mclip; # Plack::App::Proxy->new(remote => MCLIPD_HOST)->to_app;
	}
};