package Plack::Middleware::Authorization::Sentinel;
use parent qw(Plack::Middleware);
use Plack::Request;
use Plack::Util;

use Plack::Middleware::Authorization::ReqMatch;

sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	return $self->app->($env) if valid_request($self->{file}, $env->{GROUPS}, $req->method, $req->path);
	return [403, [], ["forbidden!"]];
}

sub valid_request {
	my ($file, $groups_ref, $method, $path) = @_;
	chomp $path;
	my @segments = grep { $_ ne '' } split "/", $path;
	return Plack::Middleware::Authorization::ReqMatch::match_request($file, $groups_ref, "get", @segments);
}

1;