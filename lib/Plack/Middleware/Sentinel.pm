package Plack::Middleware::Sentinel;
use parent qw(Plack::Middleware);
use Plack::Request;
use Plack::Util;

use Plack::Middleware::ReqMatch;

sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	return $self->app->($env) if valid_request($self->{file}, $env->{GROUPS}, $req->method, $req->path);
	return [403, [], ["forbidden!"]];
}

sub valid_request {
	my ($file, $groups_ref, $method, $path) = @_;
	my @segments = split "/", $path;
	@segments = grep { $_ ne '' } @segments;
	print "array: $groups_ref\n";
	return Plack::Middleware::ReqMatch::match_request($file, $groups_ref, $method, @segments);
}

1;