package Plack::Middleware::MyPolicy;
use parent qw(Plack::Middleware);
use Plack::Util;
use ReqMatch;
use Plack::Request;

sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	return $self->app->($env) if valid_request($self->{file}, "mclip_owner", $req->method, $req->path);
	return [403, [], ["forbidden!"]];
}

sub valid_request {
	my ($file, $group, $method, $path) = @_;
	chomp $path;
	chomp $group;
	my @segments = grep { $_ ne '' } split "/", $path;
	print @segments, "$method $path $group\n";
	return ReqMatch::match($file, $group,"get", @segments);
}

1;