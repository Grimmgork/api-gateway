package Plack::Middleware::Sentinel;
use parent qw(Plack::Middleware);
use Plack::Request;
use Plack::Util;

use Plack::Middleware::ReqMatch;

sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	my $data = $self->{data};

	my $uname = $env->{LOGIN};
	return [401, [], ["unauthorized!"]] unless $uname;

	my @groups = $data->get_user_groups($uname);
	return $self->app->($env) if valid_request($self->{file}, \@groups, $req->method, $req->path);
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