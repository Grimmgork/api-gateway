package Plack::Middleware::Sentinel;
use parent qw(Plack::Middleware);
use Plack::Request;
use Plack::Util;

use Plack::Middleware::ReqMatch;

sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	my $group = $self->{group};
	my $env_login = $self->{env_login};

	# group:group:group

	my $uname = $env->{$env_login};
	return [401, [], ["unauthenticated!"]] unless $uname;

	my @groups = $data->get_user_groups($uname);
	return $self->app->($env) unless $group;
	return $self->app->($env) if grep(/^$group$/, @groups);
	return [403, [], ["forbidden!"]];
}

sub valid_request {
	my ($file, $groups_ref, $method, $path) = @_;
	my @segments = split "/", $path;
	@segments = grep { $_ ne '' } @segments;
	return Plack::Middleware::ReqMatch::match_request($file, $groups_ref, $method, @segments);
}

1;