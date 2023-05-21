package Plack::Middleware::Sentinel;
use parent qw(Plack::Middleware);
use Plack::Request;
use Plack::Util;

use Plack::Middleware::ReqMatch;

sub call {
	my($self, $env) = @_;
	my $permissions = $env->{'sentinel.permissions'};
	my $perm = $self->{perm};
	
	return [401, [], ["unauthenticated!"]] unless $permissions;
	return $self->app->($env) unless $perm;
	foreach(@$permissions){
		return $self->app->($env) if $_ eq $perm;
	}
	return [403, [], ["forbidden!"]];
}

1;