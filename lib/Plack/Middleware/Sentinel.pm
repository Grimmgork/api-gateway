package Plack::Middleware::Sentinel;
use parent qw(Plack::Middleware);
use Plack::Request;
use Plack::Util;

sub call {
	my($self, $env) = @_;

	unless($env->{'sentinel'}) { # if data isnt already queried ...
		# query it
		my $get_uid = $self->{get_uid};
		my $get_permissions = $self->{get_permissions};

		my $uid = $get_uid->($env);
		$env->{'sentinel'} = {
			uid => $uid,
			permissions => $get_permissions->($uid)
		};
	}

	my $req_perm = $self->{perm};

	my $perms = $env->{'sentinel'}->{permissions};
	my $uid   = $env->{'sentinel'}->{uid};
	
	return [401, [], ["unauthenticated!"]] unless $uid; # not logged in

	return $self->app->($env) unless $req_perm; # skip if no required permission was given
	foreach(@$perms){
		return $self->app->($env) if $_ eq $req_perm;
	}
	return [403, [], ["forbidden!"]];
}

1;