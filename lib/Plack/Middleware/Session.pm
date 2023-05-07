package Plack::Middleware::Session;
use parent qw(Plack::Middleware);
use Cookie::Baker;
use Switch;

use Plack::Util;

sub call {
	my($self, $env) = @_;
	my $store = $self->{store};
	my $req = Plack::Request->new($env);

	if(my $id = $req->cookies->{'session'}){
		if(my $session = $store->deserialize($id)){
			$env->{'psgix.session.id'} = $id;
			$env->{'psgix.session'} = $session;
		}
	}

	my $res = $self->app->($env);
	$self->response_cb($res, sub {
     	my $res = shift;
		my $session = $env->{'psgix.session'};
		return unless $session;

		my $option = $env->{'psgix.session.option'};
		if($option eq 'rotate') {
			$env->{'psgix.session.id'} = $store->rotate($env->{'psgix.session.id'});
		} elsif($option eq 'create') {
			$env->{'psgix.session.id'} = $store->create($session);
		} elsif($option eq 'destroy') {
			$store->destroy($env->{'psgix.session.id'});
			return;
		}

		if(my $id = $env->{'psgix.session.id'}){
			$store->serialize($id, $session);
			my $cookie = bake_cookie('session', {
    				value => $id,
				domain => $self->{domain} || "",
				httponly => $self->{httponly}
			});
			$h = HTTP::Headers->new($res->[1]);
			$h->push_header('set-cookie' => $cookie);
			my @headers = $h->flatten();
			$res->[1] = \@headers;
		}
	});
}

1;