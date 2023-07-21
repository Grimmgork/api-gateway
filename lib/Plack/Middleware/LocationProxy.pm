package Plack::Middleware::LocationProxy;
use parent qw(Plack::Middleware);

use Plack::Util;
use HTTP::Headers;
 
sub call {
	my($self, $env) = @_;
	my $res = $self->app->($env);
	return $self->response_cb($res, sub {
        	my $res = shift;

		my $headers = $res->[1];
		my $h = HTTP::Headers->new(@$headers);
		
		if($_ = $h->header('Location')){
			my $replace = $self->{host};
			s/$replace//ee;
			$h->header('Location' => $_);
		}
		$res->[1] = [$h->flatten()];
    	});
}

1;