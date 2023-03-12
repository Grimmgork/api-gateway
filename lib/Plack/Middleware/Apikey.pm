package Plack::Middleware::Apikey;
use parent qw(Plack::Middleware);

use HTML::Template;
use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	my $data = $self->{data};

	return undef;
	
}

1;