package Plack::App::Redirect;
use parent qw(Plack::Component);

use Plack::Util;
 
sub call {
	my($self, $env) = @_;
	my $req = Plack::Request->new($env);
	return [307, ["location" => $self->{url}], []];
}

1;