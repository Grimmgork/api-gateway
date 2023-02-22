package Plack::Middleware::Chunked;
use strict;
use parent qw(Plack::Middleware);

use Plack::Util;

sub call {
    my($self, $env) = @_;
    my $res = $self->app->($env);
    $self->response_cb($res, sub {
        my $res = shift;
        my $h = Plack::Util::headers($res->[1]);
        if ($env->{'SERVER_PROTOCOL'} ne 'HTTP/1.0' and
            ! Plack::Util::status_with_no_entity_body($res->[0]) and
            ! $h->exists('Content-Length') and
            ! $h->exists('Transfer-Encoding')
        ) {
            $h->set('Transfer-Encoding' => 'chunked');
            my $done;
            return sub {
                my $chunk = shift;
			 print "hello from chunked!\n";
                return if $done;
                unless (defined $chunk) {
                    $done = 1;
                    return "0\015\012\015\012";
                }
                return '' unless length $chunk;
                return sprintf('%x', length $chunk) . "\015\012$chunk\015\012";
            };
        }
    });
}

1;