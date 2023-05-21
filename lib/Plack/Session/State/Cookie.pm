package Plack::Session::State::Cookie;
use strict;
use warnings;

our $VERSION   = '0.33';
our $AUTHORITY = 'cpan:STEVAN';

use parent 'Plack::Session::State';
use Cookie::Baker;
use Plack::Util;

use Plack::Util::Accessor qw[
    path
    domain
    expires
    secure
    httponly
    samesite
];

sub get_session_id {
    my ($self, $env) = @_;
    return crush_cookie($env->{HTTP_COOKIE})->{$self->session_key};
}

sub merge_options {
    my($self, %options) = @_;

    delete $options{id};

    $options{path}     = $self->path || '/' if !exists $options{path};
    $options{domain}   = $self->domain      if !exists $options{domain} && defined $self->domain;
    $options{secure}   = $self->secure      if !exists $options{secure} && defined $self->secure;
    $options{httponly} = $self->httponly    if !exists $options{httponly} && defined $self->httponly;
    $options{samesite} = $self->samesite    if !exists $options{samesite} && defined $self->samesite;


    if (!exists $options{expires} && defined $self->expires) {
        $options{expires} = time + $self->expires;
    }

    return %options;
}

sub expire_session_id {
    my ($self, $id, $res, $options) = @_;
    my %opts = $self->merge_options(%$options, expires => time);
    $self->_set_cookie($id, $res, %opts);
}

sub finalize {
    my ($self, $id, $res, $options) = @_;
    my %opts = $self->merge_options(%$options);
    $self->_set_cookie($id, $res, %opts);
}

sub _set_cookie {
    my($self, $id, $res, %options) = @_;

    my $cookie = bake_cookie( 
        $self->session_key, {
            value => $id,
            %options,            
        }
    );
    Plack::Util::header_push($res->[1], 'Set-Cookie', $cookie);
}

1;
