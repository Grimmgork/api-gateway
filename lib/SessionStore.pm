package SessionStore;

sub new {
    my $class = shift;
    my $self = {
		data => shift,
		id_generator => shift
    };
    return bless $self, $class;
}

sub serialize {
	my ($self, $id, $session) = @_;
	# session never changes, no need to serialize
}

sub deserialize {
	my ($self, $id) = @_;
	my (undef, $login, $exp) = $self->{data}->find_token($id);
	return undef unless $exp;
	if(time() > $exp){
		destroy($self, $id);
		return undef;
	}
	return {
		expiration => $exp,
		login => $login
	};
}

sub destroy {
	my ($self, $id) = @_;
	$self->{data}->remove_token($id);
}

sub create {
	my ($self, $session) = @_;
	print "database\n";
	my $id = $self->{id_generator}->();
	$self->{data}->add_new_token($id, $session->{login}, $session->{expiration});
	return $id;
}

sub rotate {
	my ($self, $id) = @_;
	my $nid = $self->{id_generator}->();
	return $self->{data}->rotate_token($id, $nid);
}

1;