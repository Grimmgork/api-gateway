package SessionStore;

sub new {
    my $class = shift;
    my $self = {
		data => shift
    };
    return bless $self, $class;
}

sub fetch {
	my ($self, $session_id) = @_;
	if(my ($m, $login, $exp) = $self->{data}->find_token($session_id)){
		if(time() > $exp){
			return undef;
		}
		return {
			expiration => $exp,
			login => $login
		};
	}
	return undef;
}

sub remove {
	my ($self, $session_id) = @_;
	$self->{data}->remove_token($session_id);
}

sub store {
	my ($self, $session_id, $session) = @_;
	$self->{data}->remove_token($session_id);
	$self->{data}->add_new_token($session_id, $session->{login}, $session->{expiration});
	return $session_id;
}

1;