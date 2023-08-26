package Mail;

sub new {
	my $class = shift;
	my $self = {
		groups => shift
	};
	return bless $self, $class;
}

sub send_group {
	my ($self, $group, $subject, $content) = @_;
	my $recipiants = $self->{groups}->{$group};
	foreach(@$recipiants){
		send_mail($self, $_, $subject, $content);
	}
}

sub send_mail {
	my ($self, $recipiant, $subject, $content) = @_;
	print "mail has been send\n";
	open(my $cmd, '|-', "mail", "-s", $subject, $recipiant) or die $!;
	print {$cmd} "$content";
	close $cmd;
}

1;