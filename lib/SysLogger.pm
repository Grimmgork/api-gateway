package SysLogger;
use Sys::Syslog;

sub new {
    my $class = shift;
    my $self = {
		name => shift || caller(),
		facility => shift || "local0",
		loglevel => shift || "debug"
    };
    return bless $self, $class;
}

sub log {
	my ($self, $msg) = @_;
	if(openlog($self->{name}, "ndelay,pid", $self->{facility})){
		if(syslog($self->{loglevel}, $msg)){
			closelog();
			print "logged!\n";
			return 1;
		}
	}
	return undef;
}

1;