package ReqMatch;
use strict;

# my $groups = ["test", "lel", "dies", "das", "ananas"];
# match("./policy.txt", $groups, "post", "share", "test", "kladklak", "adlkalwd");

sub match {
	my ($policy, $groups_ref, $verb, @segments) = @_;

	open my $file, $policy or die "Could not open $policy: $!";
	my $segcount;

	## find path
	FINDPATH:
	$_ = <$file>;
	return undef unless $_;
	chomp;
	if(s/^root\s+//){ # find path definition
		goto PATH;
	}
	goto FINDPATH;

	## process a path
	PATH:
	my $segc = 0;
	while($_ =~ m/([\*a-z0-9_\-\$]+)(?=(?:\s+)|$)/g){
		$segc++;
		if($1 eq "*"){
			$segc = scalar @segments; # simulate a fully matched path
			last;
		}
		goto FINDPATH if $segc > scalar @segments;
		next if $1 eq "\$";
		goto FINDPATH unless $1 eq $segments[$segc-1];
	}
	goto FINDPATH if $segc < scalar @segments; # abort if unmatched segments are left
	goto RULE;

	## process a rule
	RULE:
	$_ = <$file>;
	return undef unless $_;
	chomp;
	goto PATH if $_ =~ s/^root\s+//;
	goto VERB;

	## process a verb
	VERB:
	goto RULE unless $_ =~ s/^\s*([a-z0-9_\-]+)\s*//; # if there is no next verb
	goto RULE if $1 eq "group"; # no matching verb found
	if($1 eq $verb){
		while($_ =~ s/^\s*([a-z0-9_\-]+)\s*//){ # go to the group verb
			goto GROUP if $1 eq "group";
		}
		# no group keyword found
		goto RULE;
	}
	goto VERB;

	## process a list of groups
	GROUP:
	goto RULE unless $_ =~ s/^\s*([a-z0-9_\-]+)\s*//;
	return 1 if grep(/^$1$/, @$groups_ref);
	goto GROUP;
}

1;