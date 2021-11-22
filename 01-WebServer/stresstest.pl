#!/usr/bin/perl 

use strict;
use LWP::Simple;

my $run = 500;
my $hammer = 0;
my $time = time();
my $delay = 20;
my $x = 1;

while($run) {
	my $pid = fork();
	
	if($pid) {
		$run--;
	}
	elsif ($pid == 0) {
		sleep 1 while $hammer and $time + $delay + rand($x);
		my $output = get("http://localhost/");
		print $run, $output;
		exit;
	}
	else {
		die "Fork Failed $!\n";
	}
}



