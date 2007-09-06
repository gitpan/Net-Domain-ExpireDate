#!/usr/bin/perl -w

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Net::Domain::ExpireDate',
    'VERSION_FROM'	=> 'ExpireDate.pm',
    'PREREQ_PM'		=> {
				'Time::Piece' => 1,
				'Net::Whois::Raw' => 1.30,
				'Test::More' => 0.50,
			   },
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'ExpireDate.pm', # retrieve abstract from module
       AUTHOR     => 'Walery Studennikov <despair@regtime.net>') : ()),
);
