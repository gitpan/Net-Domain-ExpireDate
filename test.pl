#!/usr/bin/perl -w

use lib qw(.);
use Test;
use Data::Dumper;
BEGIN { plan tests => 52 };

use Net::Domain::ExpireDate;
ok(1); # If we made it this far, we're ok.

# .com .net .org tests

ok( expdate_fmt("\nRecord expires on 27-Apr-2011.\n"), '2011-04-27' );
ok( expdate_fmt("\nDomain expires: 24 Oct 2010\n"), '2010-10-24' );
ok( expdate_fmt("\nRecord expires on........: 03-Jun-2005 EST.\n"), '2005-06-03' );
ok( expdate_fmt("\nExpires on..............: 24-JAN-2003\n"), '2003-01-24' );
ok( expdate_fmt("\nExpiration Date: 02-Aug-2003 22:07:21\n"), '2003-08-02' );
ok( expdate_fmt("\nExpiration Date:03-Mar-2004 05:00:00 UTC\n"), '2004-03-03' );
ok( expdate_fmt("\nRecord expires on 2003-09-08\n"), '2003-09-08' );
ok( expdate_fmt("\nRecord expires:       2003-07-29 10:45:05 UTC\n"), '2003-07-29' );
ok( expdate_fmt("\nexpires:        2003-05-21 10:09:56\n"), '2003-05-21' );
ok( expdate_fmt("\nRecord expires on:       2010-04-07 00:00:00.0 ET\n"), '2010-04-07' );
ok( expdate_fmt("\nRecord expires on 2012-07-15 10:23:10.000\n"), '2012-07-15' );
ok( expdate_fmt("\nRecord expired on 2008/8/26\n"), '2008-08-26' );
ok( expdate_fmt("\nRecord expires:           2003-03-12 12:16:45\n"), '2003-03-12' );
ok( expdate_fmt("\nRecord expires on 2010-04-24 16:03:20+10\n"), '2010-04-24' );
ok( expdate_fmt("\nExpires on: 2003-11-05\n"), '2003-11-05' );
ok( expdate_fmt("\nDomain expires: 2007-01-20.\n"), '2007-01-20' );
ok( expdate_fmt("\nExpiry Date.......... 2009-06-16\n"), '2009-06-16' );
ok( expdate_fmt("\nExpire on................ 2002-11-05 16:42:41.000\n"), '2002-11-05' );
ok( expdate_fmt("\nValid Date     2010-11-02 05:21:35 EST\n"), '2010-11-02' );
ok( expdate_fmt("\nExpiration Date     : 2002-11-19 04:18:25-05\n"), '2002-11-19' );
ok( expdate_fmt("\nDate of expiration  : 2003-05-28 11:50:58\n"), '2003-05-28' );
ok( expdate_fmt("\nExpires on..............: 2006-07-24\n"), '2006-07-24' );
ok( expdate_fmt("\nexpires:        20030803\n"), '2003-08-03' );
ok( expdate_fmt("\nExpires on: 12-DEC-05\n"), '2005-12-12' );
ok( expdate_fmt("\nExpires on..............: Tue, Aug 04, 2009\n"), '2009-08-04' );
ok( expdate_fmt("\nExpires on..............: Oct  5 2002 12:00AM\n"), '2002-10-05' );
ok( expdate_fmt("\nRecord expires on December 05, 2004\n"), '2004-12-05' );
ok( expdate_fmt("\nRecord expires on.......: Oct  28, 2011\n"), '2011-10-28' );
ok( expdate_fmt("\nExpires on .............WED NOV 16 09:09:52 2011\n"), '2011-11-16' );
ok( expdate_fmt("\nExpires after:   Mon Jun  9 23:59:59 2003\n"), '2003-06-09' );
ok( expdate_fmt("\nRecord expires on 10-05-2003 11:21:25 AM\n"), '2003-10-05' );
ok( expdate_fmt("\nExpires on 10-09-2011\n"), '2011-10-09' );
ok( expdate_fmt("\nRecord Expires on 08-24-2011\n"), '2011-08-24' );
ok( expdate_fmt("\nExpiration: 6/3/2004\n"), '2004-06-03' );
ok( expdate_fmt("\nExpires on 11/26/2007 23:00:00\n"), '2007-11-26' );
ok( expdate_fmt("\nRecord expires on 2010-Apr-03\n"), '2010-04-03' );
ok( expdate_fmt("\nExpires on..............: 2006-Jun-12\n"), '2006-06-12' );
ok( expdate_fmt("\nExpiration date: 09/21/03 13:45:09\n"), '2003-09-21' );
# whois.bulkregister.com can give expiration date in different formats
ok( expdate_fmt("\nRecord expires on 2003-04-25\n"), '2003-04-25' );
ok( expdate_fmt("\nRecord will be expiring on date: 2003-04-25\n"), '2003-04-25' );
ok( expdate_fmt("\nRecord expiring on -  2003-04-25\n"), '2003-04-25' );
ok( expdate_fmt("\nRecord will expire on -  2003-04-25\n"), '2003-04-25' );
ok( expdate_fmt("\nRecord will be expiring on date: 2003-04-25\n"), '2003-04-25' );

# .ru tests

ok( expdate_fmt("\nstate:   Delegated till 2003.10.01\nstate:   RIPN NCC check completed OK\n", 'ru'), '2003-10-01' );
ok( expdate_fmt("\ncreated:  2001.09.19\nreg-till: 2003.09.20\n", 'ru'), '2003-09-20' );
ok( expdate_fmt("\nstate:    REGISTERED, NOT DELEGATED\nfree-date:2002.10.03\n", 'ru'), '2002-08-31' );

# .ua tests

ok( expdate_fmt("\nstatus:      OK-UNTIL 20040912000000\n", 'ua'), '2004-09-12' );

# online tests

print "The following tests requires internet connection...\n";

ok( expire_date("microsoft.com", '%Y-%m-%d'), '2012-05-03' );
ok( expire_date("usa.biz", '%Y-%m-%d'), '2005-03-26' );
ok( expire_date("nic.info", '%Y-%m-%d'), '2011-07-27' );
ok( expire_date("nic.us", '%Y-%m-%d'), '2007-04-17' );
ok( expire_date("bigmir.com.ua", '%Y-%m-%d'), '2004-09-12' );
