package Net::Domain::ExpireDate;
require Exporter;

use strict;
use Time::Seconds;
use Time::Piece;
use Net::Whois::Raw qw(whois $OMIT_MSG $CHECK_FAIL);
use vars qw(@ISA @EXPORT @EXPORT_OK $VERSION $USE_REGISTRAR_SERVERS);

@ISA = qw(Exporter);
@EXPORT = qw(
    expire_date expdate_int expdate_fmt domain_dates domdates_fmt $USE_REGISTRAR_SERVERS
);
@EXPORT_OK = qw( decode_date );
$VERSION = '0.27';

$USE_REGISTRAR_SERVERS = 0;
# 0 - make queries to registry server
# 1 - make queries to registrar server
# 2 - make queries to registrar server
#     and in case of fault make query to registry server

# for Net::Whois::Raw
$OMIT_MSG = 2; $CHECK_FAIL = 3;

sub expire_date {
    my ($domain, $format) = @_;

    if ($USE_REGISTRAR_SERVERS == 0) {
	return expire_date_query( $domain, $format, 1 )
    } elsif ($USE_REGISTRAR_SERVERS == 1) {
	return expire_date_query( $domain, $format, 0 )
    } elsif ($USE_REGISTRAR_SERVERS == 2) {
	return expire_date_query( $domain, $format, 0 )
	    || expire_date_query( $domain, $format, 1 );
    }
    
    return undef;
}

sub domain_dates {
    my ($domain, $format) = @_;

    return undef unless ($domain =~ /(.+?)\.([^.]+)$/);
    my ($name, $tld) = (lc $1, lc $2);

    my $whois;
    if (isin($tld, ['com', 'net'])) {
	$whois = whois( $domain, 'whois.crsnic.net' );
    } elsif ($tld eq 'org') {
	$whois = whois( $domain, 'whois.publicinterestregistry.net' );
    } else {
	$whois = whois( $domain );
    }

    if ($format) {
	return (domdates_fmt( $whois, $tld, $format ));
    } else {
	return (domdates_int( $whois, $tld ));
    }
    
    return undef;
}

sub expire_date_query {
    my ($domain, $format, $via_registry) = @_;

    return undef unless ($domain =~ /(.+?)\.([^.]+)$/);
    my ($name, $tld) = (lc $1, lc $2);

    my $whois;
    if (isin($tld, ['com', 'net']) && $via_registry) {
	$whois = whois( $domain, 'whois.crsnic.net' );
    } elsif ($tld eq 'org' && $via_registry) {
	$whois = whois( $domain, 'whois.publicinterestregistry.net' );
    }

    $whois ||= whois( $domain );

    if ($format) {
	return expdate_fmt( $whois, $tld, $format );
    } else {
	return expdate_int( $whois, $tld );
    }
}

sub domdates_fmt {
    my ($whois, $tld, $format, $onlyexpdate) = @_;
    $format ||= '%Y-%m-%d';

    my ($cre_date, $exp_date, $fre_date) = domdates_int( $whois, $tld, $onlyexpdate );

    local $^W = 0;  # prevent warnings

    $cre_date = $cre_date ? $cre_date->strftime( $format ) : '';
    $exp_date = $exp_date ? $exp_date->strftime( $format ) : '';
    $fre_date = $fre_date ? $fre_date->strftime( $format ) : '';

    return ($cre_date, $exp_date, $fre_date);
}

sub expdate_fmt {
    my ($whois, $tld, $format) = @_;

    my ($cre_date, $exp_date, $fre_date) = domdates_fmt( $whois, $tld, $format, 1 );

    return $exp_date;
}

sub domdates_int {
    my ($whois, $tld, $onlyexpdate) = @_;
    $tld ||= 'com';

    if ($tld eq 'ru' || $tld eq 'su') {
	return (dates_int_ru( $whois ));
    } elsif (isin($tld, ['com', 'net', 'org', 'biz', 'info', 'us', 'uk'])) {
	my $expdate = expdate_int_cno( $whois );
	my $credate = $onlyexpdate ? undef : credate_int_cno( $whois );
	return ($credate, $expdate);
    } else {
	return ();
    }
}

sub expdate_int {
    my ($whois, $tld) = @_;

    my ($cre_date, $exp_date, $fre_date) = domdates_int( $whois, $tld, 1 );
    return $exp_date;
}

# --- internal functions ----

sub decode_date {
    my ($date, $format) = @_;
    return undef unless $date;
    $format ||= '%Y-%m-%d';

    my $t;
    eval { $t = Time::Piece->strptime($date, $format); };
    if ($@) {
	warn "Can't parse date: ($date, $format)";
	return undef;
    }

    return $t;
}

# extract expiration date from whois output for .com .net .org domains
sub expdate_int_cno {
    my ($whois) = @_;
    return undef unless $whois;

    # $Y - The year, including century
    # $y - The year within century (0-99)
    # $m - The month number (1-12)
    # $b - The month name
    # $d - The day of month (1-31)
    my ($rulenum, $Y, $y, $m, $b, $d);

    # [whois.networksolutions.com]	Record expires on 27-Apr-2011.
    # [whois.opensrs.net]
    # [whois.namesdirect.com]
    # [whois.dotregistrar.com]
    # [whois.domaininfo.com]		Domain expires: 24 Oct 2010
    # [whois.ibi.net]			Record expires on........: 03-Jun-2005 EST.
    # [whois.gkg.net]			Expires on..............: 24-JAN-2003
    if ($whois =~ m/(?:Record |Domain )?expire(?:d|s)(?: on\s?)?\.*:?\s+(\d{2})[- ](\w{3})[- ](\d{4})/is) {
	$rulenum = 1.1;	$d = $1; $b = $2; $Y = $3;
    # [whois.discount-domain.com]	Expiration Date: 02-Aug-2003 22:07:21
    # [whois.publicinterestregistry.net] Expiration Date:03-Mar-2004 05:00:00 UTC
    # [whois.crsnic.net]		Expiration Date: 21-sep-2004
    # [whois.nic.uk]			Renewal Date:   23-Jan-2006
    } elsif ($whois =~ m/(?:Expiration|Renewal) Date:\s*(\d{2})-(\w{3})-(\d{4})/s) {
	$rulenum = 1.2;	$d = $1; $b = $2; $Y = $3;
    # [whois.bulkregister.com]		Record expires on 2003-04-25
    # [whois.bulkregister.com]		Record will be expiring on date: 2003-04-25
    # [whois.bulkregister.com]		Record expiring on -  2003-04-25
    # [whois.bulkregister.com]		Record will expire on -  2003-04-25
    # [whois.bulkregister.com]		Record will be expiring on date: 2003-04-25
    # [whois.eastcom.com]
    # [whois.corenic.net]		Record expires:       2003-07-29 10:45:05 UTC
    # [whois.gandi.net]			expires:        2003-05-21 10:09:56
    # [whois.dotearth.com]		Record expires on:       2010-04-07 00:00:00.0 ET
    # [whois.names4ever.com]		Record expires on 2012-07-15 10:23:10.000
    # [whois.OnlineNIC.com]		Record expired on 2008/8/26
    # [whois.ascio.net]			Record expires:           2003-03-12 12:16:45
    # [whois.totalnic.net]		Record expires on 2010-04-24 16:03:20+10
    # [whois.signaturedomains.com]	Expires on: 2003-11-05
    # [whois.1stdomain.net]		Domain expires: 2007-01-20.
    # [whois.easyspace.com]
    } elsif ($whois =~ m&(?:Record |Domain )?(?:will )?(?:be )?expir(?:e|ed|es|ing)(?: on)?(?: date)?\s*[-:]?\s*(\d{4})[/-](\d{1,2})[/-](\d{1,2})&is) {
	$rulenum = 2.1;	$Y = $1; $m = $2; $d = $3;
    # [whois.InternetNamesWW.com]	Expiry Date.......... 2009-06-16
    # [whois.aitdomains.com]		Expire on................ 2002-11-05 16:42:41.000
    # [whois.yesnic.com]		Valid Date     2010-11-02 05:21:35 EST
    # [whois.enetregistry.net]		Expiration Date     : 2002-11-19 04:18:25-05
    # [whois.enterprice.net]		Date of expiration  : 2003-05-28 11:50:58
    # [nswhois.domainregistry.com]	Expires on..............: 2006-07-24
    } elsif ($whois =~ m&(?:Expiry Date|Expire(?:d|s)? on|Valid Date|Expiration Date|Date of expiration)(?:\.*|\s*):?\s+(\d{4})-(\d{2})-(\d{2})&s) {
	$rulenum = 2.2;	$Y = $1; $m = $2; $d = $3;
    # [whois.oleane.net]		expires:        20030803
    } elsif ($whois =~ m/expires:\s+(\d{4})(\d{2})(\d{2})/is) {
	$rulenum = 2.3;	$Y = $1; $m = $2; $d = $3;
    # [whois.dotster.com]		Expires on: 12-DEC-05
    } elsif ($whois =~ m/Expires on: (\d{2})-(\w{3})-(\d{2})/s) {
	$rulenum = 3;	$d = $1; $b = $2; $y = $3;
    # [whois.register.com]		Expires on..............: Tue, Aug 04, 2009
    # [whois.registrar.aol.com]		Expires on..............: Oct  5 2002 12:00AM
    # [whois.itsyourdomain.com]		Record expires on March 06, 2011
    # [whois.doregi.com]		Record expires on.......: Oct  28, 2011
    } elsif ($whois =~ m/(?:Record )?expires on\.*:? (?:\w{3}, )?(\w{3,9})\s{1,2}(\d{1,2}),? (\d{4})/is) {
	$rulenum = 4.1;	$b = $1; $d = $2; $Y = $3;
    # [whois.domainpeople.com]		Expires on .............WED NOV 16 09:09:52 2011
    # [whois.e-names.org]		Expires after:   Mon Jun  9 23:59:59 2003
    } elsif ($whois =~ m/Expires (?:on|after)\s?\.*:?\s*\w{3} (\w{3})\s{1,2}(\d{1,2}) \d{2}:\d{2}:\d{2} (\d{4})/is) {
	$rulenum = 4.2;	$b = $1; $d = $2; $Y = $3;
    # [whois.enom.com]			Expiration date: Fri Sep 21 2012 13:45:09
    # [whois.enom.com]			Expires: Fri Sep 21 2012 13:45:09
    # [whois.neulevel.biz]		Domain Expiration Date: Fri Mar 26 23:59:59 GMT 2004
    } elsif ($whois =~ m/(?:Domain )?(?:Expires|Expiration Date):\s+\w{3} (\w{3}) (\d{2}) (?:\d{2}:\d{2}:\d{2} \w{3}(?:[-+]\d{2}:\d{2})? )(\d{4})/is) {
	$rulenum = 4.3; $b = $1; $d = $2; $Y = $3;
    # [rs.domainbank.net]		Record expires on 10-05-2003 11:21:25 AM
    # [whois.psi-domains.com]
    # [whois.namesecure.com]		Expires on 10-09-2011
    # [whois.catalog.com]		Record Expires on 08-24-2011
    } elsif ($whois =~ m&(?:Record |Domain )?expire(?:d|s) on (\d{2})-(\d{2})-(\d{4})&is) {
	$rulenum = 5.1;	$m = $1; $d = $2; $Y = $3;
    # [whois.stargateinc.com]		Expiration: 6/3/2004
    # [whois.bookmyname.com]		Expires on 11/26/2007 23:00:00
    } elsif ($whois =~ m&(?:Expiration|Expires on):? (\d{1,2})[-/](\d{1,2})[-/](\d{4})&is) {
	$rulenum = 5.2;	$m = $1; $d = $2; $Y = $3;
    # [whois.nordnet.net]		Record expires on 2010-Apr-03
    # [whois.alldomains.com]		Expires on..............: 2006-Jun-12
    } elsif ($whois =~ m/(?:Record |Domain )?expires on\.*:? (\d{4})-(\w{3})-(\d{2})/is) {
	$rulenum = 6;	$Y = $1; $b = $2; $d = $3;
    # [whois.enom.com]			Expiration date: 09/21/03 13:45:09
    } elsif ($whois =~ m|Expiration date: (\d{2})/(\d{2})/(\d{2})|s) {
	$rulenum = 7;	$m = $1; $d = $2; $y = $3;
    } elsif ($whois =~ m/Registered through- (\w{3}) (\w{3}) (\d{2}) (\d{4})/is) {
	$rulenum = 7.1; $b = $2; $d = $3; $Y = $4;
    } elsif ($whois =~ m|Expires: (\d{2})/(\d{2})/(\d{2})|is) {
	$rulenum = 7.2;	$m = $1; $d = $2; $y = $3;
    } elsif ($whois =~ m|Registered through- (\d{2})/(\d{2})/(\d{2})|is) {
	$rulenum = 7.3; $m = $1; $d = $2; $y = $3;
    }

    unless ($rulenum) {
	warn "Can't recognise expiration date format\n";
	return undef;
    } else {
	#warn "rulenum: $rulenum\n";
    };

    my ($fstr, $dstr) = ('', '');
    $fstr .= $Y ? '%Y ' : '%y ';
    $dstr .= $Y ? "$Y " : "$y ";

    $fstr .= $b ? '%b ' : '%m ';
    $dstr .= $b ? "$b " : "$m ";

    $fstr .= '%d';
    $dstr .= $d;

    return decode_date( $dstr, $fstr );
}


# extract creation date from whois output for .com .net .org domains
sub credate_int_cno {
    my ($whois) = @_;
    return undef unless $whois;

    # $Y - The year, including century
    # $m - The month number (1-12)
    # $b - The month name
    # $d - The day of month (1-31)
    my ($rulenum, $Y, $y, $m, $b, $d);

    # [whois.crsnic.net]		Creation Date: 06-sep-2000
    if ($whois =~ m/Creation Date:\s*(\d{2})-(\w{3})-(\d{4})/s) {
	$rulenum = 1.2;	$d = $1; $b = $2; $Y = $3;
    } else {
	warn "Can't recognise creation date format\n";
	return undef;
    }

    return decode_date( "$Y $b $d", '%Y %b %d' );
}



# extract creation/expiration dates from whois output for .ru and .su domains
sub dates_int_ru {
    my ($whois) = @_;
    return undef unless $whois;

    my ($reg_till, $free_date, $created);

    if ($whois =~ /reg-till:\s*(.+?)\n/s) { $reg_till = $1; }
    if ($whois =~ /Delegated till\s*(.+?)\n/s) { $reg_till = $1; }
    if ($whois =~ /payed-till:\s*(.+?)\n/s) { $reg_till = $1; }
    if ($whois =~ /paid-till:\s*(.+?)\n/s) { $reg_till = $1; }
    if ($whois =~ /free-date:\s*(.+?)\n/s) { $free_date = $1; }
    if ($whois =~ /created:\s+([0-9.]+)\n/s) { $created = $1; }

    $reg_till =~ tr/./-/ if $reg_till;
    $free_date =~ tr/./-/ if $free_date;
    $created =~ tr/./-/ if $created;

    if ($created) {
	# Guess reg-till date
	$created = decode_date( $created, '%Y-%m-%d' );
	my $t = $created;

	if ($t && !$reg_till && !$free_date) {
	    $t += 0;
	    while ($t < localtime()) {
		$t += ONE_YEAR + ($t->is_leap_year() ? 1 : 0);
	    }
	    $reg_till = $t->strftime( '%Y-%m-%d' );
	}
    }

    unless ( $reg_till || $free_date ) {
	warn "Can't obtain expiration date from ($reg_till)\n";
	return undef;
    }

    $reg_till = decode_date( $reg_till );
    $free_date = decode_date( $free_date );
    if (!$reg_till && $free_date) {
	$reg_till = $free_date - 33 * ONE_DAY;
    }
    
    return ($created, $reg_till, $free_date);
}

sub isin {
    my ( $val, $arr ) = @_;
    return '' unless $arr;
    foreach (@{$arr}) {
	return 1 if ($_ eq $val);
    }
    return 0;
}


1;
__END__

=head1 NAME

Net::Domain::ExpireDate - obtain expiration date of domain names

=head1 SYNOPSIS

 use Net::Domain::ExpireDate;

 $expiration_obj = expire_date( 'microsoft.com' );
 $expiration_str  = expire_date( 'microsoft.com', '%Y-%m-%d' );
 $expiration_obj = expdate_int( $whois_text, 'com' );
 $expiration_str  = expdate_fmt( $whois_text, 'ru', '%Y-%m-%d' );

 ($creation_obj, $expiration_obj) = domain_dates( 'microsoft.com' );
 ($creation_str, $expiration_str) = domain_dates( 'microsoft.com', '%Y-%m-%d' );
 ($creation_obj, $expiration_obj) = domdates_int( $whois_text, 'com' );

=head1 DESCRIPTION

Net::Domain::ExpireDate gets WHOIS information of given domain using
Net::Whois::Raw and tries to obtain expiration date of domain.
Unfortunately there are too many different whois servers which provides
whois info in very different formats.
Net::Domain::ExpireDate knows more than 40 different formats of
expiration date representation provided by different servers (almost
all gTLD registrars and some ccTLD registrars are covered).
Now obtaining of domain creation date is also supported.

"$date" in synopsis is an object of type L<Time::Piece>.

=head1 FUNCTIONS

=over 4

=item expire_date( DOMAIN [,FORMAT] )

Returns expiration date of C<DOMAIN>.
Without C<FORMAT> argument returns L<Time::Piece> object.
With C<FORMAT> argument returns date formatted using C<FORMAT> template.
See L<strftime> man page for C<FORMAT> specification.

=item expdate_int( WHOISTEXT [,TLD] )

Extracts expiration date of domain in TLD from C<WHOISTEXT>.
If no TLD is given 'com' is the default. There is no
distinction between 'com' or 'net' TLDs in this function.
Also 'org', 'biz', 'info', 'us', 'ru' and 'su' TLDs are suppored.
Returns L<Time::Piece> object.

With C<FORMAT> argument returns date formatted using C<FORMAT> template
(see L<strftime> man page for C<FORMAT> specification)

=item expdate_fmt( WHOISTEXT [,TLD [,FORMAT]]  )

Similar to expdate_int except that output value is formatted date.
If no C<FORMAT> specified, '%Y-%m-%d' is assumed.
See L<strftime> man page for C<FORMAT> specification.

=item domain_dates( DOMAIN [,FORMAT] )

Returns list of two values - creation and expiration date of C<DOMAIN>.
Without C<FORMAT> argument returns L<Time::Piece> objects.
With C<FORMAT> argument dates are formatted using C<FORMAT> template.
See L<strftime> man page for C<FORMAT> specification.

=item domdates_int( WHOISTEXT [,TLD] )

Returns list of two values - creation and expiration date of domain
extracted from C<WHOISTEXT>.
If no TLD is given 'com' is the default. There is no
distinction between 'com' or 'net' TLDs in this function.
Also 'org', 'biz', 'info', 'us', 'ru' and 'su' TLDs are suppored.
Returns L<Time::Piece> object.

=back

=head1 AUTHOR

Walery Studennikov, <despair@cpan.org>

=head1 SEE ALSO

L<Net::Whois::Raw>, L<Time::Piece>.

=cut
