package Net::Domain::ExpireDate;
require Exporter;

use strict;
use Time::Seconds;
use Time::Piece;
use Net::Whois::Raw;
use vars qw(@ISA @EXPORT $VERSION);

@ISA = qw(Exporter);
@EXPORT = qw(
    expire_date expdate_fmt expdate_int decode_date howmany_days_passed
);
$VERSION = '0.09';

# for Net::Whois::Raw
$OMIT_MSG = 2;
$CHECK_FAIL = 2;

sub expire_date {
    my ($domain, $format) = @_;

    return undef unless ($domain =~ /(.+?)\.([^.]+)$/);
    my ($name, $tld) = ($1, $2);

    my $whois = whois( $domain );

    if ($format) {
	return expdate_fmt( $whois, $tld, $format );
    } else {
	return expdate_int( $whois, $tld );
    }
}

sub expdate_fmt {
    my ($whois, $tld, $format) = @_;
    $format ||= '%Y-%m-%d';

    my $time = expdate_int( $whois, $tld );
    return undef unless $time;
    
    local $^W=0;                # prevent a warning
    return $time->strftime( $format );
}

sub expdate_int {
    my ($whois, $tld) = @_;
    $tld ||= 'com';

    if ($tld eq 'ru') {
	return expdate_int_ru( $whois );
    } else {
	return expdate_int_cno( $whois );
    }
}

sub howmany_days_passed {
    my ($time) = @_;
    my $now = localtime();
    my $seconds = $now - $time;
    return int( $seconds / ONE_DAY );
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
    # [whois.easyspace.com]
    # [whois.namesdirect.com]
    # [whois.dotregistrar.com]
    # [whois.domaininfo.com]		Domain expires: 24 Oct 2010
    # [whois.ibi.net]			Record expires on........: 03-Jun-2005 EST.
    # [whois.gkg.net]			Expires on..............: 24-JAN-2003
    if ($whois =~ m/(?:Record |Domain )?expire(?:d|s)(?: on\s?)?\.*:?\s+(\d{2})[- ](\w{3})[- ](\d{4})/is) {
	$rulenum = 1.1;	$d = $1; $b = $2; $Y = $3;
    # [whois.discount-domain.com]	Expiration Date: 02-Aug-2003 22:07:21
    # [?????????????]			Expiration Date:03-Mar-2004 05:00:00 UTC
    } elsif ($whois =~ m/Expiration Date:\s*(\d{2})-(\w{3})-(\d{4})/s) {
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
    } elsif ($whois =~ m&(?:Record |Domain )?(?:will )?(?:be )?expir(?:e|ed|es|ing)(?: on)?(?: date)?\s*[-:]?\s+(\d{4})[/-](\d{1,2})[/-](\d{2})&is) {
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
    } elsif ($whois =~ m/(?:Record )?expires on?\.*:? (?:\w{3}, )?(\w{3,5})\s{1,2}(\d{1,2}),? (\d{4})/is) {
	$rulenum = 4.1;	$b = $1; $d = $2; $Y = $3;
    # [whois.domainpeople.com]		Expires on .............WED NOV 16 09:09:52 2011
    # [whois.e-names.org]		Expires after:   Mon Jun  9 23:59:59 2003
    } elsif ($whois =~ m/Expires (?:on|after)\s?\.*:?\s*\w{3} (\w{3})\s{1,2}(\d{1,2}) \d{2}:\d{2}:\d{2} (\d{4})/is) {
	$rulenum = 4.2;	$b = $1; $d = $2; $Y = $3;
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
    }

    unless ($rulenum) {
	warn "Can't recognise date format\n";
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

# extract expiration date from whois output for .ru domains
sub expdate_int_ru {
    my ($whois) = @_;
    return undef unless $whois;

    my @states;
    while ($whois =~ /state:   (.+?)\n/gs) { pushstate(\@states, $1) };
    while ($whois =~ /reg-till: (.+?)\n/gs) { pushstate(\@states, "reg-till: $1") };
    while ($whois =~ /free-date:(.+?)\n/gs) { pushstate(\@states, "free-date: $1") };
    my $res = join( '; ', @states );

    my ($reg_till, $free_date, $active);

    # ON-HOLD domains
    if ($res =~ /NOT DELEGATED; reg-till:\s+([0-9.]+); free-date:\s+([0-9.]+)/) {
	$active = 0;
	($reg_till = $1) =~ tr/./-/;
	($free_date = $2) =~ tr/./-/;
    } elsif ($res =~ /NOT DELEGATED; reg-till: ([0-9.]+)/i) {
	$active = 0;
	($reg_till = $1) =~ tr/./-/;
    } elsif ($res =~ /Not delegated; (?:freeing date -|free-date:)\s+([0-9.]+)/i) {
	$active = 0;
	($free_date = $1) =~ tr/./-/;
    } elsif ($res =~ /Not delegated/i) {
	$active = 0;
    # ACTIVE DOMAINS
    } elsif ($res =~ /reg-till:\s+([0-9.]+); free-date:\s+([0-9.]+)/) {
	$active = 1;
	($reg_till = $1) =~ tr/./-/;
	($free_date = $2) =~ tr/./-/;
    } elsif ($res =~ /reg-till:\s+([0-9.]+)/) {
	$active = 1;
	($reg_till = $1) =~ tr/./-/;
    } elsif ($res =~ /Delegated till ([0-9.]+)/) {
	$active = 1;
	($reg_till = $1) =~ tr/./-/;
    } elsif ($res =~ /Delegated/) {
	$active = 1;
    # NOT-ACTIVE-YET DOMAINS
    } elsif ($res =~ /RIPN NCC check in progress/) {
	$active = 0;
    } else {
	warn "Unknown record: $res\n";
	return undef;
    }

    unless ( $reg_till || $free_date ) {
	warn "Can't obtain expiration date from: $res\n";
	return undef;
    }

    $reg_till = decode_date( $reg_till );
    $free_date = decode_date( $free_date );
    if (!$reg_till && $free_date) {
	$reg_till = $free_date - 33 * ONE_DAY;
    }
    
    return $reg_till;
}

sub pushstate {
    my ($states, $state) = @_;
    return if (
	$state =~ /REGISTERED, DELEGATED/i
	||
	$state =~ /RIPN NCC check completed OK/i
    );
    push @{$states}, $state;
}



1;
__END__

=head1 NAME

Net::Domain::ExpireDate - Perl extension for obtaining expiration date
of domain names

=head1 SYNOPSIS

 use Net::Domain::ExpireDate;

 $date = expire_date( 'microsoft.com' );
 $str  = expire_date( 'microsoft.com', '%Y-%m-%d' );
 $date = expdate_int( $whois_text, 'com' );
 $str  = expdate_fmt( $whois_text, 'ru', '%Y-%m-%d' );

=head1 DESCRIPTION

Net::Domain::ExpireDate gets WHOIS information of given domain using
Net::Whois::Raw and tries to obtain expiration date of domain.
Unfortunately there are too many different whois servers which provides
whois info in very different formats.
Net::Domain::ExpireDate knows more than 40 different formats of
expiration date representation provided by different servers (almost
all gTLD registrars and some ccTLD registrars are covered). If an
expiration date format is unknown to Net::Domain::ExpireDate - then
heuristics is used to determine expiration date.

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
distinction between 'com', 'net' or 'org' TLDs in this function -
all of them means gTLD. Also 'ru' TLD is suppored.
Returns L<Time::Piece> object.

With C<FORMAT> argument returns date formatted using C<FORMAT> template
(see L<strftime> man page for C<FORMAT> specification)

=item expdate_fmt( WHOISTEXT [,TLD [,FORMAT]]  )

Similar to expdate_int except that output value is formatted date.
If no C<FORMAT> specified, '%Y-%m-%d' is assumed.
See L<strftime> man page for C<FORMAT> specification.

=back

=head1 AUTHOR

Walery Studennikov, <despair@regtime.net>

=head1 SEE ALSO

L<Net::Whois::Raw>, L<Time::Piece>.

=cut
