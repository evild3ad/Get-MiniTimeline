#-----------------------------------------------------------
# heap.pl
#   
#
# Change history
#   20200427 - updated output date format
#   20200410 - created
#
# Ref:
#   https://channel9.msdn.com/Shows/Going+Deep/RADAR-Windows-Automatic-Memory-Leak-Detection
#   http://windowsir.blogspot.com/2011/09/registry-stuff.html 
#   
#
# Copyright 2020 QAR,LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package heap;
use strict;

my %config = (hive          => "Software",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              category      => "program execution",
              version       => 20200427);

my $VERSION = getVersion();

sub getConfig {return %config}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}
sub getDescr {}
sub getShortDescr {return "Checks HeapLeakDetection\\DiagnosedApplications Subkeys";}
sub getRefs {}

sub pluginmain {
	my $class = shift;
	my $hive = shift;

	::logMsg("Launching heap v.".$VERSION);
  ::rptMsg("heap v.".$VERSION); 
  ::rptMsg("(".$config{hive}.") ".getShortDescr());   
  ::rptMsg("");  
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key;
	my $key_path = 'Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications';
	
	if ($key = $root_key->get_subkey($key_path)) {
		
		my @sk = $key->get_list_of_subkeys();
		if (scalar @sk > 0) {
			foreach my $s (@sk) {
				my $name = $s->get_name();
				my $lw = $s->get_timestamp();
				::rptMsg($name." - LastWrite time: ".::getDateFromEpoch($lw)."Z");
				
				eval {
					if (my $v = $s->get_value("LastDetectionTime")->get_data()) {
						my ($t0,$t1) = unpack("VV",$v);
						my $last = ::getTime($t0,$t1);
						::rptMsg("  LastDetectionTime: ".::getDateFromEpoch($last)."Z");
					}
				};
				::rptMsg("");
			}
		}
	}
	else {
	
	}
}

1;
