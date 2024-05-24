#-----------------------------------------------------------
# appspecific.pl
# 
#
# Change history
#   20200515 - updated date output format
#   20120820 - created
#
# References
#
# 
# copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package appspecific;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20200515);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of user's Intellipoint\\AppSpecific subkeys";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching appspecific v.".$VERSION);
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Microsoft\\IntelliPoint\\AppSpecific';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("AppSpecific");
		::rptMsg($key_path);
		
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) { 
				::rptMsg($s->get_name()." [".::getDateFromEpoch($s->get_timestamp())."Z]");
				
				my $ts;
				eval {
					$ts = $s->get_value("Timestamp")->get_data();
					my $t = ::getTime(0,$ts);
					::rptMsg("Timestamp: ".::getDateFromEpoch($t)."Z");
					
				};
				::rptMsg("");
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;