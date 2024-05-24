#-----------------------------------------------------------
# scriptleturl.pl
# 
#
# History
#   20200525 - minor updates
#   20160428 - created
#
# References
#   https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/
#
# copyright 2020, Quantum Analytics Research, LLC
#-----------------------------------------------------------
package scriptleturl;
use strict;

my %config = (hive          => "Software, USRCLASS\.DAT",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20200525);

sub getConfig{return %config}

sub getShortDescr {
	return "Check CLSIDs for ScriptletURL subkeys";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	
	my $scriptleturl;
	
	::logMsg("Launching scriptleturl v.".$VERSION);
	::rptMsg("scriptleturl v.".$VERSION); 
  ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n");
	
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my @key_paths = ("Classes\\CLSID","CLSID","WOW6432Node\\CLSID");
	my $key;
	foreach my $key_path (@key_paths) {
		if ($key = $root_key->get_subkey($key_path)) {
			my @sk = $key->get_list_of_subkeys();
			if (scalar(@sk) > 0) {
				foreach my $s (@sk) {
					
					
					eval {
						$scriptleturl = $s->get_subkey("ScriptletURL")->get_value("(Default)")->get_data();
						::rptMsg($s->get_name()."\\ScriptletURL key found: ".$scriptleturl);
					};
					
				}
			}
		}
	}
}

1;