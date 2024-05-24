#-----------------------------------------------------------
# lxss_tln.pl
# Plugin for Registry Ripper 
# Windows\CurrentVersion\Applets Recent File List values 
#
# Change history
#  20190813 - created
#
# References
#
# 
# copyright 2019-2020 QAR, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package lxss_tln;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              category      => "configuration",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20140723);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets WSL config.";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
#	::logMsg("Launching lxss v.".$VERSION);
#	::rptMsg("lxss v.".$VERSION); 
#  ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); 
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Lxss';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
#		::rptMsg("Lxss");
#		::rptMsg($key_path);
#		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." Z");
		
#		eval {
#			my $def = $key->get_value("DefaultDistribution")->get_data();
#			::rptMsg("DefaultDistribution: ".$def);
#		};
#		::rptMsg("");
		
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $sk (@subkeys) {
#				::rptMsg($sk->get_name());
				my $lw = $sk->get_timestamp();
				
				my $str;
				eval {
					my $dist = $sk->get_value("DistributionName")->get_data();
					$str .= " ".$dist;
				};
				
				eval {
					my $kern = $sk->get_value("KernelCommandLine")->get_data();
					$str .= " (".$kern.")";
				};
				::rptMsg($lw."|REG|||Lxss - ".$str);
			}
		}
	}
	else {
#		::rptMsg($key_path." not found.");
	}
}

1;