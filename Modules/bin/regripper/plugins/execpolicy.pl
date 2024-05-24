#-----------------------------------------------------------
# execpolicy
#
# Change history:
#  20200517 - updated date output format
#  20180618 - created
# 
# Ref:
#  https://blogs.technet.microsoft.com/operationsguy/2011/04/21/remotely-tweak-powershell-execution-policies-without-powershell-remoting/
#
# copyright 2020 QAR,LLC 
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package execpolicy;
use strict;

my %config = (hive          => "Software",
							category      => "config",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20200517);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets PowerShell Execution Policy";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching execpolicy v.".$VERSION);
	::rptMsg("execpolicy v.".$VERSION); # banner
	::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner 
	my $key_path = ('Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.Powershell');
	
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite time: ".::getDateFromEpoch($key->get_timestamp())."Z");
		::rptMsg("");
		my $policy = "";
		eval {
			$policy = $key->get_value("ExecutionPolicy")->get_data();
		};
		if ($policy eq "") {
			::rptMsg("ExecutionPolicy value not found.")
		}
		else {
			::rptMsg("ExecutionPolicy = ".$policy);
		}
	}
}
1;
