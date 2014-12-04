#!/usr/bin/perl -w

use strict;
use Getopt::Long;
use Data::Dumper;
use JSON;

#$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

require "Nessus_REST.pm";

# Declair variables to keep strict happy
my $list_policies;
my $list_scans;
my $get_historyID;
my $list_scanners;
my $list_folders;
my $list_policy_templates;
my $scan_export;
my $scan_download;
my $create_scan;
my $launch_scan;
my $help;
my $n;
my $o;
my $x;
my $y;
my $z;

### evaluate parameters
GetOptions ("list-policies"   		=> \$list_policies,
			"list-scans"      		=> \$list_scans,
			"get-historyID"   		=> \$get_historyID,
			"list-scanners"	  		=> \$list_scanners,
			"list-folders"	  		=> \$list_folders,
			"list-policy-templates"	=> \$list_policy_templates,
			"scan-export"			=> \$scan_export,
			"scan-download"			=> \$scan_download,
			"create-scan"			=> \$create_scan,
			"launch-scan"			=> \$launch_scan,
			"help"					=> \$help
);

if($help) { 
	print_help(); 
}
elsif($list_policies) { 
	list_policies(); 
}
elsif($list_scans) { 
	list_scans(); 
}
elsif($get_historyID) {
	list_historyID($n);
}
elsif($list_scanners) {
	list_scanners();
}
elsif($list_folders) {
	list_folders();
}
elsif($list_policy_templates) {
	list_policy_templates();
}
elsif($scan_export) {
	scan_export($n);
}
elsif($scan_download) {
	scan_download($n,$x,$y);
}
elsif($create_scan) {
	create_scan($n,$o,$x,$y,$z);
}
elsif($launch_scan) {
	launch_scan($x);
}

sub print_help {
	print qq(
		usage: $0 <command> [ <command-options> ]

		Commands:
		--------------------------------------------------------------------------------------------------------
		--list-policies						- List the user created scan policies
		--list-scans						- List scan history and status
		--get-historyID						- List the history of a given scan
			<scan_id>
		--list-scanners						- List all the scanners
		--list-folders						- List the available scan folders
		--list-policy-templates					- List of pre-configured policy templates
		--scan-export 						- Export a scan to Nessus XML v2 Format
			<scan_id> <history_id>
		--scan-download						- Download a scan after an export
			<scan_id> <export_file_id> <save as>
		--create-scan 						- Define a new ON DEMAND scan
			<template_policy_uuid> <scan_label> <folder_id> <policy_id> <scanner_id> <file_targets>
		--launch-scan						- Launch an on demand scan
			<scan_id> \n
	);
}

sub list_policies {
	&login;
	&get_policy;
	&logoff;
}

sub list_scans {
	&login;
	&get_scans;
	&logoff;	
}

sub list_historyID {
	&login;
	&get_historyID($n);
	&logoff;	
}

sub list_scanners {
	&login;
	&get_scanners;
	&logoff;	
}

sub list_folders {
	&login;
	&get_folders;
	&logoff;	
}

sub list_policy_templates {
	&login;
	&get_policy_templates;
	&logoff;	
}

sub scan_export {
	&login;
	&get_scan_export($n);
	&get_export_status;
	&logoff;	
}

sub scan_download {
	&login;
	&get_scan_download($n,$x,$y);
	&logoff;	
}

sub create_scan {
	&login;
	&create_nessus_scan($n,$o,$x,$y,$z);
	&logoff;	
}
sub launch_scan {
	&login;
	&launch_nessus_scan($x);
	&logoff;	
}

#print "\n";

1;

