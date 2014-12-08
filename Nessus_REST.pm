#!/usr/bin/perl

use strict;
use LWP;
use LWP::UserAgent;
use JSON;
use Data::Dumper;

# Self signed cert, so don't verify the host info.
BEGIN { $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0 }

# Config Variables
my $apibaseurl = 'https://127.0.0.1:8443/';
my $username = 'username';
my $password = 'password';

# Create LWP User agent (web browser)
my $ua = LWP::UserAgent->new;
$ua->agent("OSC/5.1");

sub login {
	print "\n*** Logging into Nessus server \n";
	# Create the POST request that sends the username and password
	my $req = HTTP::Request->new(POST => $apibaseurl . 'session');
	#$req->content_type('application/x-www-form-urlencoded');
	#$req->content("username=$username&password=$password");
	$req->content_type('application/json; charset=UTF-8');

	my $json = '{
		"username": "'.$username.'",
		"password": "'.$password.'"
	}';

	$req->content($json);

	our $res = $ua->request($req);

	# See is the login worked, and if so get the session token
	our $NessusToken;
	if ($res->is_success) {
		my $result = from_json($res->content);
		$NessusToken = $result->{'token'};
	} else {
		print $res->status_line . "\n";
		print $res->content . "\n";
		exit;
	};

	print "*** Received Auth Token: $NessusToken \n";

	# Update headers to include token
	our $h = new HTTP::Headers;
	$h->header('X-Cookie' => "token=$NessusToken;");
}

use vars qw( $res $NessusToken $apibaseurl $h );

sub get_policy {	
	# Display the policies (/policies)
	my $req = HTTP::Request->new('GET' , $apibaseurl . 'policies' , $h);
	$req->content_type('application/json; charset=UTF-8');

	# Send the request to the server
	$res = $ua->request($req);

	# Test for request failure
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}

	# Convert JSON data to Perl data structure
	my $policydata = from_json($res->content);

	print "\n" . "="x75 . "\n\t\t\t\tPolicy List \n" .  "="x75 . "\n";
	print "ID \t Name \t\t\t Description \t\t UUID \n" . "-"x75 . "\n";
	
	foreach my $x (@{$policydata->{'policies'}}) {
		print "$x->{'id'} \t $x->{'name'} \t\t\t $x->{'description'} \t\t\t $x->{'template_uuid'} \n";	
	};
}

sub get_scans {
	# List the Scans (/scans)
	my $req = HTTP::Request->new('GET' , $apibaseurl . 'scans' , $h);
	$req->content_type('application/json; charset=UTF-8');
	
	# Send the request to the server
	$res = $ua->request($req);
	
	# Test for failute
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}
	
	# Convert JSON data to Perl data structure
	my $scandata = from_json($res->content);
	
	print "\n" . "="x75 . "\n\t\t\t\tScan List \n" . "="x75 . "\n";	
	print "ID \t Name \t\t\t Status \t\t  \n" . "-"x75 . "\n";

	foreach my $x (@{$scandata->{'scans'}}) {
		print "$x->{'id'} \t $x->{'name'} \t\t $x->{'status'} \n";
	}
}

sub get_historyID {

	# Check if scan_id was passed
	if ($ARGV[0] eq '') {
		warn "\n*** ERROR: Expected <scan_id> \n\n";
		die;
	};
	
	my $req = HTTP::Request->new('GET' , $apibaseurl . "scans/${ARGV[0]}" , $h);
	$req->content_type('application/json; charset=UTF-8');
	
	# Send the request
	$res = $ua->request($req);
	
	# Test for failure
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}
	
	# Convert JSON data to Perl data structure
	my $historydata = from_json($res->content);

	print "\n" . "="x75 . "\n\t\t\tScan History for Scan ID: $ARGV[0] \n" . "="x75 . "\n";
	print "ID \t Status \t\t UUID\n" . "-"x75 . "\n";
	
	foreach my $x (@{$historydata->{'history'}}) {
		print "$x->{'history_id'} \t $x->{'status'} \t\t $x->{'uuid'} \n";
	};
	
}

sub get_scan_export {
	# Check if scan_id was passed
	if ($ARGV[1] eq '') {
		warn "\n*** ERROR: Expected <scan_id> <history_ID> \n\n";
		die;
	};
	
	print "\n*** Exporting Scan ID $ARGV[0] To Nessus Format with history ID $ARGV[1] \n";

	# Post to (/scans)
	my $req = HTTP::Request->new('POST' , $apibaseurl . "scans/${ARGV[0]}/export" , $h);
	$req->content_type('application/json; charset=UTF-8');

	# Generate the JSON POST data.
	my $json = '{
		"format": "nessus",
		"history_id": "'.$ARGV[1].'"
	}';

	# Populate the BODY with JSON encoded data.
	$req->content($json);
	
	# Send the request
	$res = $ua->request($req);
	print Dumper($req);
	
	# Test for failure
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}
	
	# Convert JSON data to Perl data structure
	my $postdata = from_json($res->content);
	
	print "*** Exported to file ID: $postdata->{'file'} \n";
	#print "$postdata->{'file'} \n";
	
	# Set a variable for later use.
	our $exportID=$postdata->{'file'};	
}



sub get_export_status {
	
	use vars qw( $exportID );
		
	my $req = HTTP::Request->new('GET' , $apibaseurl . "scans/${ARGV[0]}/export/${exportID}/status" , $h);
	$req->content_type('application/json; charset=UTF-8');
	
	# Send the request to the server
	$res = $ua->request($req);
	
	# Test for failute
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}	

	my $exportstatus = from_json($res->content);

	print "*** Current Export Status: $exportstatus->{'status'} \n";
	
	if ($exportstatus->{'status'} ne "ready") {
		sleep(2);
		&get_export_status;
	};
}

sub get_scan_download {

	print "*** Downloading File ID: ${ARGV[1]} For Scan ID: $ARGV[0] \n"; 
	my $req = HTTP::Request->new('GET' , $apibaseurl . "scans/${ARGV[0]}/export/${ARGV[1]}/download" , $h);
	$req->content_type('application/json; charset=UTF-8');
	
	# Send the request to the server
	$res = $ua->request($req);
	# Test for failute
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}	

	# Output results to a a file
	if ($ARGV[1] eq '') {
		warn "\n*** ERROR: Expected <scan_id> <output_file> \n\n";
		die;	
	}
	
	print "*** Saving Nessus XML v2 format file as: $ARGV[2] \n";
	open(FILE, "> $ARGV[2]") or error_msg("Failed to write report file $ARGV[2]: $!");
	print FILE $res->content;
	close FILE;
}

sub get_scanners {
	# List the Scanners (/scanners)
	my $req = HTTP::Request->new('GET' , $apibaseurl . 'scanners' , $h);
	$req->content_type('application/json; charset=UTF-8');
	
	# Send the request to the server
	$res = $ua->request($req);
	
	# Test for failute
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}
	
	# Convert JSON data to Perl data structure
	my $scannerdata = from_json($res->content);
	
	print "\n" . "="x75 . "\n\t\t\t\tScanner List \n" . "="x75 . "\n";	
	print "ID \t Name \t\t\t UUID \n" . "-"x75 . "\n";

	foreach my $x (@{$scannerdata}) {
		print "$x->{'id'} \t $x->{'name'} \t\t $x->{'uuid'} \n";
	}	

}

sub get_folders {
	# List the folders (/folders)
	my $req = HTTP::Request->new('GET' , $apibaseurl . 'folders' , $h);
	$req->content_type('application/json; charset=UTF-8');
	
	# Send the request to the server
	$res = $ua->request($req);
	
	# Test for failute
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}
	
	# Convert JSON data to Perl data structure
	my $folderdata = from_json($res->content);
	
	print "\n" . "="x75 . "\n\t\t\t\tFolder List \n" ."="x75 . "\n";	
	print "ID \t Name \n" . "-"x75 . "\n";

	foreach my $x (@{$folderdata->{'folders'}}) {
		print "$x->{'id'} \t $x->{'name'} \n";
	}	

}

sub get_policy_templates {
	# List the templates (/folders)
	my $req = HTTP::Request->new('GET' , $apibaseurl . 'editor/policy/templates' , $h);
	$req->content_type('application/json; charset=UTF-8');
	
	# Send the request to the server
	$res = $ua->request($req);
	
	# Test for failute
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}
	
	# Convert JSON data to Perl data structure
	my $folderdata = from_json($res->content);
	
	print "\n" . "="x75 . "\n\t\t\t\tPolicy Template List \n" . "="x75 . "\n";	
	print "Title \t\t\tUUID \n" . "-"x75 . "\n";

	foreach my $x (@{$folderdata->{'templates'}}) {
		print "$x->{'title'} \t\t\t $x->{'uuid'} \n";
	}	

}

sub create_nessus_scan {
	
	if ($ARGV[5] eq '') {
		warn "\n*** ERROR: Expected <template_policy_uuid> <scan_label> <folder_id> <policy_id> <scanner_id> <targets_file>\n\n";
		die;
	};	
	
	print "*** Creating new Scan $ARGV[1] \n";
	
	# Post to (/scans)
	my $req = HTTP::Request->new('POST' , $apibaseurl . "scans" , $h);
	$req->content_type('application/json; charset=UTF-8');

	# Generate the JSON POST data.
	my $json = '{
		"uuid": "'.$ARGV[0].'", 
		"settings": {
			"name": "'.$ARGV[1].'", 
			"launch": "ON_DEMAND",
			"folder_id": "'.$ARGV[2].'",
			"policy_id": "'.$ARGV[3].'",
			"scanner_id": "'.$ARGV[4].'",
			"text_targets": "'.$ARGV[5].'"
		}
	}';

	# Populate the BODY with JSON encoded data.
	$req->content($json);
	
	# Send the request
	$res = $ua->request($req);
	
	# Test for failure
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}
	
	# Convert JSON data to Perl data structure
	my $postdata = from_json($res->content);
}

sub launch_nessus_scan {
	# Check if scan_id was passed
	if ($ARGV[0] eq '') {
		warn "*** ERROR: Expected <scan_id> \n\n";
		die;
	};
	
	print "*** Launching Scan ID: $ARGV[0] \n";
	
	# Post to (/scans/{scan_id}/launch
	my $req = HTTP::Request->new('POST' , $apibaseurl . "scans/${ARGV[0]}/launch" , $h);
	$req->content_type('application/json');
	#$req->content("{\"scan_id\":\"${ARGV[0]}\"}");
	
	my $json = '{
		"scan_id": "'.$ARGV[0].'"
	}';

	# Send the request
	$req->content($json);

	our $res = $ua->request($req);	

	# Test for failure
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}
	
}

sub logoff {
	# Post to (/session)
	my $req = HTTP::Request->new('DELETE' , $apibaseurl . "session" , $h);
	$req->content_type('application/json');
	
	# Send the request
	$res = $ua->request($req);
	
	# Test for failure
	if (!$res->is_success) {
		warn $res->status_line . "\n";
		warn $res->content . "\n";
		exit
	}
}

1;






