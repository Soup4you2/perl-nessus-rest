perl-nessus-rest
================

Perl interface to using the Nessus REST API

Configuration:
================
Edit the following variables inside the Nessus_REST.pm file
```perl
  # Config Variables
  my $apibaseurl = 'https://127.0.0.1:8834/';
  my $username = 'username';
  my $password = 'password';
  ```

Usage:
================
    usage: ./REST_runner.pl <command> [ <command-options> ]

    Commands:
    --------------------------------------------------------------------------------------------------------
    --list-policies                                         - List the user created scan policies
    --list-scans                                            - List scan history and status
    --get-historyID                                         - List the history of a given scan
            <scan_id>
    --list-scanners                                         - List all the scanners
    --list-folders                                          - List the available scan folders
    --list-policy-templates                                 - List of pre-configured policy templates
    --scan-export                                           - Export a scan to Nessus XML v2 Format
            <scan_id>
    --scan-download                                         - Download a scan after an export
            <scan_id> <export_file_id> <save as>
    --create-scan                                           - Define a new ON DEMAND scan
            <template_policy_uuid> <scan_label> <folder_id> <policy_id> <scanner_id> <file_targets>
    --launch-scan                                           - Launch an on demand scan
            <scan_id>


