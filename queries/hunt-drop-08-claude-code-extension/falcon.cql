// =====================================================================
// HUNT DROP #08 | Trojanised Claude Code extension (Cursor marketplace)
// Builds on Intel Drop #24 | CrowdStrike Falcon CQL (NG-SIEM / Advanced Event Search)
// Telemetry: Falcon Insight XDR sensors on Win/Mac/Lin; NG-SIEM or Event Search
// STATUS: UNTESTED in a live tenant. Test and tune before production use or
//         promotion to a custom IOA / correlation rule.
// TIME: set the time picker to "Last 14 days" (exposure window was
//       29 Oct 2026 09:27-20:35 UTC).
// CQL double-check: cqlsearch.com was blocked by this run's network allowlist;
//   fallback checks recorded in hunt-drop-08 markdown. Lines marked
//   [UNVERIFIED] use names not confirmed against a page opened this run.
// =====================================================================


// ---------------------------------------------------------------------
// H1a | Reverse SSH tunnel to own :22 with non-interactive options
// ATT&CK: T1572; T1021.004 (analyst)
// Expected noise: LOW-MEDIUM
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| ImageFileName=/(\\|\/)(ssh|ssh\.exe|autossh)$/i
| CommandLine=/-R\s+'?[^\s']*(localhost|127\.0\.0\.1):22/
| CommandLine=/StrictHostKeyChecking=no|BatchMode=yes|ExitOnForwardFailure=yes|-M\s+0/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine], function=[count(), collect([ParentBaseFileName])])  // ParentBaseFileName [UNVERIFIED this run]
| sort(_count, limit=200)


// ---------------------------------------------------------------------
// H1b | SSH server enablement + look-alike persistence names
// ATT&CK: T1053.005; T1053.003 (Microsoft); T1543.001; T1547.001;
//         T1036.004 (analyst)
// Expected noise: MEDIUM (real Sysinternals Sysmon tasks, IT OpenSSH scripts)
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| CommandLine=/systemsetup.+setremotelogin\s+on|Add-WindowsCapability.+OpenSSH\.Server|systemctl.+enable.+sshd|schtasks.+\/create.+SysMon|com\.apple\.sysmond|\.config[\\\/]\.?smt|smt\.cmd|sysmon\.cmd/i
| case {
    CommandLine=/setremotelogin|OpenSSH\.Server|sshd/i | Behaviour := "ssh-server-enable";
    CommandLine=/SysMon/ | Behaviour := "schtask-SysMon";
    CommandLine=/com\.apple\.sysmond/i | Behaviour := "launchagent-sysmond";
    * | Behaviour := "smt-script";
  }
| table([@timestamp, ComputerName, UserName, Behaviour, ImageFileName, CommandLine, ParentBaseFileName])  // ParentBaseFileName [UNVERIFIED this run]


// ---------------------------------------------------------------------
// H1c | Scheduled task registered with the "SysMon" name (Windows)
// ATT&CK: T1053.005
// [UNVERIFIED] event ScheduledTaskRegistered and field TaskName were not
//   confirmed against a page opened this run; validate in Event Search first.
// ---------------------------------------------------------------------
#event_simpleName=ScheduledTaskRegistered   // [UNVERIFIED]
| TaskName=/SysMon/i                         // [UNVERIFIED]
| table([@timestamp, ComputerName, UserName, TaskName])


// ---------------------------------------------------------------------
// H2  | Beacon / tunnel IOC sweep + unusual port 8099 egress
// ATT&CK: T1195.002; T1071.001; T1572 (analyst for 1195.002/1071.001)
// IOC from Cursor / Microsoft / StepSecurity; C2 reported offline.
// Expected noise: LOW
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4="134.209.82.225" OR RemotePort="8099"
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=[count(), collect([aid])])
| sort(_count, limit=200)
