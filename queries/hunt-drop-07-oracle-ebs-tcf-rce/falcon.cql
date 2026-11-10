// =====================================================================
// HUNT DROP #07 | Oracle EBS CVE-2026-101767 (TCF servlet SQLi -> RCE)
// Builds on Intel Drop #21 | CrowdStrike Falcon CQL (NG-SIEM / Advanced Event Search)
// Author: Arthur T. (draft) | TLP:CLEAR
// STATUS: UNTESTED in a live tenant. Test and tune before any use as a
// detection. Requires Falcon Insight sensors on the Linux EBS app-tier hosts.
// TIME PICKER: set to Last 14 days for every query below.
// EDIT FIRST: host names, accounts and the $APPLPTMP path.
// FIELD CAVEATS (could not be verified against public docs this run):
//   [UNVERIFIED-1] UserName population on Linux ProcessRollup2 events.
//   [UNVERIFIED-2] RemotePort field name in NG-SIEM (legacy: RemotePort_decimal).
// =====================================================================


// ---------------------------------------------------------------------
// H1 | EBS Java tier spawns a shell
// ATT&CK: T1190, T1059.004 | Noise: Low-Medium
// Hypothesis: EBS Java process starts sh/bash after exploitation.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| in(ComputerName, ignoreCase=true, values=["ebs-app01","ebs-app02"])   // EDIT
| ParentBaseFileName=/^java$/i
| FileName=/^(sh|bash|dash|ksh)$/i
| case {
    CommandLine=/(\/dev\/tcp|bash -i|base64|curl|wget|whoami|uname|ifconfig|ip addr|netstat|\/proc\/net\/arp|\/etc\/hosts|\/etc\/fstab)/i | Suspicious:="yes";
    * | Suspicious:="no";
  }
| groupBy([ComputerName, UserName, Suspicious], function=[count(as=Hits), collect([CommandLine])])   // [UNVERIFIED-1]
| sort(Hits, order=asc, limit=1000)


// ---------------------------------------------------------------------
// H2 | EBS OS account runs host recon or a reverse shell
// ATT&CK: T1059.004, T1082, T1016, T1049, T1057 | Noise: Medium
// Hypothesis: EBS account (oracle/applmgr) runs recon or /dev/tcp shell.
// Parent not filtered: Horizon3 says the shell comes via Concurrent Manager.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| in(UserName, ignoreCase=true, values=["oracle","applmgr"])   // EDIT; [UNVERIFIED-1]
| CommandLine=/(\/dev\/tcp\/|bash\s+-i|\bip\s+addr\b|\bifconfig\b|netstat\s+-an|\barp\s+-a\b|\/proc\/net\/arp|cat\s+\/etc\/(hosts|fstab)|ps\s+-?aux|\bwhoami\b)/i
| groupBy([ComputerName, UserName, ParentBaseFileName], function=[count(as=Hits), collect([CommandLine])])
| sort(Hits, order=asc, limit=1000)


// ---------------------------------------------------------------------
// H3a | Execution from $APPLPTMP
// ATT&CK: T1190 (post-exploitation artefact; analyst mapping) | Noise: Medium
// Hypothesis: a dropped file in $APPLPTMP is executed. Falcon has no
// verified generic Linux file-write event for this hunt, so this hunts
// EXECUTION from the path instead (telemetry gap noted).
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| ImageFileName=/^\/CHANGE\/ME\/applptmp\//i     // EDIT: your $APPLPTMP path
| groupBy([ComputerName, ImageFileName, ParentBaseFileName], function=[count(as=Execs), collect([CommandLine])])
| sort(Execs, order=asc, limit=1000)


// ---------------------------------------------------------------------
// H3b | EBS app tier connects to public IPs
// ATT&CK: T1071.001, T1571 (analyst mapping) | Noise: Low if egress restricted
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4
| in(ComputerName, ignoreCase=true, values=["ebs-app01","ebs-app02"])   // EDIT
| !cidr(RemoteAddressIP4, subnet="10.0.0.0/8")
| !cidr(RemoteAddressIP4, subnet="172.16.0.0/12")
| !cidr(RemoteAddressIP4, subnet="192.168.0.0/16")
| !cidr(RemoteAddressIP4, subnet="127.0.0.0/8")
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=count(as=Conns))   // [UNVERIFIED-2]
| sort(Conns, order=asc, limit=1000)


// ---------------------------------------------------------------------
// IOC SWEEP: none. No IOCs published for CVE-2026-101767 as of 30 Oct 2026.
// ---------------------------------------------------------------------
