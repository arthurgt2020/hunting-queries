// H1 WMI → hidden/encoded PowerShell relay (T1047, T1059.001)
#event_simpleName=ProcessRollup2 event_platform=Win
| in(field="FileName", values=["powershell.exe","pwsh.exe"], ignoreCase=true)
| ParentBaseFileName=/^wmiprvse\.exe$/i
| CommandLine=/\s-(e|enc|encodedcommand)\s|\s-w(indowstyle)?\s+hidden/i
| groupBy([aid, ComputerName], function=[count(as=execs), collect([CommandLine])])

// H3 java/w3wp → shell (T1505.003)
#event_simpleName=ProcessRollup2
| case {
  event_platform=Lin | ParentBaseFileName=/^java$/ | FileName=/^(sh|bash|dash|perl.*)$/;
  event_platform=Win | ParentBaseFileName=/^w3wp\.exe$/i | FileName=/^(cmd|powershell)\.exe$/i;
  }
| groupBy([aid, ComputerName, ParentBaseFileName, FileName], function=[count(as=execs), collect([CommandLine])])

// H2 (port-21 relay, selfJoinFilter) and the sudo vi hunt are in the full pack.
