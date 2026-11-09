// k0t post-VPN hunt. Time picker: last 14 days. Untested: tune before use.
#event_simpleName=ProcessRollup2 event_platform=Win
| case {
  FileName=/^cmd\.exe$/i ParentBaseFileName=/^services\.exe$/i CommandLine=/\/Q\s+\/c/i CommandLine=/(\\\\127\.0\.0\.1\\|__output)/i | Hit:="smbexec";
  FileName=/^cmd\.exe$/i ParentBaseFileName=/^svchost\.exe$/i CommandLine=/Windows\\Temp\\/i CommandLine=/&1/ | Hit:="atexec";
  ParentBaseFileName=/^(powershell|pwsh)\.exe$/i FileName=/^curl\.exe$/i CommandLine=/https?:\/\/\S+\.exe/i | Hit:="ps-curl-exe";
  FileName=/(meshagent|anydesk|atera|teramind|ngrok)/i | Hit:="rmm";
  FileName=/rclone/i | Hit:="rclone";
  CommandLine=/(wasabisys\.com|userstorage\.mega\.co\.nz)/i | Hit:="rclone";
  * | Hit:="";
}
| Hit!=""
| groupBy([ComputerName, UserName, Hit, FileName], function=[count(), collect([CommandLine])], limit=max)
