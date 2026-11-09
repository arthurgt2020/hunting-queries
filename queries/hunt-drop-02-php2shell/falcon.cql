// ===== H1 Where PHP runs - hosts executing PHP workers (pair with Falcon Exposure Management for versions/CVEs)
#event_simpleName=ProcessRollup2
| FileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|lsphp[0-9]*|frankenphp)$/i
| groupBy([ComputerName, event_platform, FileName, ImageFileName], function=[count(as=Executions), max(@timestamp, as=LastSeen)], limit=max)
| LastSeen := formatTime("%Y-%m-%d %H:%M", field=LastSeen, timezone="UTC")
| sort(Executions, order=desc, limit=1000)
// ===== H1c Windows/IIS hosts running php-cgi.exe below the PHP2Shell fixed builds (version from install path; filter internet-facing hosts with Falcon Exposure Management)
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^php(-cgi)?\.exe$/i
| regex("(?i)\\\\v?(?<Major>\\d+)\\.(?<Minor>\\d+)(?:\\.(?<Patch>\\d+))?\\\\php(-cgi)?\\.exe$", field=ImageFileName, strict=false)
| case {
    Major!=* | Status := "Unknown version - check binary" ;
    test(Major < 8) | Status := "EOL branch" ;
    Major=8 | test(Minor <= 1) | Status := "EOL branch" ;
    Major=8 Minor=2 | Patch!=* | Status := "8.2 - patch unknown" ;
    Major=8 Minor=2 | test(Patch < 35) | Status := "Below 8.2.35" ;
    Major=8 Minor=3 | Patch!=* | Status := "8.3 - patch unknown" ;
    Major=8 Minor=3 | test(Patch < 36) | Status := "Below 8.3.36" ;
    Major=8 Minor=4 | Patch!=* | Status := "8.4 - patch unknown" ;
    Major=8 Minor=4 | test(Patch < 27) | Status := "Below 8.4.27" ;
    Major=8 Minor=5 | Patch!=* | Status := "8.5 - patch unknown" ;
    Major=8 Minor=5 | test(Patch < 12) | Status := "Below 8.5.12" ;
    * | Status := "At or above fixed build" ;
  }
| Status!="At or above fixed build"
| groupBy([ComputerName, ImageFileName, Status], function=[count(as=Executions), min(@timestamp, as=FirstExecution), max(@timestamp, as=LastExecution), collect([ParentBaseFileName], limit=5)], limit=max)
| FirstExecution := formatTime("%Y-%m-%d %H:%M", field=FirstExecution, timezone="UTC")
| LastExecution := formatTime("%Y-%m-%d %H:%M", field=LastExecution, timezone="UTC")
| sort(Executions, order=desc, limit=1000)
// ===== H2 PHP or web worker spawning shells, interpreters or download tools
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$/i
| FileName=/^(sh|bash|dash|zsh|busybox|cmd\.exe|powershell\.exe|pwsh\.exe|python[0-9.]*(\.exe)?|perl|curl(\.exe)?|wget|nc|ncat|socat|certutil\.exe|bitsadmin\.exe)$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, ImageFileName, SHA256HashData], limit=1000)
// ===== H3 Reverse-shell and recon command lines from web workers or web accounts
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$/i
    OR UserName=/^(www-data|apache|nginx|http|wwwrun|nobody|daemon|iusr)$/i
| CommandLine=/(\/dev\/(tcp|udp)\/|mkfifo|fsockopen|n(c|cat)\s+.*-e\s|bash\s+-i|sh\s+-i|socat\s+.*exec)/i
    OR FileName=/^(whoami(\.exe)?|id|uname|hostname(\.exe)?|ipconfig\.exe|ifconfig|systeminfo\.exe)$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)
// ===== H4 PHP or script files written into web roots or temp paths by a PHP or web process
(#event_simpleName=ProcessRollup2 FileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$/i)
  OR (#event_simpleName=/^(WebScriptFileWritten|NewScriptWritten)$/ TargetFileName=/\.(php[0-9]?|phtml|phar)$/i)
| case {
    #event_simpleName=ProcessRollup2 | falconPID := TargetProcessId ;
    * | falconPID := ContextProcessId ;
  }
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=/^(WebScriptFileWritten|NewScriptWritten)$/}])
| groupBy([aid, falconPID], function=[collect([ComputerName, FileName, CommandLine, TargetFileName]), max(@timestamp, as=LastSeen)], limit=max)
| TargetFileName=/(\/var\/www\/|\/srv\/www\/|\/usr\/share\/nginx\/|public_html|wwwroot|\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/i
| LastSeen := formatTime("%Y-%m-%d %H:%M", field=LastSeen, timezone="UTC")
// ===== H5 Outbound connections from PHP workers to public IPs
(#event_simpleName=ProcessRollup2 FileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|lsphp[0-9]*|frankenphp)$/i)
  OR #event_simpleName=NetworkConnectIP4
| case {
    #event_simpleName=ProcessRollup2 | falconPID := TargetProcessId ;
    #event_simpleName=NetworkConnectIP4 | !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"]) | falconPID := ContextProcessId ;
  }
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=NetworkConnectIP4}])
| groupBy([aid, falconPID], function=[collect([ComputerName, FileName, CommandLine, RemoteAddressIP4, RemotePort]), count(RemoteAddressIP4, distinct=true, as=DistinctPublicIPs), max(@timestamp, as=LastSeen)], limit=max)
| DistinctPublicIPs >= 1
| LastSeen := formatTime("%Y-%m-%d %H:%M", field=LastSeen, timezone="UTC")
| sort(DistinctPublicIPs, order=asc, limit=1000)
// ===== H6 New web-worker parent to child pairs (first seen in the last 2 days; set the time picker to 30 days)
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(php(-fpm|-cgi)?[0-9.]*(\.exe)?|httpd|apache2|nginx|lsphp[0-9]*|frankenphp|w3wp\.exe)$/i
| groupBy([aid, ComputerName, ParentBaseFileName, FileName], function=[count(as=Executions), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen), collect([CommandLine], limit=10)], limit=max)
| test(FirstSeen > (now() - 172800000))
| FirstSeen := formatTime("%Y-%m-%d %H:%M", field=FirstSeen, timezone="UTC")
| LastSeen := formatTime("%Y-%m-%d %H:%M", field=LastSeen, timezone="UTC")
| sort(Executions, order=asc, limit=1000)
// ===== H7 Persistence by the web account - cron, SSH keys, new users
#event_simpleName=ProcessRollup2
| UserName=/^(www-data|apache|nginx|http|wwwrun|nobody|daemon)$/i
| FileName=/^(crontab|useradd|adduser|usermod|passwd|chpasswd)$/i
    OR CommandLine=/(authorized_keys|\/etc\/cron|\/var\/spool\/cron|\/etc\/sudoers|\/etc\/systemd\/system\/)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=1000)
// ===== H8 PHP fatal out-of-memory errors in ingested web/PHP logs (Next-Gen SIEM; set repository/parser for your log source)
"PHP Fatal error" "tried to allocate" "Unknown on line 0"
| groupBy([@host], function=[count(as=Errors), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)], limit=max)
| sort(Errors, order=desc)
// ===== H9 Apache child exits (AH00052) bursts - possible exploit retries
"AH00052"
| bucket(span=10m, field=[@host], function=count(as=Exits))
| Exits >= 10
