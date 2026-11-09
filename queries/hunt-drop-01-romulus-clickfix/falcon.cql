CrowdStrike Falcon (CQL) | H1 multi-signal | PART 1 of 2
// Paste Part 1 + Part 2 together as ONE query. Time picker: last 14 days.
#event_simpleName=ProcessRollup2 event_platform=Win
| case {
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/(irm|iwr|curl|https?:\/\/)\s*\d{8,10}(\/|:|\s|$)/i
      | Signal := "1-PS stager decimal-IP download";
    FileName=/^(powershell|pwsh)\.exe$/i ParentBaseFileName=/^explorer\.exe$/i CommandLine=/(https?:\/\/|irm\s|iwr\s|iex|invoke-(restmethod|webrequest|expression)|net\.webclient|download(string|file|data))/i
      | Signal := "1-PS download cradle; explorer.exe parent";
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/[-\/–—―](w[a-z]*\s+h|e[a-z]*\s+bypass|e[a-z]*\s+[a-z0-9+\/=]{40,})/i CommandLine=/(https?:\/\/|irm\s|iwr\s|iex|invoke-(restmethod|webrequest|expression)|net\.webclient|download(string|file|data))/i
      | Signal := "1-PS stager hidden/bypass + download";
    FileName=/^msiexec\.exe$/i CommandLine=/[-\/–—―](qn|quiet)/i CommandLine=/\\[0-9a-f]{32}_[^\\]+\.msi/i
      | Signal := "2-Silent MSI with GUID-prefixed name";

CrowdStrike Falcon (CQL) | H1 multi-signal | PART 2 of 2
// Continues directly from Part 1.
    FileName=/^msiexec\.exe$/i ParentBaseFileName=/^(powershell|pwsh)\.exe$/i CommandLine=/[-\/–—―](qn|quiet)/i CommandLine=/(\\AppData\\Local\\Temp\\|%temp%)/i
      | Signal := "2-Silent MSI from TEMP launched by PowerShell";
    FileName=/^(DeElevate64|COTFileReadApp)\.exe$/i ImageFileName=/\\AppData\\Local\\Programs\\/i ParentBaseFileName=/^msiexec\.exe$/i
      | Signal := "3-Candidate host started by msiexec from user Programs";
    ImageFileName=/\\AppData\\Local\\Programs\\(Stardock Smart DeElevation Tool|Advanced Printer Configuration Reader)\\/i
      | Signal := "3-Process from lure install folder";
  }
| Signal=*
| groupBy(
    [aid, ComputerName],
    function=[
      count(Signal, distinct=true, as=signalTypes),
      count(as=hits),
      collect([Signal, UserName, CommandLine]),
      min(@timestamp, as=firstSeen),
      max(@timestamp, as=lastSeen)
    ],
    limit=max
  )
| sort(field=[signalTypes, hits], order=desc, limit=200)
