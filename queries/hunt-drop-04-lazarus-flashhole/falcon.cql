// CrowdStrike Falcon (CQL) | Hunt Drop #04 | UNTESTED: tune before use
Time picker: last 14 days

// T1055: fsquirt.exe with an unusual parent
#event_simpleName=ProcessRollup2
| ImageFileName=/\\fsquirt\.exe$/i
| !in(field="ParentBaseFileName", ignoreCase=true, values=["explorer.exe","SystemSettings.exe"])
| table([@timestamp, aid, UserName, ParentBaseFileName, CommandLine])

// T1543.003: service created with a binary in a System32 sub-folder
#event_simpleName=CreateService
| ServiceImagePath=/system32\\[^\\]+\\[^\\]+\.exe/i
| groupBy([ServiceImagePath, ServiceDisplayName], function=[count(), collect([aid])])
| _count < 20

// T1036.005: services.exe child running from a System32 sub-folder
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^services\.exe$/i
| ImageFileName=/\\Windows\\System32\\[^\\]+\\[^\\]+\.exe$/i
| groupBy([ImageFileName, CommandLine], function=[count(), collect([aid])])
| _count < 20
