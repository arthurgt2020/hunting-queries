// =====================================================================
// HUNT DROP #06 | Fake "IT Support" in Teams external chat -> Quick Assist/RMM -> PowerShell/MSI -> pythonw implant
// Builds on Intel Drop #15 | CrowdStrike Falcon (CQL) - Next-Gen SIEM / Advanced Event Search
// Author: Arthur T. (draft) | TLP:CLEAR | Drafted 2026-10-28
// STATUS: UNTESTED in a live tenant. These are HUNTS. Test and tune before any use; tuned versions may later be
//         promoted to a custom IOA / correlation rule (see notes in the .md).
// TIME PICKER: set to Last 14 days for every query below.
// FIELD VERIFICATION: #event_simpleName, event_platform, aid, ImageFileName, CommandLine, UserSid, case{}, groupBy(),
//   collect(), count(distinct=true), regex named captures were checked against public LogScale/Falcon tutorial docs.
//   Lines marked  // UNVERIFIED FIELD  use field names that are standard in Falcon telemetry but could not be confirmed
//   on a public documentation page in this run - confirm them in your Event Search field list before use.
// H1 (Teams chat / email bombing) has NO Falcon endpoint equivalent: Teams chat events are not endpoint telemetry.
//   If you ingest Microsoft 365 audit logs into NG-SIEM, build H1 on that parser's field names.
// =====================================================================


// ---------------------------------------------------------------------
// H2 | Remote-assist tool + user-run PowerShell/MSI stager + pythonw from user path on the same host
// ATT&CK: T1219 | T1059.001 | T1204.002 | T1105
// Hypothesis: Quick Assist/RMM launch, then explorer -> powershell download, msiexec from user/URL paths,
//             PowershellCleaner script, pythonw.exe from AppData. Two or more stages on one host = hunt lead.
// Expected noise: MEDIUM - genuine help-desk sessions; exclude sanctioned RMM and signed software deployment paths.
// Note: this groups co-occurrence across the time window; check ordering/timing (target: <30 min) during triage.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| case {
    ImageFileName=/\\(quickassist|msra|anydesk|teamviewer|ateraagent|client32|screenconnect\.clientservice)\.exe$/i
      | Stage := "1_remote_assist" ;
    ImageFileName=/\\(powershell|pwsh)\.exe$/i ParentBaseFileName=/^explorer\.exe$/i CommandLine=/(https?:|blob\.core\.windows\.net|\.msi|DownloadFile|Invoke-WebRequest|iwr\s|Start-BitsTransfer)/i
      | Stage := "2_ps_stager" ;   // UNVERIFIED FIELD: ParentBaseFileName
    ImageFileName=/\\msiexec\.exe$/i CommandLine=/(https?:|\\AppData\\|\\Temp\\)/i
      | Stage := "2_msiexec_user_path" ;
    CommandLine=/PowershellCleaner/i
      | Stage := "3_cleaner_script" ;
    ImageFileName=/\\(AppData|Temp|ProgramData)\\.*\\pythonw\.exe$/i
      | Stage := "4_pythonw_user_path" ;
  }
| groupBy([aid], function=[count(Stage, distinct=true, as=StageCount), collect([Stage, ImageFileName, CommandLine, UserSid])], limit=max)
| test(StageCount >= 2)
| sort(StageCount, order=desc)


// ---------------------------------------------------------------------
// H2b | High-fidelity artefacts named in the source: PowershellCleaner script path, archive6.zip, ss.py
// ATT&CK: T1059.001 | T1036 | T1105      Expected noise: LOW
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(\\AppData\\Local\\PowershellCleaner\\|archive6\.zip|\\ss\.py)/i
| table([@timestamp, aid, UserSid, ImageFileName, CommandLine], limit=1000)


// ---------------------------------------------------------------------
// H3 | pythonw/python making LDAP / Global Catalog connections (implant AD recon via adsisearcher)
// ATT&CK (analyst mapping): T1087.002 | T1018
// Expected noise: LOW-MEDIUM - admin/dev Python LDAP tooling; allow-list by host and path.
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4 event_platform=Win
| in(field=RemotePort, values=["389", "636", "3268", "3269"])   // UNVERIFIED FIELD: RemotePort
| ContextBaseFileName=/^pythonw?\.exe$/i                          // UNVERIFIED FIELD: ContextBaseFileName
| groupBy([aid, ContextBaseFileName], function=[count(as=Conns), collect([RemoteAddressIP4, RemotePort])], limit=max)   // UNVERIFIED FIELD: RemoteAddressIP4
| sort(Conns, order=desc)


// ---------------------------------------------------------------------
// H3c | Two or more remote-access tool families on the same host (second RMM for persistence)
// ATT&CK: T1219      Expected noise: MEDIUM - exclude your sanctioned pair of tools.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(?<RmmTool>quickassist|msra|anydesk|teamviewer|ateraagent|client32|screenconnect\.clientservice)\.exe$/i
| groupBy([aid], function=[count(RmmTool, distinct=true, as=RmmFamilies), collect([RmmTool, UserSid])], limit=max)
| test(RmmFamilies >= 2)
| sort(RmmFamilies, order=desc)


// ---------------------------------------------------------------------
// IOC sweep | DNS lookups for published lure / payload / C2 domains (Arctic Wolf appendices). Low longevity.
// ATT&CK: T1583.001 | T1105
// ---------------------------------------------------------------------
#event_simpleName=DnsRequest event_platform=Win
| in(field=DomainName, ignoreCase=true, values=["update-software.top", "expertassist.top", "getsystembridge.top", "techrelay.top", "it-assistant.top", "get-help-systems.top", "fix-it.top", "helpdesk-support-us-ny.com", "helpdesk-call.com", "itdeskassist.com", "kilan.com.pl", "saludcentro.gov.co", "ggc.com.ph", "scapini.com.br"])   // UNVERIFIED FIELD: DomainName
| groupBy([aid, DomainName], function=[count(as=Lookups)], limit=max)
