// =====================================================================
// HUNT DROP #05 | LiteLLM 1.107.0 startup-hook stealer (PRIVCOLLECT)
// Builds on Intel Drop #13 | CrowdStrike Falcon - CQL (NG-SIEM / Advanced Event Search)
// Author: Arthur Thomas (draft) | TLP:CLEAR
// STATUS: UNTESTED in a live tenant. Run as hunts first; test and tune
//         before promoting anything to a custom IOA / correlation rule.
// TIME PICKER: set to "Last 14 days" for every query below.
// Field notes (see schema-validation log in the .md):
//   Verified this run: ProcessRollup2, DnsRequest, NetworkConnectIP4, FileName,
//     ImageFileName, CommandLine, DomainName, RemoteAddressIP4, RemotePort,
//     aid, ComputerName, UserName, ContextProcessId, TargetProcessId.
//   NOT verified this run (marked "UNVERIFIED"): ParentBaseFileName,
//     file-write events (*Written) and TargetFileName. Check in your
//     Falcon event data dictionary before use.
// =====================================================================


// ---------------------------------------------------------------------
// H0 - Exposure scoping: LiteLLM installs / pulls (T1195.001)
// Hypothesis: pip/uv/poetry/docker runs for litellm on 21 Oct or pinned
//   to 1.107.0 identify hosts that may hold the bad build.
// Expected noise: Low-Medium (presence = exposure, not compromise).
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| CommandLine=/litellm/i
| CommandLine=/(pip3?|uv|poetry|pipx|docker|podman)(\.exe)?\s/i
| CommandLine=/1\.107\.0|latest|main-stable|main-latest|ghcr\.io\/berriai/i
| table([@timestamp, aid, ComputerName, UserName, FileName, CommandLine], limit=1000)


// ---------------------------------------------------------------------
// H1 - Python startup-hook implant in a library directory
// ATT&CK: T1546.018, T1195.001
// Hypothesis: cook.pth / cook.py / sitecustomize.py written into
//   site-packages / dist-packages outside the litellm folder.
// Expected noise: Low for these names; sitecustomize.py has rare
//   legitimate uses (distro / conda builds).
// UNVERIFIED: whether your sensor emits a *Written event for .py/.pth
//   files, and the TargetFileName field. If no results, pivot with
//   Falcon RTR / Falcon Forensics file listing of site-packages instead.
// ---------------------------------------------------------------------
#event_simpleName=/Written$/                                  // UNVERIFIED event coverage
| TargetFileName=/(site|dist)-packages/i                      // UNVERIFIED field
| TargetFileName=/[\\\/](cook\.pth|cook\.py|sitecustomize\.py)$/i
| table([@timestamp, aid, ComputerName, #event_simpleName, TargetFileName, ContextProcessId], limit=1000)


// ---------------------------------------------------------------------
// H2 - Python spawning crypto staging, inline DB theft or discovery
// ATT&CK: T1059.006, T1027.013, T1552.001, T1082, T1016
// Hypothesis: openssl with ".pc_e_" staging, python -c querying
//   LiteLLM_CredentialsTable / LiteLLM_ProxyModelTable with query_raw,
//   or a Windows discovery burst, all with a Python parent.
// Expected noise: Low for openssl/DB; Medium for discovery (need >= 3).
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(python|pythonw|platform-python|python3(\.\d+)?)(\.exe)?$/i   // UNVERIFIED field
| case {
    FileName=/^openssl(\.exe)?$/i CommandLine=/\.pc_e_/ | Signal := "OpenSSL .pc_e_ staging";
    CommandLine=/LiteLLM_(Credentials|ProxyModel)Table/i CommandLine=/query_raw/ | Signal := "Inline LiteLLM DB pull";
    FileName=/^(systeminfo|ipconfig|route|arp|netstat)\.exe$/i | Signal := "Discovery child";
    * | Signal := "none" }
| Signal!="none"
| groupBy([aid, ComputerName, Signal], function=[count(as=Hits), count(field=FileName, distinct=true, as=Kinds), collect([CommandLine])])
| case { Signal!="Discovery child" | Keep := "y";            // keep all high-signal rows
         test(Kinds >= 3) | Keep := "y" }                    // discovery only if >= 3 distinct tools
| sort(Hits, order=desc, limit=500)


// ---------------------------------------------------------------------
// H3a - Python DNS: dead-drop pointer and exfil host (T1102.001, T1105)
// Expected noise: Medium for raw GitHub (pip/tools); Low for IOC host.
// ---------------------------------------------------------------------
#event_simpleName=DnsRequest
| DomainName=/(^|\.)litellm\.dev$|^raw\.githubusercontent\.com$/i
| join(query={#event_simpleName=ProcessRollup2 | FileName=/^(python|pythonw|platform-python|python3(\.\d+)?)(\.exe)?$/i},
       field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[FileName, CommandLine], mode=inner)
| groupBy([aid, ComputerName, DomainName], function=[count(as=Lookups), collect([CommandLine])])


// ---------------------------------------------------------------------
// H3b - Python to instance metadata from non-cloud hosts (T1552.005)
// Expected noise: High on cloud VMs / build agents - exclude by host group.
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4 RemoteAddressIP4="169.254.169.254"
| join(query={#event_simpleName=ProcessRollup2 | FileName=/^(python|pythonw|platform-python|python3(\.\d+)?)(\.exe)?$/i},
       field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[FileName, CommandLine], mode=inner)
| groupBy([aid, ComputerName, RemotePort], function=[count(as=Conns), collect([CommandLine])])


// ---------------------------------------------------------------------
// IOC SWEEP (Microsoft / Socket, Oct 2026) - retro-scoping only
// ---------------------------------------------------------------------
#event_simpleName=DnsRequest
| in(field="DomainName", ignoreCase=true, values=["litellm.dev", "www.litellm.dev"])
| table([@timestamp, aid, ComputerName, DomainName, ContextProcessId], limit=1000)
