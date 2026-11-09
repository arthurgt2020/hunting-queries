# Hunt Drop 04 | Hiding in plain System32

**Hypothesis:** Trusted software spawns a LOLBin host, then a renamed Windows binary side-loads a DLL.

**ATT&CK:** T1055, T1543.003, T1036.005, T1574.001, T1087.002, T1102.002
**Date:** 2026-10-23
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-04-lazarus-flashhole/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. Kaspersky Securelist (21 Oct 2026): https://securelist.com/lazarus-operation-flashhole/121541/
2. BleepingComputer (21 Oct 2026): https://www.bleepingcomputer.com/news/security/lazarus-hackers-use-post-quantum-cryptography-for-malware-delivery/
3. MITRE ATT&CK T1574.001: https://attack.mitre.org/techniques/T1574/001/
