# Hunt Drop 12 | Hunting Operation Snowball: AI-run relays and shells

**Hypothesis:** An AI-driven operator is relaying TCP through WMI-spawned PowerShell and planting web shells on Java and IIS servers.

**ATT&CK:** T1047, T1059.001, T1105, T1090, T1505.003, T1548.003, T1543.002
**Date:** 2026-11-11
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-12-operation-snowball/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. Malbear Labs (8 Nov 2026): <https://malbearlabs.com/posts/operation-snowball-inside-an-autonomous-ai-intrusion-campaign>
2. Cyber Security News (9 Nov 2026): <https://cybersecuritynews.com/jailbroken-deepseek-ai-agent-breach/>
