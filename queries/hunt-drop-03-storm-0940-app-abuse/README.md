# Hunt Drop 03 | When your MSP's app becomes the attacker

**Hypothesis:** A stolen app credential signs in app-only, then grants itself roles and credentials.

**ATT&CK:** T1199, T1195, T1078.004, T1528, T1098.001, T1098.003, T1087.004, T1580, T1555.006
**Date:** 2026-10-23
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-03-storm-0940-app-abuse/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. Microsoft Threat Intelligence (21 Oct 2026): https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
2. Cybersecurity Dive (22 Oct 2026): https://www.cybersecuritydive.com/news/china-nexus-actor-attack-connectwise-cloud-backup/833727/
