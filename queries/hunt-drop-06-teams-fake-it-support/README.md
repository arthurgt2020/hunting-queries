# Hunt Drop 06 | Fake "IT Support" in Teams

**Hypothesis:** An IT-desk chat becomes a remote session and a stager in under 30 minutes.

**ATT&CK:** T1566.003, T1656, T1667, T1219, T1059.001, T1204.002, T1105, T1087.002, T1018
**Date:** 2026-10-28
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-06-teams-fake-it-support/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. Arctic Wolf Labs (Shubham Dubey): Beyond the Inbox: How Threat Actors Abuse Microsoft Teams External Chat for Initial Access <https://arcticwolf.com/resources/blog/threat-actors-abuse-microsoft-teams-external-chat-for-initial-access/>
2. Techzine Global (Berry Zwets): Attackers are exploiting Teams chat as a fake IT help desk <https://www.techzine.eu/news/security/145269/attackers-are-exploiting-teams-chat-as-a-fake-it-help-desk/>
