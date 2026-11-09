# Hunt Drop 01 | ROMULUS ClickFix: hunt the paste-to-loader chain

**Hypothesis:** Run-box PowerShell leads to a silent MSI or passworded 7-Zip, then a loader on the host.

**ATT&CK:** T1204.004, T1059.001, T1218.007, T1574.002, T1027.013, T1027.001
**Date:** 2026-10-21
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-01-romulus-clickfix/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. Forescout Vedere Labs (15 Oct 2026): https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/
2. Huntress (28 Sep 2026, updated 14 Oct 2026): https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat
3. The Hacker News (20 Oct 2026): https://thehackernews.com/2026/10/romulus-clickfix-platform-tricks-users.html
4. Microsoft Threat Intelligence (21 Aug 2025): https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique
