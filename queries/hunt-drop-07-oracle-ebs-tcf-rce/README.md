# Hunt Drop 07 | Oracle EBS: hunting the TCF servlet RCE

**Hypothesis:** An EBS Java process or app account starts a shell.

**ATT&CK:** T1190, T1059.004, T1082, T1016, T1049, T1071.001, T1571
**Date:** 2026-10-30
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-07-oracle-ebs-tcf-rce/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. CVE-2026-101767: Oracle EBS SQL Injection RCE <https://horizon3.ai/attack-research/vulnerabilities/cve-2026-101767/>
2. Oracle Critical Patch Update Advisory – October 2026 <https://www.oracle.com/security-alerts/cpuoct2026.html>
3. Hackers Actively Exploiting New Oracle EBS RCE Vulnerability <https://cybersecuritynews.com/oracle-ebs-rce-exploited/>
4. Oracle E-Business Suite CVE-2026-101767: Critical (CVSS 9.8) Unauthenticated Flaw <https://www.rescana.com/post/oracle-e-business-suite-cve-2026-101767-prepare-now>
5. Oracle's October 2026 update: an unauthenticated E-Business Suite RCE sat behind a servlet the default firewall allows <https://r3konx.asia/oracle-october-2026-cpu-ebs-cve-2026-101767-default-allowlisted-servlet/>
6. Oracle E-Business Suite Zero-Day Exploited in Widespread Extortion Campaign <https://cloud.google.com/blog/topics/threat-intelligence/oracle-ebusiness-suite-zero-day-exploitation>
7. Threat-hunting-queries.md <https://github.com/amjcyber/crowdstrike/blob/main/Threat-hunting-queries.md>
