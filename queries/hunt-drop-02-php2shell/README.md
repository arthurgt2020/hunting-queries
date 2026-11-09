# Hunt Drop 02 | PHP2Shell: hunt PHP workers gone rogue

**Hypothesis:** A PHP web worker has been turned into a shell on the host.

**ATT&CK:** T1059.004, T1059, T1033, T1505.003, T1071, T1053.003
**Date:** 2026-10-21
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-02-php2shell/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. Sergio Albea, Detect FYI (21 Oct 2026): <https://detect.fyi/php2shell-two-critical-php-vulnerabilities-cve-2026-109618-and-cve-2026-109619-are-your-3f0a0c08f6ec>
2. Cyb3rMonk KQL hunt: <https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection/blob/main/Uncategorized/PHP2Shell.md>
3. Huntress (21 Oct 2026): <https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities>
4. Abstract Security (21 Oct 2026): <https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619>
5. Cybaverse (21 Oct 2026): <https://www.cybaverse.co.uk/en/php2shell-checker>
6. Wiz Research (21 Oct 2026): <https://www.wiz.io/blog/php2shell-php-rce>
7. PHP security release (21 Oct 2026): <https://www.php.net/archive/2026.php#2026-10-21-5>
