# Hunt Drop 09 | LLMJacking: find the hijacked AI before the bill does

**Hypothesis:** A stolen cloud identity is reselling our AI quota.

**ATT&CK:** T1078.004, T1580, T1562.008, T1496.004, T1136.003, T1098.001, T1098.003
**Date:** 2026-11-04
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-09-llmjacking/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. The Rise of LLMJacking: How Threat Actors Monetize Compromised Cloud and Model Resources <https://cloud.google.com/blog/topics/threat-intelligence/llmjacking-monetizing-compromised-cloud-models/>
2. Monitor Amazon Bedrock API calls using CloudTrail <https://docs.aws.eu/bedrock/latest/userguide/logging-using-cloudtrail.html>
3. Resource Hijacking: Cloud Service Hijacking (T1496.004) <https://attack.mitre.org/techniques/T1496/004/>
4. CVE-2026-40217 <https://nvd.nist.gov/vuln/detail/CVE-2026-40217>
5. LiteLLM vulnerability chain enables full AI gateway takeover <https://dev.to/etairos/litellm-vulnerability-chain-enables-full-ai-gateway-takeover-from-default-account-kh2>
6. cs-shadowbq/CQL-Queries <https://gh.r-mj.com/cs-shadowbq/CQL-Queries>
7. Cool Query Friday: hunting newly seen DNS <https://nyc1.lr.ggtyler.dev/r/crowdstrike/comments/1fqokic/20240927_cool_query_friday_hunting_newly_seen_dns>
