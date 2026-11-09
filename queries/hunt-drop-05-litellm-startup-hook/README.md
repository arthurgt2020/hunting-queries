# Hunt Drop 05 | Hunting the LiteLLM 1.107.0 startup-hook stealer

**Hypothesis:** Python itself runs the stealer on every start.

**ATT&CK:** T1546.018, T1195.001, T1027.013, T1552.001, T1082, T1016, T1102.001, T1552.005
**Date:** 2026-10-26
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-05-litellm-startup-hook/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. Microsoft Threat Intelligence (23 Oct 2026): <https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/>
2. Socket (21 Oct 2026): <https://socket.dev/blog/litellm-compromise>
3. LiteLLM (BerriAI) (23 Oct 2026): <https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain>
