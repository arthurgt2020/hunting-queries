# Hunt Drop 08 | Trojanised Claude Code extension: hunt the reverse SSH backdoor

**Hypothesis:** An editor loader plants an SSH key and a reverse tunnel.

**ATT&CK:** T1572, T1098.004, T1053.005, T1543.001, T1547.001, T1053.003, T1071.001
**Date:** 2026-11-02
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-08-claude-code-extension/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. Security notice — malicious version of Anthropic.claude-code (2.1.312 and 2.1.313) identified in the Cursor VS Code Extension Marketplace <https://cursor.com/blog/claude-code-extension-security-notice>
2. Inside a malicious Claude Code-branded extension and its persistent SSH backdoor <https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/>
3. Trojanized Claude Code Extension Delivered Persistent SSH Backdoor to Developer Machines <https://www.stepsecurity.io/blog/claude-code-extension-trojanized>
