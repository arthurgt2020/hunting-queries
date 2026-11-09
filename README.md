# Hunting queries

Hypothesis-driven hunts from the Hunt Drop series (Monday, Wednesday and Friday), with Microsoft Defender KQL and CrowdStrike Falcon CQL. Full write-ups: https://arkknight.si/hunting/

These queries are untested in your environment. Treat them as hunts and tune them before any use as detections. Everything here is shared at TLP:CLEAR and is built from public sources.

| Drop | Title | ATT&CK | KQL | CQL |
|---|---|---|---|---|
| 10 | [Edge-to-Domain: Hunting the k0t Post-VPN Playbook](queries/hunt-drop-10-edge-to-domain-k0t/) | T1569.002, T1053.005, T1059.001, T1219, T1567.002 | yes | yes |
| 9 | [LLMJacking: find the hijacked AI before the bill does](queries/hunt-drop-09-llmjacking/) | T1078.004, T1580, T1562.008, T1496.004, T1136.003, T1098.001, T1098.003 | yes | yes |
| 8 | [Trojanised Claude Code extension: hunt the reverse SSH backdoor](queries/hunt-drop-08-claude-code-extension/) | T1572, T1098.004, T1053.005, T1543.001, T1547.001, T1053.003, T1071.001 | yes | yes |
| 7 | [Oracle EBS: hunting the TCF servlet RCE](queries/hunt-drop-07-oracle-ebs-tcf-rce/) | T1190, T1059.004, T1082, T1016, T1049, T1071.001, T1571 | yes | yes |
| 6 | [Fake "IT Support" in Teams](queries/hunt-drop-06-teams-fake-it-support/) | T1566.003, T1656, T1667, T1219, T1059.001, T1204.002, T1105, T1087.002, T1018 | yes | yes |
| 5 | [Hunting the LiteLLM 1.107.0 startup-hook stealer](queries/hunt-drop-05-litellm-startup-hook/) | T1546.018, T1195.001, T1027.013, T1552.001, T1082, T1016, T1102.001, T1552.005 | yes | yes |
| 4 | [Hiding in plain System32](queries/hunt-drop-04-lazarus-flashhole/) | T1055, T1543.003, T1036.005, T1574.001, T1087.002, T1102.002 | yes | yes |
| 3 | [When your MSP's app becomes the attacker](queries/hunt-drop-03-storm-0940-app-abuse/) | T1199, T1195, T1078.004, T1528, T1098.001, T1098.003, T1087.004, T1580, T1555.006 | yes | yes |
| 2 | [PHP2Shell: hunt PHP workers gone rogue](queries/hunt-drop-02-php2shell/) | T1059.004, T1059, T1033, T1505.003, T1071, T1053.003 | yes | yes |
| 1 | [ROMULUS ClickFix: hunt the paste-to-loader chain](queries/hunt-drop-01-romulus-clickfix/) | T1204.004, T1059.001, T1218.007, T1574.002, T1027.013, T1027.001 | yes | yes |

## By ATT&CK technique

- **T1016**: [Hunting the LiteLLM 1.107.0 startup-hook stealer](queries/hunt-drop-05-litellm-startup-hook/), [Oracle EBS: hunting the TCF servlet RCE](queries/hunt-drop-07-oracle-ebs-tcf-rce/)
- **T1018**: [Fake "IT Support" in Teams](queries/hunt-drop-06-teams-fake-it-support/)
- **T1027.001**: [ROMULUS ClickFix: hunt the paste-to-loader chain](queries/hunt-drop-01-romulus-clickfix/)
- **T1027.013**: [ROMULUS ClickFix: hunt the paste-to-loader chain](queries/hunt-drop-01-romulus-clickfix/), [Hunting the LiteLLM 1.107.0 startup-hook stealer](queries/hunt-drop-05-litellm-startup-hook/)
- **T1033**: [PHP2Shell: hunt PHP workers gone rogue](queries/hunt-drop-02-php2shell/)
- **T1036.005**: [Hiding in plain System32](queries/hunt-drop-04-lazarus-flashhole/)
- **T1049**: [Oracle EBS: hunting the TCF servlet RCE](queries/hunt-drop-07-oracle-ebs-tcf-rce/)
- **T1053.003**: [PHP2Shell: hunt PHP workers gone rogue](queries/hunt-drop-02-php2shell/), [Trojanised Claude Code extension: hunt the reverse SSH backdoor](queries/hunt-drop-08-claude-code-extension/)
- **T1053.005**: [Trojanised Claude Code extension: hunt the reverse SSH backdoor](queries/hunt-drop-08-claude-code-extension/), [Edge-to-Domain: Hunting the k0t Post-VPN Playbook](queries/hunt-drop-10-edge-to-domain-k0t/)
- **T1055**: [Hiding in plain System32](queries/hunt-drop-04-lazarus-flashhole/)
- **T1059**: [PHP2Shell: hunt PHP workers gone rogue](queries/hunt-drop-02-php2shell/)
- **T1059.001**: [ROMULUS ClickFix: hunt the paste-to-loader chain](queries/hunt-drop-01-romulus-clickfix/), [Fake "IT Support" in Teams](queries/hunt-drop-06-teams-fake-it-support/), [Edge-to-Domain: Hunting the k0t Post-VPN Playbook](queries/hunt-drop-10-edge-to-domain-k0t/)
- **T1059.004**: [PHP2Shell: hunt PHP workers gone rogue](queries/hunt-drop-02-php2shell/), [Oracle EBS: hunting the TCF servlet RCE](queries/hunt-drop-07-oracle-ebs-tcf-rce/)
- **T1071**: [PHP2Shell: hunt PHP workers gone rogue](queries/hunt-drop-02-php2shell/)
- **T1071.001**: [Oracle EBS: hunting the TCF servlet RCE](queries/hunt-drop-07-oracle-ebs-tcf-rce/), [Trojanised Claude Code extension: hunt the reverse SSH backdoor](queries/hunt-drop-08-claude-code-extension/)
- **T1078.004**: [When your MSP's app becomes the attacker](queries/hunt-drop-03-storm-0940-app-abuse/), [LLMJacking: find the hijacked AI before the bill does](queries/hunt-drop-09-llmjacking/)
- **T1082**: [Hunting the LiteLLM 1.107.0 startup-hook stealer](queries/hunt-drop-05-litellm-startup-hook/), [Oracle EBS: hunting the TCF servlet RCE](queries/hunt-drop-07-oracle-ebs-tcf-rce/)
- **T1087.002**: [Hiding in plain System32](queries/hunt-drop-04-lazarus-flashhole/), [Fake "IT Support" in Teams](queries/hunt-drop-06-teams-fake-it-support/)
- **T1087.004**: [When your MSP's app becomes the attacker](queries/hunt-drop-03-storm-0940-app-abuse/)
- **T1098.001**: [When your MSP's app becomes the attacker](queries/hunt-drop-03-storm-0940-app-abuse/), [LLMJacking: find the hijacked AI before the bill does](queries/hunt-drop-09-llmjacking/)
- **T1098.003**: [When your MSP's app becomes the attacker](queries/hunt-drop-03-storm-0940-app-abuse/), [LLMJacking: find the hijacked AI before the bill does](queries/hunt-drop-09-llmjacking/)
- **T1098.004**: [Trojanised Claude Code extension: hunt the reverse SSH backdoor](queries/hunt-drop-08-claude-code-extension/)
- **T1102.001**: [Hunting the LiteLLM 1.107.0 startup-hook stealer](queries/hunt-drop-05-litellm-startup-hook/)
- **T1102.002**: [Hiding in plain System32](queries/hunt-drop-04-lazarus-flashhole/)
- **T1105**: [Fake "IT Support" in Teams](queries/hunt-drop-06-teams-fake-it-support/)
- **T1136.003**: [LLMJacking: find the hijacked AI before the bill does](queries/hunt-drop-09-llmjacking/)
- **T1190**: [Oracle EBS: hunting the TCF servlet RCE](queries/hunt-drop-07-oracle-ebs-tcf-rce/)
- **T1195**: [When your MSP's app becomes the attacker](queries/hunt-drop-03-storm-0940-app-abuse/)
- **T1195.001**: [Hunting the LiteLLM 1.107.0 startup-hook stealer](queries/hunt-drop-05-litellm-startup-hook/)
- **T1199**: [When your MSP's app becomes the attacker](queries/hunt-drop-03-storm-0940-app-abuse/)
- **T1204.002**: [Fake "IT Support" in Teams](queries/hunt-drop-06-teams-fake-it-support/)
- **T1204.004**: [ROMULUS ClickFix: hunt the paste-to-loader chain](queries/hunt-drop-01-romulus-clickfix/)
- **T1218.007**: [ROMULUS ClickFix: hunt the paste-to-loader chain](queries/hunt-drop-01-romulus-clickfix/)
- **T1219**: [Fake "IT Support" in Teams](queries/hunt-drop-06-teams-fake-it-support/), [Edge-to-Domain: Hunting the k0t Post-VPN Playbook](queries/hunt-drop-10-edge-to-domain-k0t/)
- **T1496.004**: [LLMJacking: find the hijacked AI before the bill does](queries/hunt-drop-09-llmjacking/)
- **T1505.003**: [PHP2Shell: hunt PHP workers gone rogue](queries/hunt-drop-02-php2shell/)
- **T1528**: [When your MSP's app becomes the attacker](queries/hunt-drop-03-storm-0940-app-abuse/)
- **T1543.001**: [Trojanised Claude Code extension: hunt the reverse SSH backdoor](queries/hunt-drop-08-claude-code-extension/)
- **T1543.003**: [Hiding in plain System32](queries/hunt-drop-04-lazarus-flashhole/)
- **T1546.018**: [Hunting the LiteLLM 1.107.0 startup-hook stealer](queries/hunt-drop-05-litellm-startup-hook/)
- **T1547.001**: [Trojanised Claude Code extension: hunt the reverse SSH backdoor](queries/hunt-drop-08-claude-code-extension/)
- **T1552.001**: [Hunting the LiteLLM 1.107.0 startup-hook stealer](queries/hunt-drop-05-litellm-startup-hook/)
- **T1552.005**: [Hunting the LiteLLM 1.107.0 startup-hook stealer](queries/hunt-drop-05-litellm-startup-hook/)
- **T1555.006**: [When your MSP's app becomes the attacker](queries/hunt-drop-03-storm-0940-app-abuse/)
- **T1562.008**: [LLMJacking: find the hijacked AI before the bill does](queries/hunt-drop-09-llmjacking/)
- **T1566.003**: [Fake "IT Support" in Teams](queries/hunt-drop-06-teams-fake-it-support/)
- **T1567.002**: [Edge-to-Domain: Hunting the k0t Post-VPN Playbook](queries/hunt-drop-10-edge-to-domain-k0t/)
- **T1569.002**: [Edge-to-Domain: Hunting the k0t Post-VPN Playbook](queries/hunt-drop-10-edge-to-domain-k0t/)
- **T1571**: [Oracle EBS: hunting the TCF servlet RCE](queries/hunt-drop-07-oracle-ebs-tcf-rce/)
- **T1572**: [Trojanised Claude Code extension: hunt the reverse SSH backdoor](queries/hunt-drop-08-claude-code-extension/)
- **T1574.001**: [Hiding in plain System32](queries/hunt-drop-04-lazarus-flashhole/)
- **T1574.002**: [ROMULUS ClickFix: hunt the paste-to-loader chain](queries/hunt-drop-01-romulus-clickfix/)
- **T1580**: [When your MSP's app becomes the attacker](queries/hunt-drop-03-storm-0940-app-abuse/), [LLMJacking: find the hijacked AI before the bill does](queries/hunt-drop-09-llmjacking/)
- **T1656**: [Fake "IT Support" in Teams](queries/hunt-drop-06-teams-fake-it-support/)
- **T1667**: [Fake "IT Support" in Teams](queries/hunt-drop-06-teams-fake-it-support/)

## Licence

MIT. Use, adapt and share, with no warranty.
