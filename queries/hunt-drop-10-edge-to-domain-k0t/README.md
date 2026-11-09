# Hunt Drop 10 | Edge-to-Domain: Hunting the k0t Post-VPN Playbook

**Hypothesis:** A VPN edge foothold has been turned into domain access.

**ATT&CK:** T1569.002, T1053.005, T1059.001, T1219, T1567.002
**Date:** 2026-11-06
**Queries:** [defender.kql](defender.kql), [falcon.cql](falcon.cql)

Write-up: https://arkknight.si/hunting/hunt-drop-10-edge-to-domain-k0t/

> Untested queries. Run them as hunts, then test and tune them in your own environment before using them as detections.

## Sources

1. Group-IB (21 Oct 2026): <https://www.group-ib.com/blog/stray-cat-network-edge/>
2. The Hacker News (23 Oct 2026): <https://thehackernews.com/2026/10/hackers-breach-enterprise-firewalls-and.html>
3. SigmaHQ via Detection.FYI: <https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_hktl_impacket_lateral_movement/>
4. Cyber Triage (20 Sep 2024): <https://www.cybertriage.com/blog/dfir-breakdown-impacket-remote-execution-activity-smbexec/>
5. NCC Group (27 May 2021): <https://www.nccgroup.com/research/detecting-rclone-an-effective-tool-for-exfiltration/>
