// CrowdStrike Falcon (CQL) | Hunt Drop #03 | UNTESTED: tune before use
Needs Entra ID logs in Falcon Next-Gen SIEM. Free-text filters, so they work whatever your parser's field names are.

// T1078.004/T1528: app-only sign-ins with scripted tooling. Time picker: last 14 days
/servicePrincipal/i
/python-requests|python-urllib|curl\/|azure-toolkit/i
| table([@timestamp, #repo, #type, @rawstring], limit=500)

// T1098.003: role assignments (Entra audit activity names)
/Add member to role|Add eligible member to role|Add app role assignment to service principal/i
| table([@timestamp, #repo, #type, @rawstring], limit=500)

// T1199/T1195 exposure: affected ConnectWise app IDs. Time picker: last 30 days
"506e08f9-6e9a-4da4-942b-a099a03644ae" OR "24205314-2b89-4e07-a2a4-579e898a5640" OR "0de14c77-b9b0-4137-9360-34878a929827"
| groupBy([#repo, #type], function=[count(), max(@timestamp, as=last_seen)])
