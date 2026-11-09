// =====================================================================================
// HUNT DROP #09 | LLMJacking: find the hijacked AI before the bill does
// Builds on Intel Drop #26 (Mandiant / GTIG "The Rise of LLMJacking", 2 Nov 2026)
// Platform: CrowdStrike Falcon Next-Gen SIEM / Advanced Event Search (CQL)
// STATUS: UNTESTED in a live tenant. Test and tune before relying on results, and before
//         promoting anything to a correlation rule or custom IOA.
// TIME WINDOW: set the time picker to Last 14 days for every query below.
// Lines marked [UNVERIFIED] use field paths that could not be confirmed against public docs in this run.
// Cloud queries (H1, H2) need AWS CloudTrail ingested into NG-SIEM with the aws-cloudtrail parser
//   (#Vendor="aws", #event.module="cloudtrail"; fields event.action, event.provider, user.name,
//   source.address, user_agent.original, cloud.region, error.code per library.humio.com parser page).
// Endpoint queries (H3) use native Falcon sensor events.
// =====================================================================================


// -------------------------------------------------------------------------------------
// H1 | Bedrock scoping, model-access enablement, invocation-logging tampering, inference bursts
// ATT&CK: T1078.004 | T1580 (analyst mapping) | T1562.008 | T1496.004
// Hypothesis: A stolen AWS identity used for LLMJacking shows Bedrock scoping / enablement /
//   logging changes, then InvokeModel/Converse bursts and throttling errors.
// Expected noise: ML/platform teams, IaC pipelines. Exclude known automation principals.
// -------------------------------------------------------------------------------------
#Vendor="aws" #event.module="cloudtrail"
| event.provider="bedrock.amazonaws.com"
| in(field="event.action", values=["ListFoundationModels","ListInferenceProfiles","GetFoundationModelAvailability","PutUseCaseForModelAccess","CreateFoundationModelAgreement","GetModelInvocationLoggingConfiguration","PutModelInvocationLoggingConfiguration","DeleteModelInvocationLoggingConfiguration","InvokeModel","InvokeModelWithResponseStream","Converse","ConverseStream"])
// TUNE: exclude IaC / ML-platform principals
| !in(field="user.name", values=["<iac-principal>"])
| case {
    in(field="event.action", values=["PutUseCaseForModelAccess","CreateFoundationModelAgreement"]) | Stage := "Enable" | w := 3 ;
    in(field="event.action", values=["GetModelInvocationLoggingConfiguration","PutModelInvocationLoggingConfiguration","DeleteModelInvocationLoggingConfiguration"]) | Stage := "LogTamper" | w := 3 ;
    in(field="event.action", values=["ListFoundationModels","ListInferenceProfiles","GetFoundationModelAvailability"]) | Stage := "Scoping" | w := 1 ;
    * | Stage := "Invoke" | w := 0 ;
  }
| case {
    in(field="error.code", values=["ThrottlingException","ValidationException","ResourceNotFoundException"]) | err := 1 ;
    * | err := 0 ;
  }
| groupBy([user.name, source.address], function=[count(as=Events), sum(w, as=StageWeight), sum(err, as=Errors), collect([Stage, event.action, user_agent.original, cloud.region], limit=20), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| Score := StageWeight + if(Events > 500, then=2, else=0) + if(Errors > 50, then=1, else=0)
| Score >= 3
| sort(Score, order=desc, limit=200)
// Note: StageWeight sums every matching event, so repeated scoping calls also raise the score. Tune.


// -------------------------------------------------------------------------------------
// H2a | Burn-and-rotate: IAM users created and deleted within 24 hours
// ATT&CK: T1136.003 | T1098.001
// Expected noise: CI/CD fixtures, IAM automation, offboarding scripts.
// -------------------------------------------------------------------------------------
#Vendor="aws" #event.module="cloudtrail"
| event.provider="iam.amazonaws.com"
| in(field="event.action", values=["CreateUser","DeleteUser","CreateAccessKey"])
| rename(field="Vendor.requestParameters.userName", as=TargetUser)     // [UNVERIFIED] field path not listed on parser page
| case {
    event.action="CreateUser" | c := 1 | d := 0 | k := 0 ;
    event.action="DeleteUser" | c := 0 | d := 1 | k := 0 ;
    * | c := 0 | d := 0 | k := 1 ;
  }
| groupBy([TargetUser], function=[sum(c, as=Creates), sum(d, as=Deletes), sum(k, as=KeysCreated), collect([user.name, source.address], limit=10), min(@timestamp, as=First), max(@timestamp, as=Last)])
| Creates >= 1
| Deletes >= 1
| LifetimeMin := (Last - First) / 60000
| LifetimeMin < 1440
| sort(LifetimeMin, order=asc, limit=200)


// -------------------------------------------------------------------------------------
// H2b | Administrative policies attached to users or service roles
// ATT&CK: T1098.003
// Expected noise: break-glass setup, landing-zone automation. Correlate with change tickets.
// -------------------------------------------------------------------------------------
#Vendor="aws" #event.module="cloudtrail"
| event.provider="iam.amazonaws.com"
| in(field="event.action", values=["AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy"])
| case {
    Vendor.requestParameters.policyArn=/AdministratorAccess$/ ;          // [UNVERIFIED] field path
    in(field="event.action", values=["PutUserPolicy","PutRolePolicy"]) ;
  }
| table([@timestamp, event.action, user.name, source.address, user_agent.original, cloud.region, Vendor.requestParameters.roleName, Vendor.requestParameters.userName, Vendor.requestParameters.policyArn])


// -------------------------------------------------------------------------------------
// H3a | IOC sweep: endpoints resolving LLM-mixer domains (jet-night[.]com, newapi[.]pro)
// ATT&CK: T1496.004 (analyst mapping)
// Expected noise: Very low.
// Real (non-defanged) strings below so the query works.
// -------------------------------------------------------------------------------------
#event_simpleName=DnsRequest
| DomainName=/(^|\.)(jet-night\.com|newapi\.pro)$/i
| groupBy([aid, ContextBaseFileName, DomainName], function=[count(as=Lookups), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| sort(Lookups, order=desc, limit=200)
// Add hostnames with your aid_master lookup if needed.


// -------------------------------------------------------------------------------------
// H3b | Scripted LLM API key validation sweeps (max_tokens=1) from our endpoints
// ATT&CK: T1078.004 (analyst mapping)
// Only catches payloads on the command line (curl -d, python -c). Script files / SDK calls will not show.
// Expected noise: developer health checks, monitoring probes.
// -------------------------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| CommandLine=/max_tokens["']?\s*[:=]\s*1\b/i
| case {
    CommandLine=/(api\.openai\.com|api\.anthropic\.com|bedrock-runtime|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|openai\.azure\.com)/i | LlmHost := "yes" ;
    * | LlmHost := "no" ;
  }
| groupBy([aid, ComputerName, UserName, ImageFileName], function=[count(as=Executions), collect([CommandLine, ParentBaseFileName, LlmHost], limit=5)])
| Executions >= 5
| sort(Executions, order=desc, limit=200)
