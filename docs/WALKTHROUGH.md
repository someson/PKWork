# Walkthrough

Chronological record of the queries run during the investigation and their
results.

## Session 1 – Data sources

Microsoft Sentinel workspace `sentinellab1786260698` → Logs.

```kql
Usage
| where TimeGenerated > ago(730d)
| summarize MB = sum(Quantity), First = min(TimeGenerated), Last = max(TimeGenerated) by DataType
| sort by MB desc
```

| DataType | MB | First (UTC) | Last (UTC) |
|---|---|---|---|
| SecurityEvent | 24.52 | 2026-08-09 09:00 | 2026-08-18 20:00 |
| AzureActivity | 4.35 | 2026-08-09 10:00 | 2026-10-30 08:00 |
| AzureActivity_CL | 1.44 | 2026-08-09 08:00 | 2026-08-18 20:00 |
| OfficeActivity_CL | 0.73 | 2026-08-09 08:00 | 2026-08-18 20:00 |
| CrowdStrikeDetections | 0.52 | 2026-08-09 09:00 | 2026-08-18 20:00 |
| azureActivity_adele_CL | 0.48 | 2026-08-09 08:00 | 2026-08-18 20:00 |
| sign_in_adelete_CL | 0.33 | 2026-08-09 09:00 | 2026-08-18 20:00 |
| CommonSecurityLog | 0.20 | 2026-08-09 09:00 | 2026-08-18 20:00 |
| Watchlist | 0.10 | 2026-08-09 08:00 | 2026-11-01 04:00 |
| SecurityAlert | 0.09 | 2026-08-09 09:00 | 2026-08-21 20:00 |
| CrowdStrikeAlerts | 0.09 | 2026-08-09 09:00 | 2026-08-18 20:00 |
| OktaV2_CL | 0.08 | 2026-08-09 08:00 | 2026-08-18 20:00 |
| MailGuard365_Threats_CL | 0.06 | 2026-08-09 08:00 | 2026-08-18 20:00 |
| GCPAuditLogs | 0.06 | 2026-08-09 09:00 | 2026-08-18 20:00 |
| AWSCloudTrail | 0.06 | 2026-08-09 09:00 | 2026-08-18 20:00 |
| SecurityIncident | 0.04 | 2026-08-09 09:00 | 2026-08-21 20:00 |
| AuditLogsHunting_CL | 0.03 | 2026-08-09 08:00 | 2026-08-18 20:00 |
| CrowdStrikeVulnerabilities | 0.02 | 2026-08-09 09:00 | 2026-08-18 20:00 |
| CrowdStrikeHosts | 0.02 | 2026-08-09 09:00 | 2026-08-18 20:00 |
| disable_accounts_CL | 0.02 | 2026-08-09 08:00 | 2026-08-18 20:00 |
| SEG_MailGuard_CL | 0.01 | 2026-08-09 09:00 | 2026-08-18 20:00 |
| model_evasion_detection_CL | 0.01 | 2026-08-09 08:00 | 2026-08-18 20:00 |
| office_activity_inbox_rule_CL | 0.01 | 2026-08-09 08:00 | 2026-08-18 20:00 |

Data was ingested between 2026-08-09 and 2026-08-18.
