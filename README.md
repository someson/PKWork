# The PKWork Files

Incident investigation of a security breach at the fictional company PKWork,
carried out in Microsoft Sentinel (Microsoft Defender portal) as part of a
cybersecurity course.

## Scenario

It started with a handful of alerts. Different systems, different users and
different security products all point toward the same incident.
The question is no longer whether there was an attack, but:

**What really happened at PKWork?**

## Goals

- What happened?
- Which users, systems and resources were affected?
- What evidence supports the conclusions?
- What remains uncertain?
- What should the organization do next?

## Environment

- Portal: [security.microsoft.com](https://security.microsoft.com/)
- Sentinel workspace: `sentinel-lab-main-ws`
- Data: pre-ingested endpoint, identity, network, email and cloud telemetry

## Repository layout

| Path | Content |
|---|---|
| `docs/INVESTIGATION_LOG.md` | Working notebook: findings, hypotheses, session status |
| `docs/WALKTHROUGH.md` | Step-by-step record of the queries run and their results |
| `docs/ANALYSIS.md` | Consolidated timeline, scope, MITRE ATT&CK mapping and confidence |
| `queries/` | KQL queries used in the investigation |
