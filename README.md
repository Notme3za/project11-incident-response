# Project 11: Incident Response & Automation

## Goal

Turn a simulated SSH password-spraying alert into a structured incident case report. The workflow records the alert details, hashes the input file with SHA-256, summarizes what is and is not known, and recommends human-reviewed next actions.

This project builds on Project 10's detection by adding case triage and evidence recording. The alert is a lead for investigation; it does not prove malicious intent, password reuse, or successful access.

## Safety boundary

This starter workflow accepts simulated alerts only. It does not read live system logs, block traffic, terminate sessions, or change security settings. Any containment recommendation requires evidence review and authorization by an administrator.

## Files

- `sample-alert.json` — simulated input based on the Project 10 detection.
- `triage.py` — standard-library Python script that creates the case report.
- `examples/sample-case-report.md` — example output generated from the simulated input.
- `case-report-<case-id>.md` — generated report for each run; local generated reports are excluded from version control.

## Reproduce on Windows

Open PowerShell in this folder and run:

```powershell
py .\triage.py .\sample-alert.json
```

The script writes a uniquely named `case-report-<case-id>.md` beside the input file and prints the case ID. It records a SHA-256 digest of the input alert in the report. Existing reports are never overwritten.

To independently calculate the input file's digest in PowerShell, run:

```powershell
Get-FileHash .\sample-alert.json -Algorithm SHA256
```

The displayed hash should match the SHA-256 value in the generated case report as long as the input file has not changed since report generation.

## Current limits

- The case uses simulated alert data, not raw authentication logs or packet captures.
- The script checks the alert structure and simulated flag but does not verify the detection against source logs.
- The report leaves priority unassessed and the case open because it has no corroborating evidence about successful logins or whether the source is authorized.
- Recommendations are advisory. An analyst must review supporting evidence before deciding on containment.

