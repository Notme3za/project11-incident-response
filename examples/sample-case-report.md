# Incident Case Report: IR-20261020T031838302956Z

## Case status

- **Status:** Open — analyst review required
- **Assessment:** Possible SSH password spraying; the alert alone does not prove malicious intent or password reuse.
- **Priority:** Unassessed; assign after reviewing surrounding evidence.
- **Input:** `sample-alert.json` (simulated alert)

## Alert summary

- **Detection:** possible SSH password spraying
- **Source address:** `192.0.2.10`
- **Distinct usernames:** 4 (`lab-user-01`, `lab-user-02`, `lab-user-03`, `lab-user-04`)
- **Failed events:** 4
- **Observed window (UTC):** 2026-10-20T09:00:00Z to 2026-10-20T09:04:00Z

## Evidence record

- **Evidence file:** `sample-alert.json`
- **SHA-256:** `f79fa2941c7eec800f761d033c31e984854b41409b06f013c4821dd0c8c5190b`
- **Note:** Example data based on the Project 10 detection; not copied from real logs.
- **Scope:** This case is based on the supplied simulated alert only. No raw logs or packet captures were examined.

## Triage findings

The alert matches the Project 10 hypothesis of at least four distinct usernames from one source within five minutes. It is a lead for investigation, not a conclusion. The available record does not show whether any login succeeded or whether the source is authorized.

## Recommended next actions

1. Review SSH authentication records around the observed window for successful logins from this source and related activity.
2. Check whether the source address belongs to an authorized user, scanner, VPN, or shared network before attributing activity.
3. If corroborating evidence supports malicious activity, have an authorized administrator consider a temporary source restriction under the organization's process.
4. Preserve relevant logs and record any containment decision, owner, and time in this case.

**No traffic was blocked and no system security settings were changed by this workflow.** These recommendations are advisory and require human review and authorization.

