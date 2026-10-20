#!/usr/bin/env python3
"""Create an advisory incident case report from a simulated Project 10 alert."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def required(alert: dict, key: str):
    if key not in alert or alert[key] in (None, ""):
        raise ValueError(f"Missing required field: {key}")
    return alert[key]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Turn a Project 10 alert JSON file into an advisory case report."
    )
    parser.add_argument("alert_file", type=Path, help="Path to the alert JSON file")
    parser.add_argument(
        "--output", type=Path, help="Report path (defaults to case-report.md beside the alert)"
    )
    args = parser.parse_args()

    alert_path = args.alert_file.expanduser().resolve()
    if not alert_path.is_file():
        parser.error(f"Alert file not found: {alert_path}")

    try:
        alert = json.loads(alert_path.read_text(encoding="utf-8"))
        if not isinstance(alert, dict):
            raise ValueError("Alert JSON must contain one object")

        alert_type = required(alert, "alert_type")
        source_ip = required(alert, "source_ip")
        usernames = required(alert, "usernames")
        start = required(alert, "window_start_utc")
        end = required(alert, "window_end_utc")
        distinct_count = int(required(alert, "distinct_username_count"))
        event_count = int(required(alert, "failed_event_count"))
        if not isinstance(usernames, list) or len(usernames) != distinct_count:
            raise ValueError("usernames must be a list matching distinct_username_count")
        if not alert.get("simulated", False):
            raise ValueError("This starter workflow accepts simulated alerts only")
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
        parser.error(f"Cannot triage alert: {error}")

    evidence_hash = sha256_file(alert_path)
    case_time = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    case_id = f"IR-{case_time}"
    output_path = args.output or alert_path.with_name(f"case-report-{case_id}.md")
    usernames_text = ", ".join(f"`{name}`" for name in usernames)
    evidence_note = alert.get("evidence_note", "No additional evidence note supplied.")

    report = f"""# Incident Case Report: {case_id}

## Case status

- **Status:** Open — analyst review required
- **Assessment:** Possible SSH password spraying; the alert alone does not prove malicious intent or password reuse.
- **Priority:** Unassessed; assign after reviewing surrounding evidence.
- **Input:** `{alert_path.name}` (simulated alert)

## Alert summary

- **Detection:** {alert_type}
- **Source address:** `{source_ip}`
- **Distinct usernames:** {distinct_count} ({usernames_text})
- **Failed events:** {event_count}
- **Observed window (UTC):** {start} to {end}

## Evidence record

- **Evidence file:** `{alert_path.name}`
- **SHA-256:** `{evidence_hash}`
- **Note:** {evidence_note}
- **Scope:** This case is based on the supplied simulated alert only. No raw logs or packet captures were examined.

## Triage findings

The alert matches the Project 10 hypothesis of at least four distinct usernames from one source within five minutes. It is a lead for investigation, not a conclusion. The available record does not show whether any login succeeded or whether the source is authorized.

## Recommended next actions

1. Review SSH authentication records around the observed window for successful logins from this source and related activity.
2. Check whether the source address belongs to an authorized user, scanner, VPN, or shared network before attributing activity.
3. If corroborating evidence supports malicious activity, have an authorized administrator consider a temporary source restriction under the organization's process.
4. Preserve relevant logs and record any containment decision, owner, and time in this case.

**No traffic was blocked and no system security settings were changed by this workflow.** These recommendations are advisory and require human review and authorization.
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("x", encoding="utf-8") as report_file:
            report_file.write(report)
    except FileExistsError:
        parser.error(f"Refusing to overwrite existing report: {output_path}")
    print(f"Created case report: {output_path}")
    print(f"Case ID: {case_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

