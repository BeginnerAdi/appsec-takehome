#!/usr/bin/env python3
"""Task 1: secrets scan with gitleaks + baseline.

Writes:
  artifacts/secrets.raw.json       every finding gitleaks reported (values redacted)
  artifacts/secrets.filtered.json  only NEW findings (raw minus baseline.json)
Exit codes: 0 = no new findings, 1 = new findings, 2 = tool/config error.
Env vars:   TARGET (folder to scan, default "samples"), GITLEAKS_IMAGE (override image).
"""
import os
import sys

from common import (ARTIFACTS, EXIT_FINDINGS, EXIT_OK, ROOT, docker_run, fail,
                    read_json, tool_image, write_json)

TARGET = os.environ.get("TARGET", "samples")
BASELINE = ROOT / "baseline.json"
TMP_REPORT = "artifacts/.gitleaks-report.json"


def run_gitleaks():
    """Run gitleaks in Docker and return its list of findings."""
    ARTIFACTS.mkdir(exist_ok=True)
    result = docker_run(
        tool_image("GITLEAKS_IMAGE"),
        [
            "dir", TARGET,                          # scan files (not git history)
            "--config", "config/gitleaks.toml",     # our tuning
            "--report-format", "json",
            "--report-path", TMP_REPORT,
            "--redact",                             # never write secret values to disk
            "--no-banner",
            "--log-level", "error",
            "--exit-code", "0",                     # WE decide pass/fail, not gitleaks
        ],
        workdir="/repo",
    )
    if result.returncode != 0:
        fail(f"gitleaks failed (exit {result.returncode}):\n{result.stderr.strip()}")
    report = ROOT / TMP_REPORT
    findings = read_json(report)
    report.unlink()
    return findings


def fingerprint(finding):
    """Stable ID for a finding: file:rule:line (e.g. samples/app/settings.py:generic-api-key:6)."""
    return f"{finding['File']}:{finding['RuleID']}:{finding['StartLine']}"


def load_baseline():
    """Return {fingerprint: baseline entry}. A missing baseline.json means an empty baseline."""
    if not BASELINE.exists():
        return {}
    data = read_json(BASELINE)
    try:
        return {entry["fingerprint"]: entry for entry in data["entries"]}
    except (KeyError, TypeError):
        fail('baseline.json must look like {"entries": [{"fingerprint": "...", ...}]}')


def main():
    findings = run_gitleaks()
    for f in findings:
        f["Fingerprint"] = fingerprint(f)
    # gitleaks scans files in parallel, so its order changes between runs. Sort for determinism.
    findings.sort(key=lambda f: (f["File"], f["StartLine"], f["RuleID"], f["StartColumn"]))
    write_json(ARTIFACTS / "secrets.raw.json", findings)

    baseline = load_baseline()
    new = [f for f in findings if f["Fingerprint"] not in baseline]
    baselined = sorted(f["Fingerprint"] for f in findings if f["Fingerprint"] in baseline)
    seen = {f["Fingerprint"] for f in findings}
    stale = sorted(fp for fp in baseline if fp not in seen)  # accepted but no longer present

    write_json(ARTIFACTS / "secrets.filtered.json", {
        "summary": {
            "target": TARGET,
            "raw_count": len(findings),
            "baselined_count": len(baselined),
            "new_count": len(new),
            "baselined": baselined,
            "stale_baseline_entries": stale,
        },
        "findings": new,
    })

    print(f"[secrets] raw={len(findings)} baselined={len(baselined)} new={len(new)}")
    for f in new:
        print(f"  NEW  {f['Fingerprint']}")
    for fp in stale:
        print(f"  STALE baseline entry (no longer found): {fp}")
    return EXIT_FINDINGS if new else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
