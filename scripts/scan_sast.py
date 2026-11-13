#!/usr/bin/env python3
"""Task 2: SAST scan with Semgrep + severity threshold.

Writes:
  artifacts/sast.json   Semgrep results (sorted, so output is stable)
  artifacts/sast.sarif  same results in SARIF (for GitHub code scanning / IDEs)
Exit codes: 0 = nothing at/above MIN_SEVERITY, 1 = findings at/above it, 2 = tool/config error.
Env vars:   MIN_SEVERITY (LOW|MEDIUM|HIGH|CRITICAL, default HIGH; INFO/WARNING/ERROR also accepted),
            TARGET (folder to scan, default "samples"), SEMGREP_IMAGE (override image).
"""
import os
import sys

from common import (ARTIFACTS, EXIT_FINDINGS, EXIT_OK, ROOT, docker_run, fail,
                    read_json, tool_image, write_json)

# One ladder for both Semgrep naming styles: INFO=LOW, WARNING=MEDIUM, ERROR=HIGH.
SEVERITY_RANK = {
    "INFO": 1, "LOW": 1,
    "WARNING": 2, "MEDIUM": 2,
    "ERROR": 3, "HIGH": 3,
    "CRITICAL": 4,
}
TARGET = os.environ.get("TARGET", "samples")


def min_severity():
    value = os.environ.get("MIN_SEVERITY", "HIGH").strip().upper()
    if value not in SEVERITY_RANK:
        fail(f"MIN_SEVERITY={value!r} is invalid. Use one of: LOW, MEDIUM, HIGH, CRITICAL")
    return value


def run_semgrep():
    ARTIFACTS.mkdir(exist_ok=True)
    result = docker_run(
        tool_image("SEMGREP_IMAGE"),
        [
            "semgrep", "scan",
            "--config", "config/semgrep.yml",   # local rules only (no registry download)
            "--metrics=off",                    # no telemetry, works offline
            "--disable-version-check",          # no network call
            "--quiet",
            "--json-output=artifacts/sast.json",
            "--sarif-output=artifacts/sast.sarif",
            TARGET,
        ],
        workdir="/src",
    )
    if result.returncode != 0:
        fail(f"semgrep failed (exit {result.returncode}):\n{result.stderr.strip()}")
    data = read_json(ARTIFACTS / "sast.json")
    if data.get("errors"):
        # Some files or rules failed. A partial scan is not a clean scan: fail closed.
        fail(f"semgrep reported errors: {data['errors']}")
    return data


def main():
    threshold = min_severity()
    data = run_semgrep()
    results = data["results"]
    # Sort and re-save so sast.json is byte-identical across runs.
    results.sort(key=lambda r: (r["path"], r["start"]["line"], r["check_id"]))
    data.pop("time", None)  # timing info (only present with --time) would break determinism
    write_json(ARTIFACTS / "sast.json", data)

    blocking = [r for r in results
                if SEVERITY_RANK.get(r["extra"]["severity"].upper(), 0) >= SEVERITY_RANK[threshold]]

    print(f"[sast] total={len(results)} min_severity={threshold} at_or_above={len(blocking)}")
    for r in results:
        sev = r["extra"]["severity"].upper()
        mark = "FAIL" if r in blocking else "info"
        print(f"  {mark}  {sev:<8} {r['path']}:{r['start']['line']}  {r['check_id']}")
    return EXIT_FINDINGS if blocking else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
