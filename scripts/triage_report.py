#!/usr/bin/env python3
"""Task 3: build artifacts/triage.md from the scan artifacts.

Reads (whichever exist): artifacts/secrets.raw.json, artifacts/secrets.filtered.json,
baseline.json, artifacts/sast.json. Output is deterministic (no timestamps, stable sorting).
Exit codes: 0 = report written, 2 = error.
"""
import os
import sys

from common import ARTIFACTS, EXIT_OK, ROOT, read_json

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]           # display order, most severe first
RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
NORMALIZE = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}  # Semgrep legacy names


def secret_severity(rule_id):
    # gitleaks has no severities, so we assign them: private keys are the worst case.
    return "CRITICAL" if rule_id == "private-key" else "HIGH"


def load_secrets():
    """Return (new findings, baselined findings, stale fingerprints) or None if not scanned."""
    raw_path = ARTIFACTS / "secrets.raw.json"
    filtered_path = ARTIFACTS / "secrets.filtered.json"
    if not (raw_path.exists() and filtered_path.exists()):
        return None
    raw = read_json(raw_path)
    filtered = read_json(filtered_path)
    new_ids = {f["Fingerprint"] for f in filtered["findings"]}

    def to_row(f):
        return {"tool": "gitleaks", "rule": f["RuleID"], "severity": secret_severity(f["RuleID"]),
                "category": "secret", "file": f["File"], "line": f["StartLine"],
                "id": f["Fingerprint"]}

    new = [to_row(f) for f in raw if f["Fingerprint"] in new_ids]
    baselined = [to_row(f) for f in raw if f["Fingerprint"] not in new_ids]
    return new, baselined, filtered["summary"]["stale_baseline_entries"]


def load_sast():
    path = ARTIFACTS / "sast.json"
    if not path.exists():
        return None
    rows = []
    for r in read_json(path)["results"]:
        sev = r["extra"]["severity"].upper()
        rows.append({"tool": "semgrep", "rule": r["check_id"].split(".")[-1],
                     "severity": NORMALIZE.get(sev, sev),
                     "category": r["extra"].get("metadata", {}).get("category", "uncategorized"),
                     "file": r["path"], "line": r["start"]["line"]})
    return rows


def baseline_reasons():
    path = ROOT / "baseline.json"
    if not path.exists():
        return {}
    return {e["fingerprint"]: e.get("reason", "") for e in read_json(path).get("entries", [])}


def sort_key(row):
    # Required ordering: severity desc, then file path asc. Line/rule/tool break remaining ties.
    return (-RANK.get(row["severity"], 0), row["file"], row["line"], row["rule"], row["tool"])


def main():
    secrets = load_secrets()
    sast = load_sast()
    min_sev = os.environ.get("MIN_SEVERITY", "HIGH").upper()
    min_sev = NORMALIZE.get(min_sev, min_sev)

    active = []  # findings that still need attention (new secrets + all SAST results)
    if secrets:
        active += secrets[0]
    if sast:
        active += sast
    active.sort(key=sort_key)

    out = ["# Security Triage Report", ""]
    out.append(f"- Secrets scan (gitleaks): {'ran' if secrets else 'not run'}")
    out.append(f"- SAST scan (semgrep): {'ran' if sast is not None else 'not run'}"
               f" (fails build at MIN_SEVERITY={min_sev} and above)")
    out.append(f"- Findings needing attention: **{len(active)}**")
    out.append("")

    out += ["## Counts by severity", "", "| Severity | Secrets (new) | SAST | Total |", "|---|---|---|---|"]
    for sev in SEVERITIES:
        s = sum(1 for r in active if r["tool"] == "gitleaks" and r["severity"] == sev)
        c = sum(1 for r in active if r["tool"] == "semgrep" and r["severity"] == sev)
        out.append(f"| {sev} | {s} | {c} | {s + c} |")
    out.append("")

    counts = {}
    for r in active:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    out += ["## Counts by category", "", "| Category | Count |", "|---|---|"]
    for cat, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        out.append(f"| {cat} | {n} |")
    if not counts:
        out.append("| (none) | 0 |")
    out.append("")

    out += ["## Top 5 findings", "", "Ordered by severity (highest first), then file path (A to Z).", "",
            "| # | Severity | Tool | Rule | Location |", "|---|---|---|---|---|"]
    for i, r in enumerate(active[:5], 1):
        out.append(f"| {i} | {r['severity']} | {r['tool']} | {r['rule']} | `{r['file']}:{r['line']}` |")
    if not active:
        out.append("| - | - | - | (no findings) | - |")
    out.append("")

    out += ["## Secrets: suppressed vs new", ""]
    if secrets is None:
        out.append("Secrets scan not run.")
    else:
        new, baselined, stale = secrets
        reasons = baseline_reasons()
        out.append(f"- New (fail the build): **{len(new)}**")
        out.append(f"- Suppressed by baseline.json: **{len(baselined)}**")
        out.append(f"- Stale baseline entries (accepted but no longer found): **{len(stale)}**")
        out.append("")
        if new:
            out += ["New:", ""] + [f"- `{r['id']}`" for r in sorted(new, key=sort_key)] + [""]
        if baselined:
            out += ["Suppressed (with the reason recorded in baseline.json):", ""]
            out += [f"- `{r['id']}`: {reasons.get(r['id'], '')}" for r in sorted(baselined, key=sort_key)]
            out.append("")
        if stale:
            out += ["Stale (consider removing from baseline.json):", ""] + [f"- `{fp}`" for fp in stale] + [""]

    ARTIFACTS.mkdir(exist_ok=True)
    (ARTIFACTS / "triage.md").write_text("\n".join(out).rstrip() + "\n")
    print(f"[triage] wrote artifacts/triage.md ({len(active)} findings needing attention)")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
