#!/usr/bin/env bash
# One command for everything: secrets scan -> SAST scan -> triage report.
# Exit codes: 0 = clean, 1 = findings that fail the build, 2 = a tool/config error.
# No "set -e": if a scan finds problems we still want the other scans and the report.
set -u

cd "$(dirname "$0")" || exit 2
mkdir -p artifacts

python3 scripts/scan_secrets.py;  secrets_rc=$?
python3 scripts/scan_sast.py;     sast_rc=$?
python3 scripts/triage_report.py; triage_rc=$?

final=0
for rc in "$secrets_rc" "$sast_rc" "$triage_rc"; do
  if [ "$rc" -ge 2 ]; then
    final=2
  elif [ "$rc" -eq 1 ] && [ "$final" -eq 0 ]; then
    final=1
  fi
done

echo "secrets=$secrets_rc sast=$sast_rc triage=$triage_rc -> exit $final (report: artifacts/triage.md)"
exit "$final"
