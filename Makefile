# `make` runs everything. Recipes use the one-line "target: ; command" form (no tabs needed).
# Note: make itself exits 2 whenever a command fails. For the exact 0/1/2 codes, use ./run.sh.
.PHONY: all scan secrets sast triage clean

all: scan

scan: ; ./run.sh
secrets: ; python3 scripts/scan_secrets.py
sast: ; python3 scripts/scan_sast.py
triage: ; python3 scripts/triage_report.py
clean: ; rm -rf artifacts
