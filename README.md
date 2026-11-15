# appsec-takehome

This repo covers Task 1 (secrets scanning with gitleaks), Task 2 (SAST with Semgrep) and Task 3 (triage report). The scanners run in Docker and scan a small demo app in samples/demo-app that contains planted issues. All secrets in it are fake.

Requirements: Linux or macOS with Docker, Python 3 and bash.

## Run

```bash
git clone https://github.com/BeginnerAdi/appsec-takehome.git
cd appsec-takehome
./run.sh
```

This runs all three tasks and writes the results to the artifacts folder: secrets.raw.json, secrets.filtered.json, sast.json, sast.sarif and triage.md. `make` also works, but make reports any failure as exit code 2, so use ./run.sh to see the exact codes below.

Expected exit code: 1. The secrets scan passes because both secrets are in the baseline, but the SAST scan finds issues at or above the default HIGH threshold.

## Exit codes

- 0: no new secrets and no SAST findings at or above MIN_SEVERITY
- 1: at least one new secret, or at least one SAST finding at or above MIN_SEVERITY
- 2: the scanner itself failed, for example Docker is not running or MIN_SEVERITY is invalid

## Task 1: secrets

```bash
python3 scripts/scan_secrets.py
```

Exit code 0. It finds 2 secrets and both are listed in baseline.json, so artifacts/secrets.filtered.json has no findings. Any secret that is not in baseline.json makes it exit with 1.

## Task 2: SAST

```bash
MIN_SEVERITY=INFO python3 scripts/scan_sast.py
MIN_SEVERITY=HIGH python3 scripts/scan_sast.py
```

INFO counts 5 findings and HIGH counts 3, so INFO is more sensitive. Both exit with 1. The default is HIGH.

## Task 3: triage report

```bash
python3 scripts/triage_report.py
```

Writes artifacts/triage.md with counts by severity and category, the top 5 findings (severity first, then file path), and the number of suppressed vs new secrets. Exit code 0.

## Tuning notes

gitleaks uses its default rules plus an allowlist for "dummy" and "fake" placeholder values, so obvious placeholders are not reported. Accepted findings are listed in baseline.json with a reason and an owner.
Semgrep uses five local Python rules. To reduce noise they skip safe code (a constant shell command, yaml's safe loader) and the tests folder, and MD5 is rated LOW so it is reported without failing the HIGH threshold.
