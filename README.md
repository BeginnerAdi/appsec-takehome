# appsec-takehome

Security scanning wrappers for the AppSec Tools Engineer take-home.

- **Task 1:** secrets scan (gitleaks) with baseline + suppression
- **Task 2:** SAST (Semgrep) with a bounded rule set, noise reduction and a `MIN_SEVERITY` threshold
- **Task 3 (bonus):** triage report built from both outputs

Both scanners run in pinned Docker images (`config/tools.env`). No cloud accounts and no network rule downloads.
The scan target is a small, deliberately insecure demo app in `samples/demo-app/`. All secrets in it are fake.

## Requirements

Linux or macOS with Docker, Python 3.8+ (standard library only) and bash. `make` is optional.

## Run everything (one command)

```bash
./run.sh          # or: make
```

It writes these files to `artifacts/`:

| File | Content |
|---|---|
| `secrets.raw.json` | every gitleaks finding (secret values redacted) |
| `secrets.filtered.json` | only NEW findings, after removing `baseline.json` entries, plus a summary |
| `sast.json`, `sast.sarif` | Semgrep results |
| `triage.md` | counts by severity/category, top 5, suppressed vs new |

**Expected result on this repo: exit code `1`.** Secrets pass (2 found, both baselined), but SAST finds 3 issues at or above the default `MIN_SEVERITY=HIGH`.

## Exit codes

| Code | `./run.sh` | `scripts/scan_secrets.py` | `scripts/scan_sast.py` |
|---|---|---|---|
| 0 | everything passed | no new (non-baseline) secrets | nothing at/above `MIN_SEVERITY` |
| 1 | at least one scan failed | at least 1 new secret | at least 1 finding at/above `MIN_SEVERITY` |
| 2 | a tool/config error | gitleaks/Docker/baseline error | Semgrep/Docker error or invalid `MIN_SEVERITY` |

`make` exits `2` for any failure (that's make's own behaviour). Use `./run.sh` when you need the exact code.

## Task 1: secrets

```bash
python3 scripts/scan_secrets.py; echo "exit=$?"
# [secrets] raw=2 baselined=2 new=0    -> exit=0

# add a new (fake) secret -> exit 1
echo 'NEW_TOKEN = "acme_live_0123456789abcdef0123456789abcdef"' >> samples/demo-app/settings.py
python3 scripts/scan_secrets.py; echo "exit=$?"
# [secrets] raw=3 baselined=2 new=1    -> exit=1
git checkout samples/demo-app/settings.py   # undo
```

**How the baseline works:** `baseline.json` lists accepted findings by fingerprint (`file:rule:line`), each with a `reason`, `owner` and `added` date. The wrapper removes those from `secrets.filtered.json` and only fails on what's left. To accept a finding, copy its `Fingerprint` from `artifacts/secrets.raw.json` into a new entry. Entries that no longer match anything are reported as "stale".

## Task 2: SAST and `MIN_SEVERITY`

```bash
MIN_SEVERITY=LOW      python3 scripts/scan_sast.py; echo "exit=$?"   # 5 of 5 count  -> exit=1
MIN_SEVERITY=MEDIUM   python3 scripts/scan_sast.py; echo "exit=$?"   # 4 of 5        -> exit=1
MIN_SEVERITY=HIGH     python3 scripts/scan_sast.py; echo "exit=$?"   # 3 of 5 (default) -> exit=1
MIN_SEVERITY=CRITICAL python3 scripts/scan_sast.py; echo "exit=$?"   # 1 of 5        -> exit=1
TARGET=samples/demo-app/tests python3 scripts/scan_sast.py; echo "exit=$?"   # 0 findings (tests excluded) -> exit=0
MIN_SEVERITY=BOGUS    python3 scripts/scan_sast.py; echo "exit=$?"   # invalid value -> exit=2
```

`INFO`, `WARNING` and `ERROR` are accepted as aliases for `LOW`, `MEDIUM` and `HIGH`. So `MIN_SEVERITY=INFO` (5 findings) is more sensitive than `MIN_SEVERITY=HIGH` (3 findings).

## Task 3: triage report

```bash
python3 scripts/triage_report.py && cat artifacts/triage.md
```

Top 5 is ordered by severity (highest first), then file path (A to Z). Secrets have no severity in gitleaks, so private keys count as CRITICAL and all other secrets as HIGH.

## Tuning notes

gitleaks keeps its default rules and adds three tuning choices in `config/gitleaks.toml`: an allowlist for values starting with `dummy`/`fake` (team placeholder convention), an exclude for generated `artifacts/`, and a custom `acme-api-token` rule. Known findings are accepted in `baseline.json` with a reason and owner, so suppression stays auditable. Semgrep uses a bounded set of 5 local Python rules. Noise is cut with `pattern-not` for safe variants (constant shell command, `SafeLoader`), `paths.exclude` for `tests/` (test code isn't shipped), and LOW severity for MD5, so only real risks fail the default `HIGH` threshold.

## Determinism

Pinned image versions, `--metrics=off`, local rules only, findings sorted before writing, relative paths, JSON written with sorted keys, and no timestamps in the report. Running `./run.sh` twice produces byte-identical artifacts.

## Known limitations

- The baseline matches on `file:rule:line`, so adding lines above a baselined secret makes it look new.
- gitleaks runs in `dir` mode (files on disk), not over git history.
- Secret severities are assigned by the wrapper, not by gitleaks.
