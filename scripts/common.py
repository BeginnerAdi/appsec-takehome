"""Small helpers shared by the scan scripts (Python standard library only)."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Repo root = the folder above scripts/. Everything is resolved from here,
# so the scripts work no matter which directory you run them from.
ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts"

# Exit codes used by every script
EXIT_OK = 0        # nothing that should fail the build
EXIT_FINDINGS = 1  # findings that should fail the build
EXIT_ERROR = 2     # the tool itself failed (docker missing, bad config, ...)


def fail(message):
    """Print an error and exit with code 2 (tool/config error)."""
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(EXIT_ERROR)


def tool_image(name):
    """Return the Docker image for NAME (e.g. GITLEAKS_IMAGE).

    An environment variable of the same name wins; otherwise read config/tools.env.
    """
    if os.environ.get(name):
        return os.environ[name]
    env_file = ROOT / "config" / "tools.env"
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            if key.strip() == name:
                return value.strip()
    fail(f"{name} not found in {env_file}")


def docker_run(image, args, workdir):
    """Run IMAGE with the repo mounted at WORKDIR. Returns the CompletedProcess."""
    if shutil.which("docker") is None:
        fail("docker is not installed or not on PATH")
    cmd = [
        "docker", "run", "--rm",
        # run as your user so files in artifacts/ are not owned by root
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-e", "HOME=/tmp",
        "-v", f"{ROOT}:{workdir}",
        "-w", workdir,
        image,
    ] + args
    return subprocess.run(cmd, capture_output=True, text=True)


def write_json(path, data):
    """Write JSON in a stable format: sorted keys, 2-space indent, trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        fail(f"cannot read {path}: {exc}")
