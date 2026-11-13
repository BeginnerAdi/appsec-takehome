"""Test helper code. Test code is not shipped, so SAST findings here are noise.

config/semgrep.yml excludes tests/ for that reason.
"""
import subprocess


def reset_test_db(name):
    # Would be flagged as HIGH, but tests/ is excluded in config/semgrep.yml
    subprocess.run("rm -f /tmp/" + name, shell=True)
