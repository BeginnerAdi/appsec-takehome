"""Deliberately insecure demo app. It exists only so the scanners have something to find.

Every risky line is marked with a comment saying which scanner rule should flag it.
"""
import hashlib
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # BAD (HIGH): user input reaches a shell -> command injection
    subprocess.run("ping -c 1 " + host, shell=True)
    # OK: constant command, nothing user-controlled -> ignored by pattern-not (noise reduction)
    subprocess.run("uptime", shell=True)
    return "pong"


@app.route("/user")
def get_user():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    # BAD (CRITICAL): SQL built from user input -> SQL injection
    rows = conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchall()
    # OK: parameterized query -> not flagged
    rows = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
    return str(rows)


@app.route("/config", methods=["POST"])
def load_config():
    # BAD (HIGH): yaml.load without SafeLoader can build arbitrary Python objects
    data = yaml.load(request.data)
    # OK: safe loader -> not flagged
    data = yaml.safe_load(request.data)
    return str(data)


def fetch_partner_feed(url):
    # BAD (MEDIUM): TLS certificate checking turned off
    return requests.get(url, verify=False, timeout=5)


def cache_key(text):
    # BAD (LOW): MD5 is a weak hash (low risk when used only as a cache key)
    return hashlib.md5(text.encode()).hexdigest()


if __name__ == "__main__":
    app.run()
