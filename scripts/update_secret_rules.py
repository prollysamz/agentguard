"""Refresh the vendored gitleaks ruleset.

    python scripts/update_secret_rules.py [--ref <commit-or-tag>]

Downloads config/gitleaks.toml and LICENSE from github.com/gitleaks/gitleaks at ``ref``
(default: the latest commit touching the config), checks every rule compiles on RE2, and
rewrites agentguard/risk/data/. Run the test suite afterwards and review the diff.
"""

import argparse
import json
import sys
import tomllib
import urllib.request
from pathlib import Path

REPOSITORY = "gitleaks/gitleaks"
DATA = Path(__file__).resolve().parent.parent / "agentguard" / "risk" / "data"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "agentguard-rules-update"})
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310 - fixed https URL
        return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref", help="gitleaks commit or tag (default: latest config change)")
    args = parser.parse_args()
    ref = args.ref
    if not ref:
        commits = json.loads(
            fetch(
                f"https://api.github.com/repos/{REPOSITORY}/commits"
                "?path=config/gitleaks.toml&per_page=1"
            )
        )
        ref = commits[0]["sha"]
    raw = f"https://raw.githubusercontent.com/{REPOSITORY}/{ref}"
    config = fetch(f"{raw}/config/gitleaks.toml").decode("utf-8")
    license_text = fetch(f"{raw}/LICENSE").decode("utf-8")

    import re2

    rules = tomllib.loads(config)["rules"]
    for rule in rules:
        if "regex" in rule:
            re2.compile(rule["regex"])
    header = (
        f"# Vendored from https://github.com/{REPOSITORY}/blob/{ref}/config/gitleaks.toml\n"
        "# Copyright (c) 2019 Zachary Rice. MIT License: see gitleaks-LICENSE.txt in this "
        "directory.\n# Update with: python scripts/update_secret_rules.py\n\n"
    )
    (DATA / "gitleaks.toml").write_text(header + config, encoding="utf-8", newline="\n")
    (DATA / "gitleaks-LICENSE.txt").write_text(license_text, encoding="utf-8", newline="\n")
    print(f"Updated {len(rules)} rules from {REPOSITORY}@{ref[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
