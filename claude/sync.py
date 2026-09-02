#!/usr/bin/env python3
"""Export the portable parts of ~/.claude into this repo.

    python3 claude/sync.py           # refresh the repo from live config
    python3 claude/sync.py --check   # report drift, write nothing (for CI)

Pulls from the real ~/.claude/settings.json rather than a hand-maintained copy,
so the repo cannot drift from what is actually in use. Everything specific to a
machine, an employer, or an internal toolchain is dropped on the way out:

  * permissions.additionalDirectories -- every entry is a local absolute path
  * absolute paths in env values       -- rewritten to __HOME__
  * the files in SKIP                  -- never copied at all

The repo is a PUBLIC mirror, so a keyword scan runs over everything about to be
written and aborts on a hit. That check is the reason this script exists: a rule
or comment mentioning an internal project name would otherwise be published by
whoever next runs the sync, long after anyone remembers to look.
"""

import argparse
import json
import os
import re
import shutil
import sys

HOME = os.path.expanduser("~")
LIVE = os.path.join(HOME, ".claude")
REPO = os.path.dirname(os.path.abspath(__file__))

# Copied verbatim. Anything not listed is not published.
FILES = [
    "bash_env.sh",
    "hooks/bash-write-guard.py",
    "hooks/bash-write-guard-cases.py",
    "hooks/bash-write-guard-tables.py",
    "hooks/unguarded-worktrees",
    "tools/why-prompt.py",
    "tools/guard-verdict.py",
    "tools/check-settings.py",
    "tools/transcript_cost.py",
    # The only portable skill. The rest of ~/.claude/skills is workplace
    # tooling, so skills are published one path at a time, never as a tree.
    "skills/write-guard/SKILL.md",
]

# Named so the omission is a decision on the record, not an oversight.
SKIP = {
    "hooks/local_grants.py": "site-specific grants; names internal tooling",
    "hooks/allowed-blueprints": "internal test-blueprint names",
    "CLAUDE.md": "workplace build, branch and release conventions",
    "tools/share-perms.sh": "bundles the two files above",
    "tools/subcommand-tools.local": "internal tool names; transcript_cost.py "
                                    "reads it and works without it",
    "skills/ (except write-guard)": "workplace build, test, ticket and review "
                                    "conventions",
    ".credentials.json": "OAuth credentials -- never leaves the machine",
    "history.jsonl": "every command run, verbatim",
    "projects/": "full session transcripts and per-project memory",
}

# permissions keys that are portable; everything else is dropped.
KEEP_PERMISSION_KEYS = {"allow", "deny", "ask"}

# Settings keys that are portable at the top level.
KEEP_TOP_KEYS = {"env", "permissions", "hooks", "worktree", "theme", "model"}

# Structural giveaways: absolute paths that can only mean one machine. Safe to
# publish, because the patterns describe a shape rather than a name.
STRUCTURAL = re.compile(r"/mnt/|/media/|/home/(?!you\b)[a-z]|/u/[a-z]",
                        re.IGNORECASE)

# Site keywords -- internal project, tool and product names -- live in an
# untracked file, one regex per line, because a denylist of them is itself a
# disclosure: it names the employer and every internal system worth hiding.
DENY_FILE = os.path.join(REPO, "sync-deny.local")


def load_deny():
    """(compiled patterns, note). Missing file is a warning, not an error."""
    try:
        with open(DENY_FILE) as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None, (f"no {os.path.basename(DENY_FILE)}: only structural "
                      f"path checks ran, no site keywords were checked")
    patterns = [l.strip() for l in lines
                if l.strip() and not l.strip().startswith("#")]
    if not patterns:
        return None, f"{os.path.basename(DENY_FILE)} is empty"
    try:
        return re.compile("|".join(patterns), re.IGNORECASE), None
    except re.error as exc:
        return None, f"{os.path.basename(DENY_FILE)} is not valid regex: {exc}"


def scrub_settings(settings):
    """Portable subset of a settings dict, plus a list of what was dropped."""
    dropped, out = [], {}

    for key, value in settings.items():
        if key not in KEEP_TOP_KEYS:
            dropped.append(f"{key} (not a portable key)")
            continue
        out[key] = value

    perms = out.get("permissions")
    if isinstance(perms, dict):
        kept = {}
        for key, value in perms.items():
            if key in KEEP_PERMISSION_KEYS:
                kept[key] = value
            else:
                count = len(value) if isinstance(value, list) else 1
                dropped.append(f"permissions.{key} ({count} local entr"
                               f"{'y' if count == 1 else 'ies'})")
        out["permissions"] = kept

    # env values are the one place a real absolute path is load-bearing:
    # BASH_ENV must be absolute, since bash does not expand ~ in it.
    #
    # Home can have more than one spelling -- here $HOME is /u/<user> while the
    # realpath is /home/<user> -- and a value written with the other one sailed
    # past this and was caught downstream by the leak scanner. Match every
    # spelling, longest first so a prefix of another cannot win.
    homes = sorted({HOME, os.path.realpath(HOME)}, key=len, reverse=True)
    env = out.get("env")
    if isinstance(env, dict):
        out["env"] = {}
        for key, value in env.items():
            if isinstance(value, str):
                # Every occurrence, not just a leading one, and every spelling
                # rather than the first that hits: PATH is a colon-joined LIST,
                # so home appears mid-value and repeatedly. Rewriting only the
                # prefix let the rest of a PATH through to the leak scanner.
                original = value
                for home in homes:
                    value = value.replace(home, "__HOME__")
                if value != original:
                    dropped.append(f"env.{key} (absolute path -> __HOME__)")
            out["env"][key] = value

    return out, dropped


def offending_lines(text, label, deny=None):
    checks = [STRUCTURAL] + ([deny] if deny is not None else [])
    return [f"  {label}:{n}: {line.strip()}"
            for n, line in enumerate(text.splitlines(), 1)
            if any(check.search(line) for check in checks)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="report drift and leaks, write nothing")
    args = parser.parse_args()

    try:
        with open(os.path.join(LIVE, "settings.json")) as handle:
            live = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"cannot read {LIVE}/settings.json: {exc}")

    settings, dropped = scrub_settings(live)
    outgoing = {"settings.json": json.dumps(settings, indent=2) + "\n"}

    missing = []
    for rel in FILES:
        path = os.path.join(LIVE, rel)
        try:
            with open(path) as handle:
                outgoing[rel] = handle.read()
        except OSError:
            missing.append(rel)

    deny, deny_note = load_deny()
    if deny_note:
        print(f"WARNING: {deny_note}", file=sys.stderr)

    leaks = []
    for rel, text in outgoing.items():
        leaks.extend(offending_lines(text, rel, deny))
    if leaks:
        print("ABORT -- workplace-specific content in files bound for a public "
              "repo:\n" + "\n".join(leaks), file=sys.stderr)
        return 1

    print("dropped as non-portable:")
    for item in dropped:
        print(f"  - {item}")
    print("never published:")
    for rel, why in SKIP.items():
        print(f"  - {rel:34} {why}")
    if missing:
        print("MISSING from ~/.claude (not written):")
        for rel in missing:
            print(f"  - {rel}")

    changed = []
    for rel, text in outgoing.items():
        target = os.path.join(REPO, rel)
        try:
            with open(target) as handle:
                if handle.read() == text:
                    continue
        except OSError:
            pass
        changed.append(rel)
        if not args.check:
            os.makedirs(os.path.dirname(target) or REPO, exist_ok=True)
            with open(target, "w") as handle:
                handle.write(text)
            shutil.copymode(os.path.join(LIVE, rel), target) if rel in FILES \
                else None

    verb = "would update" if args.check else "updated"
    print(f"\n{verb}: {', '.join(changed) if changed else '(nothing, in sync)'}")
    return 1 if args.check and changed else 0


if __name__ == "__main__":
    sys.exit(main())
