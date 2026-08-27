#!/usr/bin/env python3
"""Install this repo's portable Claude Code config into ~/.claude.

    python3 claude/install.py             # merge into ~/.claude
    python3 claude/install.py --dry-run   # show what would change

MERGES rather than overwrites, because the live config legitimately holds things
this repo must never carry:

  * permissions.additionalDirectories -- local absolute paths
  * extra allow rules for local tooling
  * hooks/local_grants.py             -- site-specific grants

So repo settings win only for the keys the repo actually defines, allow lists are
unioned, and local_grants.py is never touched. The previous settings.json is
backed up first.

Permissions are set explicitly: the hook must be readable by the interpreter and
the tools executable, and a fresh machine's umask cannot be assumed.
"""

import argparse
import json
import os
import shutil
import sys
import time

HOME = os.path.expanduser("~")
LIVE = os.path.join(HOME, ".claude")
REPO = os.path.dirname(os.path.abspath(__file__))

# (path relative to both trees, mode). 0755 for anything executed directly.
FILES = [
    ("bash_env.sh", 0o644),
    ("hooks/bash-write-guard.py", 0o755),
    ("hooks/unguarded-worktrees", 0o644),
    ("tools/why-prompt.py", 0o755),
    ("skills/write-guard/SKILL.md", 0o644),
]

# Present in the repo as a template; must not overwrite a real one.
NEVER_OVERWRITE = {"hooks/local_grants.py"}

# Lists that are unioned instead of replaced, so local additions survive.
UNION_KEYS = [("permissions", "allow"), ("permissions", "deny"),
              ("permissions", "ask")]


def merge(repo, live):
    """Repo settings over live, preserving local-only keys and list additions."""
    merged = dict(live)
    notes = []

    for key, value in repo.items():
        if key not in merged:
            merged[key] = value
            continue
        if isinstance(value, dict) and isinstance(merged[key], dict):
            inner = dict(merged[key])
            inner.update(value)
            merged[key] = inner
        else:
            merged[key] = value

    for outer, inner in UNION_KEYS:
        repo_list = (repo.get(outer) or {}).get(inner)
        live_list = (live.get(outer) or {}).get(inner)
        if not isinstance(repo_list, list) or not isinstance(live_list, list):
            continue
        extra = [item for item in live_list if item not in repo_list]
        if extra:
            merged[outer][inner] = repo_list + extra
            notes.append(f"kept {len(extra)} local {outer}.{inner} entr"
                         f"{'y' if len(extra) == 1 else 'ies'}: "
                         f"{', '.join(map(str, extra[:4]))}"
                         f"{' ...' if len(extra) > 4 else ''}")

    # Preserved implicitly by the loop above -- report it so it is visible.
    local_dirs = (live.get("permissions") or {}).get("additionalDirectories")
    if local_dirs:
        notes.append(f"kept {len(local_dirs)} local "
                     f"permissions.additionalDirectories")

    return merged, notes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        with open(os.path.join(REPO, "settings.json")) as handle:
            repo = json.loads(handle.read().replace("__HOME__", HOME))
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"cannot read {REPO}/settings.json: {exc}")

    live_path = os.path.join(LIVE, "settings.json")
    try:
        with open(live_path) as handle:
            live = json.load(handle)
    except FileNotFoundError:
        live = {}
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"{live_path} exists but will not parse, refusing to "
                 f"overwrite it: {exc}")

    merged, notes = merge(repo, live)
    for note in notes:
        print(f"  {note}")

    text = json.dumps(merged, indent=2) + "\n"
    if text == json.dumps(live, indent=2) + "\n":
        print("  settings.json already matches")
    elif args.dry_run:
        print("  settings.json would change")
    else:
        os.makedirs(LIVE, exist_ok=True)
        if os.path.exists(live_path):
            backup = f"{live_path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
            shutil.copy2(live_path, backup)
            print(f"  backed up -> {backup}")
        with open(live_path, "w") as handle:
            handle.write(text)
        os.chmod(live_path, 0o600)
        print("  wrote settings.json")

    for rel, mode in FILES:
        source, target = os.path.join(REPO, rel), os.path.join(LIVE, rel)
        if not os.path.exists(source):
            print(f"  SKIP {rel} (not in repo)")
            continue
        if args.dry_run:
            print(f"  would install {rel} (mode {mode:04o})")
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(source, target)
        os.chmod(target, mode)
        print(f"  installed {rel} (mode {mode:04o})")

    for rel in sorted(NEVER_OVERWRITE):
        target = os.path.join(LIVE, rel)
        state = "present, left alone" if os.path.exists(target) else "absent"
        print(f"  {rel}: {state}")

    print("\nsettings.json is read at startup only -- restart Claude Code. "
          "Hook files are re-read per command and need no restart.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
