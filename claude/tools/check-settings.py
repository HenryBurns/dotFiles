#!/usr/bin/env python3
"""Check ~/.claude/settings.json for the mistakes that are easy to make by hand.

    check-settings.py                 # check every settings*.json under ~/.claude
    check-settings.py --quiet         # print only problems
    check-settings.py PATH ...        # check specific files

Exit status is 1 if anything failed, 0 otherwise. Warnings alone do not fail:
they are shapes worth a second look, not errors.

JSON syntax is the least of it -- a broken file is obvious the moment Claude
Code restarts. What is NOT obvious is a rule that quietly means more than it
says, so most of the checks here are about the allow list:

  * a prefix rule ending in an option that also has an `=VALUE` form covers
    that form too. `Bash(git --exec-path:*)` reads as "let git print its exec
    path" and also admits `git --exec-path=/tmp/evil status`, which repoints
    where git finds its helper programs. The write guard happens to refuse
    that one, so this is reported by severity: FAIL when nothing else catches
    it, WARN when the guard does.
  * a rule that another rule already covers is dead weight, and dead weight in
    a security-relevant list is how a broad rule hides among narrow ones.
  * additionalDirectories are a second, independent gate; a path that does not
    exist silently grants nothing, and a typo looks exactly like a real entry.
"""

import argparse
import glob
import importlib.util
import json
import os
import sys

HOME = os.path.expanduser("~")
GUARD = os.path.join(HOME, ".claude", "hooks", "bash-write-guard.py")

# Appended to a prefix rule's command to see what else that rule admits. Only
# the `=` form is probed: a space-separated continuation is what `:*` is FOR,
# but `=VALUE` fuses onto the last token and can change which option it is.
ATTACHED_PROBE = "=/tmp/probe"

# Options whose `=VALUE` form redirects where a program reads, writes, or finds
# the programs it executes. Enumerated rather than "any option", because most
# flags have no `=VALUE` spelling at all and warning about those buries the few
# that matter -- the first version of this check produced four false positives
# (`git --version=...`) and no true ones. Add to this as new ones are met.
ATTACHED_VALUE_OPTIONS = {
    "--exec-path",        # where git finds its helper programs
    "--git-dir", "--work-tree", "--namespace",
    "-c",                 # arbitrary config, including aliases that shell out
    "--output", "--output-directory", "-o",
    "--upload-pack", "--receive-pack",   # programs run on the far end
    "--file", "-f",       # a program or script read from elsewhere
}


def load_guard():
    """The write guard as a module, or None if it cannot be imported."""
    try:
        spec = importlib.util.spec_from_file_location("bash_write_guard", GUARD)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def bash_rules(allow):
    """[(rule, command, is_prefix)] for the Bash entries of an allow list."""
    out = []
    for rule in allow:
        if not (rule.startswith("Bash(") and rule.endswith(")")):
            continue
        body = rule[len("Bash("):-1]
        if body.endswith(":*"):
            out.append((rule, body[:-len(":*")], True))
        else:
            out.append((rule, body, False))
    return out


def check_duplicates(allow, report):
    seen = set()
    for rule in allow:
        if rule in seen:
            report("FAIL", f"{rule} is listed more than once")
        seen.add(rule)


def check_subsumed(rules, report):
    """A prefix rule that another prefix rule already covers."""
    prefixes = [(rule, cmd) for rule, cmd, is_prefix in rules if is_prefix]
    for rule, cmd in prefixes:
        for other_rule, other in prefixes:
            if other_rule == rule or not other:
                continue
            # "git log" is covered by "git", but "git logic" is not covered by
            # "git log" -- the boundary has to fall between words.
            if cmd == other or cmd.startswith(other + " "):
                report("WARN", f"{rule} is already covered by {other_rule}")
                break


def check_attached_values(rules, guard, report):
    """A prefix rule whose last token also has an `=VALUE` spelling."""
    for rule, cmd, is_prefix in rules:
        if not is_prefix or not cmd:
            continue
        if cmd.split()[-1] not in ATTACHED_VALUE_OPTIONS:
            continue
        probe = cmd + ATTACHED_PROBE
        if guard is None:
            report("WARN", f"{rule} also admits `{probe} ...`; "
                           f"could not load the guard to see if it objects")
            continue
        if guard.find_reasons(probe + " status"):
            report("WARN", f"{rule} also admits `{probe} ...`, but the write "
                           f"guard refuses it -- rule is wider than it reads")
        else:
            report("FAIL", f"{rule} also admits `{probe} ...` and nothing "
                           f"refuses it; make this an exact rule")


def check_directories(dirs, report):
    for entry in dirs:
        path = os.path.expanduser(entry)
        if not path.startswith("/"):
            report("FAIL", f"additionalDirectories: {entry} is not absolute")
        elif not os.path.isdir(path):
            report("FAIL", f"additionalDirectories: {entry} does not exist")


def check_file(path, guard, quiet):
    """Report on one settings file. Returns (failures, warnings)."""
    counts = {"FAIL": 0, "WARN": 0}
    lines = []

    def report(level, message):
        counts[level] += 1
        lines.append(f"  {level} {message}")

    try:
        with open(path) as handle:
            settings = json.load(handle)
    except OSError as exc:
        print(f"{path}\n  FAIL cannot read: {exc}")
        return 1, 0
    except json.JSONDecodeError as exc:
        print(f"{path}\n  FAIL invalid JSON at line {exc.lineno}: {exc.msg}")
        return 1, 0

    permissions = settings.get("permissions") or {}
    allow = permissions.get("allow") or []
    rules = bash_rules(allow)

    check_duplicates(allow, report)
    check_subsumed(rules, report)
    check_attached_values(rules, guard, report)
    check_directories(permissions.get("additionalDirectories") or [], report)

    if not quiet or counts["FAIL"] or counts["WARN"]:
        print(f"{path}  ({len(allow)} allow, {len(rules)} of them Bash)")
        print("\n".join(lines) if lines else "  ok")
    return counts["FAIL"], counts["WARN"]


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", metavar="PATH",
                        help="settings files to check "
                             "(default: ~/.claude/settings*.json)")
    parser.add_argument("--quiet", action="store_true",
                        help="print only files that have something to say")
    args = parser.parse_args()

    paths = args.paths or sorted(
        glob.glob(os.path.join(HOME, ".claude", "settings*.json")))
    if not paths:
        sys.exit("no settings files found")

    guard = load_guard()
    failures = warnings = 0
    for path in paths:
        bad, warned = check_file(path, guard, args.quiet)
        failures += bad
        warnings += warned

    print(f"\n{len(paths)} file(s), {failures} failure(s), "
          f"{warnings} warning(s)", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
