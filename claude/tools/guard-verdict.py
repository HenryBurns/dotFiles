#!/usr/bin/env python3
"""Show what the Bash write guard would decide for each command given.

    guard-verdict.py 'sed -i s/a/b/ /tmp/.../scratchpad/f' 'echo x | tee /etc/passwd'
    guard-verdict.py --expect ask 'rm -rf /tmp/x' 'sed -i s/a/b/ f'
    printf '%s\n' 'cmd one' 'cmd two' | guard-verdict.py -

Each command is passed to the guard exactly as Claude Code passes it -- a JSON
`tool_input` on stdin, one subprocess per command -- rather than by importing
the module. What is reported is therefore what the hook will really emit,
including anything that only goes wrong in the wiring.

The verdict is printed FIRST so the columns line up no matter how long the
command is; scratchpad paths are long enough to wreck any other layout.

With --expect, every command must produce that verdict or the run fails, so
this can gate a check. Exit status is 1 on any mismatch, 2 if the guard could
not be run at all.

Pass commands after `--` if one of them begins with a dash.
"""

import argparse
import json
import os
import subprocess
import sys

GUARD = os.path.expanduser("~/.claude/hooks/bash-write-guard.py")
VERDICTS = ("allow", "ask", "silent")


def verdict_of(command):
    """(verdict, reason) for one command, as the hook would emit it."""
    payload = json.dumps({"tool_input": {"command": command}})
    try:
        proc = subprocess.run([GUARD], input=payload, capture_output=True,
                              text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return "ERROR", f"could not run the guard: {exc}"

    out = proc.stdout.strip()
    if not out:
        # No stdout is the guard's "silent": it is not vouching either way, and
        # the allow rules decide alone. A non-zero exit with no output would be
        # a crash, which the guard turns into `ask` -- so if that ever shows up
        # here as silent, the fail-closed path itself is broken.
        if proc.returncode != 0:
            return "ERROR", (f"exit {proc.returncode}, no output: "
                             f"{proc.stderr.strip()[:200]}")
        return "silent", ""
    try:
        hook = json.loads(out)["hookSpecificOutput"]
    except (ValueError, KeyError) as exc:
        return "ERROR", f"unparseable output ({exc}): {out[:200]}"
    return hook.get("permissionDecision", "?"), \
        hook.get("permissionDecisionReason", "")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("commands", nargs="+", metavar="CMD",
                        help="shell commands to judge; `-` reads them from "
                             "stdin, one per line")
    parser.add_argument("--expect", choices=VERDICTS,
                        help="require this verdict for every command")
    parser.add_argument("--quiet", action="store_true",
                        help="print only mismatches (implies --expect)")
    args = parser.parse_args()

    commands = []
    for item in args.commands:
        if item == "-":
            commands.extend(line for line in sys.stdin.read().splitlines()
                            if line.strip())
        else:
            commands.append(item)

    if not os.access(GUARD, os.X_OK):
        sys.exit(f"{GUARD} is missing or not executable")

    failures = 0
    for command in commands:
        verdict, reason = verdict_of(command)
        bad = args.expect is not None and verdict != args.expect
        failures += bool(bad) or verdict == "ERROR"
        if args.quiet and not bad and verdict != "ERROR":
            continue
        mark = "FAIL " if bad else "     "
        line = f"{mark}{verdict:<7} {command}"
        print(line if not reason else f"{line}\n{'':<13}-- {reason}")

    if args.expect:
        # stdout is block-buffered into a pipe while stderr is not, so the
        # summary otherwise prints before the results it summarizes.
        sys.stdout.flush()
        print(f"\n{len(commands)} command(s), {failures} unexpected",
              file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
