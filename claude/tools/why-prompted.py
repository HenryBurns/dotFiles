#!/usr/bin/env python3
"""Report what a session ACTUALLY decided about a Bash command, from the record.

    why-prompted.py 'ssh -o BatchMode=yes host'   # search every transcript
    why-prompted.py -f cmd.txt                    # exact text, no retyping
    why-prompted.py --asks 'pb devel'             # only the ones that prompted
    why-prompted.py --session ba0890ba --asks     # everything one session asked

The sibling tool, why-prompt.py, predicts: it evaluates a command against
today's rules and today's guard. This one reports: for each time the command
ran, it prints the hook's own permissionDecision and permissionDecisionReason,
verbatim, plus how long the call took.

The two disagree more often than they should, and when they do, THIS one is
right. A guard crash mid-edit once made a command prompt with
"(TypeError)"; by the time anyone asked why, the guard was repaired and the
prediction cleared it. Reasoning from the prediction produced a confident wrong
answer twice in one session -- stale settings, blamed for a prompt that was
really a path gate -- before anyone read the record.

So: reach for this FIRST when asked "why did this prompt", and use
why-prompt.py to work out what to change once the cause is known.

A long gap between the call and its result means a human was looking at a
prompt, but only when the decision was "ask" -- otherwise it is just a slow
command, and the tool labels it accordingly.

This reads other sessions' transcripts, which is fine HERE: it is hand-run and
its output is advisory. The guard must never do it -- unbounded I/O on the
gating path, and a verdict inferred from a conversation it cannot see.
"""

import argparse
import datetime
import glob
import json
import os
import sys

HOME = os.path.expanduser("~")
PROJECTS = os.path.join(HOME, ".claude", "projects")


def _epoch(timestamp):
    """ISO-8601 timestamp to epoch seconds, or None if it cannot be read."""
    try:
        return datetime.datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")).timestamp()
    except (AttributeError, ValueError):
        return None


def _hook_verdict(stdout):
    """(decision, reason) from a PreToolUse hook's stdout, or (None, None).

    A hook that stays silent prints nothing, which is a real outcome and not a
    parse failure -- it means the rules decided alone.
    """
    if not stdout or not stdout.strip():
        return None, None
    try:
        out = json.loads(stdout)["hookSpecificOutput"]
    except (ValueError, KeyError, TypeError):
        return None, None
    return out.get("permissionDecision"), out.get("permissionDecisionReason")


def scan_lines(lines, needle):
    """Records for every Bash call in `lines` whose command contains `needle`.

    Returns [(decision, reason, waited)] in call order. `waited` is the seconds
    between the call and its result, or None when the transcript has no result
    for it -- an unfinished call, or one whose result was written after this.

    Two passes, because a hook attachment and a tool_result are written as
    separate records that can be far from the call: the first pass collects the
    ids worth caring about, the second fills them in. That also keeps the memory
    cost proportional to the MATCHES rather than to the transcript, which
    matters -- these files reach hundreds of megabytes.
    """
    order, calls = [], {}
    parsed = []
    for line in lines:
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue                   # a partial last line, still being written
        parsed.append(entry)
        content = (entry.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if (block.get("type") == "tool_use"
                    and block.get("name") == "Bash"
                    and needle in (block.get("input") or {}).get("command", "")):
                uid = block.get("id")
                order.append(uid)
                calls[uid] = {"at": entry.get("timestamp"),
                              "command": block["input"]["command"],
                              "decision": None, "reason": None, "done": None}
    if not calls:
        return []

    for entry in parsed:
        attachment = entry.get("attachment") or {}
        uid = attachment.get("toolUseID")
        if uid in calls and attachment.get("hookName") == "PreToolUse:Bash":
            decision, reason = _hook_verdict(attachment.get("stdout"))
            if decision is not None:
                calls[uid]["decision"] = decision
                calls[uid]["reason"] = reason
        content = (entry.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if (block.get("type") == "tool_result"
                    and block.get("tool_use_id") in calls
                    and calls[block["tool_use_id"]]["done"] is None):
                calls[block["tool_use_id"]]["done"] = entry.get("timestamp")

    records = []
    for uid in order:
        call = calls[uid]
        start, end = _epoch(call["at"]), _epoch(call["done"])
        waited = round(end - start, 3) if start and end else None
        records.append((call["decision"], call["reason"], waited))
    return records


def scan_file(path, needle):
    """scan_lines over one transcript, paired with its call metadata."""
    try:
        with open(path, errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []
    records = scan_lines(lines, needle)
    if not records:
        return []
    # Re-walk only for the display fields; scan_lines is the tested seam and is
    # deliberately kept to the verdict triple.
    detail = []
    for line in lines:
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        content = (entry.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if (block.get("type") == "tool_use"
                    and block.get("name") == "Bash"
                    and needle in (block.get("input") or {}).get("command", "")):
                detail.append((entry.get("timestamp"),
                               block["input"]["command"]))
    session = os.path.basename(path)[:8]
    return [(when, session, cmd) + rec
            for (when, cmd), rec in zip(detail, records)]


def find(needle, session=None, asks_only=False):
    """Every recorded run of `needle`, oldest first."""
    rows = []
    pattern = os.path.join(PROJECTS, "*", "*.jsonl")
    for path in glob.glob(pattern):
        if session and not os.path.basename(path).startswith(session):
            continue
        rows.extend(scan_file(path, needle))
    if asks_only:
        rows = [r for r in rows if r[3] == "ask"]
    return sorted(rows, key=lambda row: row[0] or "")


def selftest():
    """Run WHY_PROMPTED_CASES from the guard's cases file. Returns failures."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "bash_write_guard_cases",
        os.path.join(HOME, ".claude", "hooks", "bash-write-guard-cases.py"))
    cases = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cases)

    failed = 0
    for label, lines, needle, expected in cases.WHY_PROMPTED_CASES:
        got = scan_lines(lines, needle)
        if got != expected:
            failed += 1
            print(f"FAIL  {label}\n      needle   {needle!r}\n"
                  f"      expected {expected}\n      got      {got}")
    print(f"{len(cases.WHY_PROMPTED_CASES)} cases, {failed} failed")
    return failed


def _describe_wait(decision, waited):
    """How to read the call-to-result gap, which depends on the decision."""
    if waited is None:
        return "no result recorded"
    if waited < 1:
        return f"{waited:.1f}s"
    shown = f"{int(waited // 60)}m{int(waited % 60):02d}s" if waited >= 60 \
        else f"{waited:.1f}s"
    return f"{shown} waiting for approval" if decision == "ask" else shown


def main():
    parser = argparse.ArgumentParser(
        description="What a session actually decided about a Bash command.")
    parser.add_argument("command", nargs="*",
                        help="command text, or a fragment of it")
    parser.add_argument("-f", "--file",
                        help="read the command text from this file, exactly")
    parser.add_argument("--session", help="limit to one session id (prefix)")
    parser.add_argument("--asks", action="store_true",
                        help="only calls the hook answered with ask")
    parser.add_argument("--limit", type=int, default=20,
                        help="most recent N (default 20)")
    parser.add_argument("--test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.test:
        return 1 if selftest() else 0

    if args.file:
        needle = open(args.file, errors="replace").read().rstrip("\n")
    elif args.command:
        needle = " ".join(args.command)
    elif not sys.stdin.isatty():
        needle = sys.stdin.read().rstrip("\n")
    else:
        needle = ""
    if not needle and not args.session:
        raise SystemExit("usage: why-prompted.py '<command or fragment>'")

    rows = find(needle, session=args.session, asks_only=args.asks)
    if not rows:
        where = f" in session {args.session}" if args.session else ""
        print(f"no recorded run of that command{where}.")
        print("  (the match is on the command text as the transcript stored "
              "it -- use -f to avoid retyping a multi-line command)")
        return 0

    shown = rows[-args.limit:]
    print(f"{len(rows)} recorded run(s)"
          + (f", showing the last {len(shown)}" if len(shown) < len(rows) else ""))
    for when, session, cmd, decision, reason, waited in shown:
        verdict = decision or "no hook record"
        print(f"\n{when}  {session}  {verdict}")
        if reason:
            print(f"  reason: {reason}")
        print(f"  elapsed: {_describe_wait(decision, waited)}")
        first = cmd.strip().splitlines()[0]
        more = len(cmd.strip().splitlines()) - 1
        print(f"  command: {first[:100]}" + (f"  (+{more} lines)" if more else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
