#!/usr/bin/env python3
"""PreToolUse gate for Bash: refuse a commit message far longer than its change.

Sibling of comment-ratio-gate.py, same failure and same remedy: the standing
instruction is to size a message to the change rather than to the analysis
behind it, and the instruction alone has not been enough.

What is measured is the BODY -- subject, blank lines and trailers (JIRA:,
Review:, Testing:, Co-Authored-By:) are all excluded, since those are required
and their length is not a choice. The limit comes from the size of the change,
because a long message on a large refactor is proportionate and a long message
on a four-line fix is the thing worth catching.

LIMITS was measured, not picked: each ceiling is its band's MEDIAN body length
over 600 commits, so going over is the exception rather than room to fill.

Fails OPEN, like its sibling: no repo, no message it can see, a crash -- all
allow. It also cannot see a message typed in an editor, since that is written
after the hook runs; a post of the finished commit catches that case later.

Self-test:  ./commit-message-gate.py --test
"""

import json
import os
import re
import shlex
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from hook_triggers import acknowledged, commits_all, triggered  # noqa: E402

# (max lines changed, max body lines). Read as: up to this size, that many.
LIMITS = [(20, 3), (100, 4), (500, 6), (10 ** 9, 7)]

# Required lines whose length is not a stylistic choice, so not counted. A
# commit standard may mandate Testing:, review tooling stamps Review: and
# JIRA:, and the harness adds Co-Authored-By:.
TRAILER = re.compile(
    r"^\s*(JIRA|Review|Reviewed at|Testing|Co-Authored-By|Signed-off-by|"
    r"Change-Id|Bug|Fixes|Depends-On|CC)\s*:", re.I)


def body_lines(message):
    """Prose lines after the subject.

    Blanks, trailers and indented blocks do not count: their length is not a
    choice, and the budget is for prose. Paragraphs here are flush left.
    """
    lines = message.splitlines()
    return [ln for ln in lines[1:]
            if ln.strip() and not TRAILER.match(ln) and not ln[:1].isspace()]


def limit_for(changed):
    for ceiling, allowed in LIMITS:
        if changed <= ceiling:
            return allowed
    return LIMITS[-1][1]


def numstat_total(args, cwd):
    out = subprocess.run(["git", "diff", "--numstat"] + args,
                         cwd=cwd, capture_output=True, text=True)
    if out.returncode != 0:
        return None
    total = 0
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        # A binary file reports "-\t-"; it has no line count to add.
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            total += int(parts[0]) + int(parts[1])
    return total


def message_from_command(command, cwd):
    """The message this command would write, or None if it cannot be seen.

    `-m` and `-F` put it in the command. A bare `git commit` opens an editor and
    writes the message after this hook has already run, so there is nothing to
    measure -- that case is caught later, when the finished commit is posted.
    """
    try:
        argv = shlex.split(command)
    except ValueError:
        return None

    parts, i = [], 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("-m", "--message") and i + 1 < len(argv):
            parts.append(argv[i + 1])
            i += 2
            continue
        if tok.startswith("--message="):
            parts.append(tok.split("=", 1)[1])
            i += 1
            continue
        if tok.startswith("-m") and len(tok) > 2 and not tok.startswith("--"):
            parts.append(tok[2:])
            i += 1
            continue
        # Every spelling git accepts, as for -m above: missing one fails the gate open,
        # which is silent.
        path = None
        if tok in ("-F", "--file") and i + 1 < len(argv):
            path, step = argv[i + 1], 2
        elif tok.startswith("--file="):
            path, step = tok.split("=", 1)[1], 1
        elif tok.startswith("-F") and len(tok) > 2:
            path, step = tok[2:], 1
        if path is not None:
            try:
                with open(os.path.join(cwd, path)) as fh:
                    parts.append(fh.read())
            except OSError:
                return None
            i += step
            continue
        i += 1
    # git joins repeated -m with a blank line, which is how a body follows a
    # subject; reproducing that keeps the subject on line 1 where it belongs.
    return "\n\n".join(parts) if parts else None


def revision_in(command):
    m = re.search(r"\b(HEAD|[0-9a-f]{7,40})\b", command)
    return m.group(1) if m else None


def gather(command, cwd):
    """(message, changed_lines) for the change this command publishes."""
    is_commit = re.search(r"\bgit\s+commit(?![\w-])", command)

    if is_commit:
        message = message_from_command(command, cwd)
        if message is None:
            return None
        changed = numstat_total(["--cached"], cwd)
        # `-a` stages every tracked change on the way past, so the index alone
        # is not what gets committed. Counting only `--cached` judged a 35-line
        # commit by its 5 staged lines -- always understating, so the budget
        # came out too tight rather than too loose.
        if commits_all(command):
            unstaged = numstat_total([], cwd)
            if unstaged is not None and changed is not None:
                changed += unstaged
        # An amend replaces HEAD, so the resulting commit carries HEAD's diff as
        # well as whatever is staged on top of it.
        if "--amend" in command:
            head = numstat_total(["HEAD^", "HEAD"], cwd)
            if head is not None and changed is not None:
                changed += head
        return (message, changed)

    rev = revision_in(command) or "HEAD"
    msg = subprocess.run(["git", "log", "-1", "--format=%B", rev],
                         cwd=cwd, capture_output=True, text=True)
    if msg.returncode != 0:
        return None
    return (msg.stdout, numstat_total([f"{rev}^", rev], cwd))


def emit_deny(reason):
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, sys.stdout)


def decide():
    payload = json.load(sys.stdin)
    command = (payload.get("tool_input") or {}).get("command") or ""
    if not command.strip() or acknowledged(command) or not triggered(command):
        return 0

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    if subprocess.run(["git", "rev-parse", "--is-inside-work-tree"],
                      cwd=cwd, capture_output=True).returncode != 0:
        return 0

    got = gather(command, cwd)
    if got is None:
        return 0
    message, changed = got
    if changed is None or not message.strip():
        return 0

    body = body_lines(message)
    allowed = limit_for(changed)
    if len(body) <= allowed:
        return 0

    emit_deny(
        f"Commit message body is {len(body)} lines for a {changed}-line change; "
        f"the limit at that size is {allowed}.\n\n"
        "Body counted (subject, blanks and trailers excluded):\n"
        + "\n".join(f"  {ln}" for ln in body[:allowed + 6])
        + (f"\n  ... and {len(body) - allowed - 6} more"
           if len(body) > allowed + 6 else "")
        + "\n\nKeep the conclusion, drop the derivation -- mechanism, counts and "
          "log excerpts belong in the review's Testing Done, not here."
    )
    return 0


def _selftest():
    bad = 0

    def check(label, got, want):
        nonlocal bad
        if got != want:
            print(f"FAIL {label}: {got!r} != {want!r}")
            bad += 1

    check("limit tiny", limit_for(1), 3)
    check("limit 20", limit_for(20), 3)
    check("limit 21", limit_for(21), 4)
    check("limit 500", limit_for(500), 6)
    check("limit huge", limit_for(50000), 7)

    msg = ("TICKET-1 Subject line\n\nOne body line.\nAnother.\n\n"
           "Testing: ran it\nJIRA: TICKET-1\n"
           "Co-Authored-By: Someone <x@y>\n")
    check("body excludes trailers", len(body_lines(msg)), 2)
    check("subject not counted", body_lines(msg)[0], "One body line.")

    # A pasted invocation and its output is kept at whatever length the command
    # is, so only the prose around it counts.
    transcript = ("TICKET-1 Subject line\n\nProse before.\n\n"
                  "  $ some-tool --action thing \\\n"
                  "        --flag value\n"
                  "  some-tool: nothing written\n\n"
                  "Prose after.\n\nTesting: ran it\n")
    check("indented block excluded", len(body_lines(transcript)), 2)

    check("-m parsed", message_from_command('git commit -m "S" -m "B"', "."),
          "S\n\nB")
    check("-mS glued", message_from_command('git commit -mSubject', "."),
          "Subject")
    check("--message=", message_from_command('git commit --message=S', "."), "S")
    check("editor commit unseen", message_from_command("git commit", "."), None)
    check("amend no-edit unseen",
          message_from_command("git commit --amend --no-edit", "."), None)

    # Every -F spelling git takes. --file= and glued -F once read as no message at all,
    # so an over-long body committed that way was never measured.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "m.txt"), "w") as fh:
            fh.write("S\n\nbody\n")
        for form in ("-F m.txt", "--file m.txt", "--file=m.txt", "-Fm.txt"):
            check(f"{form} read", message_from_command(f"git commit {form}", tmp),
                  "S\n\nbody\n")

    # `-a` commits tracked files that were never staged, so counting only the
    # index understates the change -- and the budget with it. A big unstaged
    # edit beside a small staged one judged a 35-line commit at the 5-line
    # budget. Fixture: 5 staged lines, 30 unstaged tracked lines.
    with tempfile.TemporaryDirectory() as tmp:
        def git(*args):
            subprocess.run(["git"] + list(args), cwd=tmp, capture_output=True)
        git("init", "-q", ".")
        git("config", "user.email", "t@example.com")
        git("config", "user.name", "T")
        for name in ("staged.txt", "unstaged.txt"):
            with open(os.path.join(tmp, name), "w") as fh:
                fh.write("\n".join(str(n) for n in range(1, 11)) + "\n")
        git("add", "-A")
        git("commit", "-qm", "base")
        with open(os.path.join(tmp, "staged.txt"), "a") as fh:
            fh.write("\n".join(str(n) for n in range(11, 16)) + "\n")
        git("add", "staged.txt")
        with open(os.path.join(tmp, "unstaged.txt"), "a") as fh:
            fh.write("\n".join(str(n) for n in range(11, 41)) + "\n")

        def size(command):
            got = gather(command + ' -m "S\n\nbody"', tmp)
            return got[1] if got else None

        check("plain commit counts index", size("git commit"), 5)
        check("-a adds unstaged", size("git commit -a"), 35)
        check("-am adds unstaged", size("git commit -am"), 35)
        check("--all adds unstaged", size("git commit --all"), 35)
        # A bare `-m` is not `-a`: the letter has to be a real short flag.
        check("-m alone is not -a", size("git commit"), 5)

    check("rev found", revision_in("post-review c7ad8c929c2a"), "c7ad8c929c2a")
    check("HEAD found", revision_in("post-review HEAD"), "HEAD")
    check("no rev", revision_in("post-review"), None)

    print("all cases pass" if not bad else f"{bad} failure(s)")
    return 1 if bad else 0


def main():
    if "--test" in sys.argv[1:]:
        return _selftest()
    try:
        return decide()
    except Exception:
        return 0


if __name__ == "__main__":
    sys.exit(main())
