#!/usr/bin/env python3
"""PreToolUse gate for Bash: refuse a commit or review post that is comment-heavy.

Standing instruction is to match a change's comment density to the code it lands
in, and there is a tool that measures it. The failure this exists to stop is not
disagreeing with that instruction -- it is never running the tool, then finding
out from a reviewer.

So the check is bound to the action instead of to attention. Commands that put
comments in front of someone else -- committing, posting for review -- are
measured first, and refused when the added comments run well past the density of
the file they land in.

Refusing, not warning: a warning that can be ignored is the state we already had.
The answer to a refusal is to cut the comment, not to look for a way past it.

Fails OPEN. This is a style gate, not a safety one: anything unexpected (no
tool, no repo, a crash) allows the command. Blocking real work over a broken
style check would be a worse bug than the one it prevents.

Triggers: `git commit` always. Anything else -- a site's own review-posting
command -- goes in the sibling `comment-ratio-triggers`, one extended regex per
line, which is deliberately not published.

Self-test:  ./comment-ratio-gate.py --test
"""

import json
import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from hook_triggers import MARKER, acknowledged, triggered  # noqa: E402

TOOL = os.path.expanduser("~/.claude/tools/comment-ratio.py")

# How far past the surrounding file's own comment density an added change may go.
# Calibrated against four commits whose reviewer outcome is known, rather than
# picked: it fails the two a reviewer objected to (5.6x and 2.7x) and passes the
# trimmed rewording that same reviewer supplied (2.1x). Tighten it and the gate
# starts refusing accepted work, which is how a gate gets disabled.
MAX_MULTIPLE = "2.5"

def target_for(command):
    """What to measure: an explicit revision if the command names one, else staged.

    A post names the commit it sends, and that whole commit is what a reviewer
    reads -- measuring only what is staged would miss everything already
    committed. A plain `git commit` has no commit yet, so the staged diff is
    both the best and the only answer.
    """
    # A 7+ hex word is a revision; anything shorter collides with ordinary words
    # ("deadbeef" is fine, "add" is not). HEAD is spelled out separately.
    m = re.search(r"\b(HEAD|[0-9a-f]{7,40})\b", command)
    if m and not re.search(r"\bgit\s+commit\b", command):
        return [m.group(1)]
    return ["--staged"]


def run_tool(target, cwd):
    """Returns (failed, report) or None when there is nothing to judge.

    A non-zero exit means the gate tripped ONLY if the tool actually produced a
    verdict. It exits non-zero for its own errors too -- an unknown revision,
    say -- and reporting one of those as a density failure would block a command
    over a broken check, which is exactly the direction this must not fail.
    """
    argv = [TOOL] + target + ["--max-block", "--max-multiple", MAX_MULTIPLE]
    proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=25)
    out = (proc.stdout or "") + (proc.stderr or "")
    if "Verdict:" not in out:
        return None
    return (proc.returncode != 0, out.strip())


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
    if not command.strip():
        return 0
    if acknowledged(command):
        return 0
    if not triggered(command):
        return 0
    if not os.path.exists(TOOL):
        return 0

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    inside = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"],
                            cwd=cwd, capture_output=True, text=True)
    if inside.returncode != 0:
        return 0

    result = run_tool(target_for(command), cwd)
    if result is None:
        return 0
    failed, report = result
    if not failed:
        return 0

    emit_deny(
        "Comment density is over the gate for this change:\n\n"
        f"{report}\n\n"
        "State the conclusion, not the derivation -- cut the sentences a reader "
        "would not act on, then re-run."
    )
    return 0


def _selftest():
    cases = [
        ("git commit -m x", True),
        ("git add f && git commit --amend --no-edit", True),
        ("git commit-tree abc", False),
        ("git status", False),
        ("echo 'git commit' > /tmp/note", True),   # over-trigger: fails open anyway
        (f"{MARKER}=1 git commit -m x", False),    # marker checked before triggers
        ("ls", False),
    ]
    bad = 0
    for command, want in cases:
        got = (MARKER not in command) and triggered(command)
        if got != want:
            print(f"FAIL trigger({command!r}) = {got}, want {want}")
            bad += 1

    targets = [
        ("git commit -m x", ["--staged"]),
        ("post-review c7ad8c929c2a", ["c7ad8c929c2a"]),
        ("post-review HEAD", ["HEAD"]),
        ("post-review", ["--staged"]),
        ("git add f && git commit --amend", ["--staged"]),
    ]
    for command, want in targets:
        got = target_for(command)
        if got != want:
            print(f"FAIL target_for({command!r}) = {got}, want {want}")
            bad += 1

    print("all cases pass" if not bad else f"{bad} failure(s)")
    return 1 if bad else 0


def main():
    if "--test" in sys.argv[1:]:
        return _selftest()
    try:
        return decide()
    except Exception:
        # Fails open on purpose -- see the module docstring. Nothing is printed:
        # a style gate that cannot run should be invisible, not noisy.
        return 0


if __name__ == "__main__":
    sys.exit(main())
