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
import shlex
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from hook_triggers import MARKER, acknowledged, trigger_match, triggered  # noqa: E402

TOOL = os.path.expanduser("~/.claude/tools/comment-ratio.py")

# How far past the surrounding file's own comment density an added change may go.
# Calibrated against four commits whose reviewer outcome is known, rather than
# picked: it fails the two a reviewer objected to (5.6x and 2.7x) and passes the
# trimmed rewording that same reviewer supplied (2.1x). Tighten it and the gate
# starts refusing accepted work, which is how a gate gets disabled.
MAX_MULTIPLE = "2.5"

# The multiple is relative, so a comment-dense file licenses a comment-dense
# change: at a 0.35 baseline, 2.5x permits 87% comments. This is the ceiling no
# baseline excuses.
MAX_RATIO = 0.45

# ...but only once the change is big enough for a ratio to mean anything. A
# 5-line fix carrying 7 lines of reason is 58% comments and entirely correct.
MIN_RATED_LINES = 40

# The tool's totals row: FILE ADDED CODE CMNT RATIO BASELINE.
TOTAL_ROW = re.compile(
    r"^TOTAL\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)%", re.MULTILINE)


def ratio_over_ceiling(report):
    """(over, code, comment) for the absolute cap, or None if unmeasurable.

    Read from the report the tool already produced rather than from a second
    invocation: the gate runs under a 30s hook timeout and the tool walks git
    history, so one run is the budget. An unparseable report returns None and
    the cap simply does not apply -- this is a style gate, and failing open on
    a format change beats blocking real work.
    """
    row = TOTAL_ROW.search(report)
    if not row:
        return None
    code, comment = int(row.group(2)), int(row.group(3))
    measured = code + comment
    if measured < MIN_RATED_LINES:
        return (False, code, comment)
    return (comment / measured > MAX_RATIO, code, comment)

HEAVY_BLOCK = re.compile(
    r"^\s+(\S+:\d+)\s+(\d+) comment lines over (\d+) of code", re.MULTILINE)


def explain(report):
    """(headline, advice) naming which of the tool's checks actually refused.

    Two gates share one exit code, so the failures arrive identical, and a
    generic message sends you trimming comments that were never the problem.

    The gate hands the tool only --max-block and --max-multiple, and the ratio
    path cannot refuse without printing HEAVY. So a refusal that is not HEAVY is
    the block check, with certainty and without a second run.
    """
    if "Verdict: HEAVY" in report:
        return ("Blocked by the RATIO check: the added comments run past %sx the "
                "density of the code they land in." % MAX_MULTIPLE,
                "State the conclusion, not the derivation -- cut the sentences a "
                "reader would not act on, then re-run.")

    blocks = "".join("\n  %s  %s comment lines over %s of code" % b
                     for b in HEAVY_BLOCK.findall(report))
    return ("Blocked by the BLOCK check, not the ratio. The aggregate ratio is "
            "within the gate, so trimming comments elsewhere will not clear "
            "this. It is these blocks alone:" + (blocks or " (see the list below)"),
            "Shorten the block, or restructure so it is not introduced here at "
            "all -- a block is also flagged when existing lines are merely "
            "re-indented into a new scope, which no rewording fixes.")


def commits_all(command):
    """Does this `git commit` stage tracked files itself, via -a/--all?

    Only the segment after `git commit` counts: `git add -A && git commit` puts
    an unrelated -A earlier in the same line. Short flags bundle, so -am is -a.
    A heredoc message holding an apostrophe makes shlex raise, same as below.
    """
    m = re.search(r"\bgit\s+commit(?![\w-])", command)
    if not m:
        return False
    scope = command[m.end():].split(";")[0].split("|")[0].split("&")[0]
    try:
        tokens = shlex.split(scope)
    except ValueError:
        tokens = scope.split()
    for tok in tokens:
        if tok == "--all":
            return True
        if tok.startswith("-") and not tok.startswith("--") and "a" in tok[1:]:
            return True
    return False


def target_for(command):
    """What to measure: an explicit revision if the command names one, else staged.

    A post names the commit it sends, and that whole commit is what a reviewer
    reads -- measuring only what is staged would miss everything already
    committed. A plain `git commit` has no commit yet, so the staged diff is
    both the best and the only answer.

    `git commit -a` is the exception, and it silently defeated this gate: -a
    stages at commit time, so nothing is staged while the hook runs and the
    staged diff is empty. Measure the working tree, which is what -a commits.
    """
    if re.search(r"\bgit\s+commit(?![\w-])", command):
        return ["--worktree"] if commits_all(command) else ["--staged"]

    # Read the revision out of the post itself, not the whole command line. A
    # compound that merely mentions a revision earlier -- an `echo` naming HEAD,
    # say -- otherwise measures whatever it mentioned rather than the commit
    # actually being sent, and blocks on the wrong change.
    m = trigger_match(command)
    scope = command[m.end():].split(";")[0].split("|")[0].split("&")[0] if m else command

    # A 7+ hex word is a revision; anything shorter collides with ordinary words
    # ("deadbeef" is fine, "add" is not). HEAD is spelled out separately.
    try:
        tokens = shlex.split(scope)
    except ValueError:
        tokens = scope.split()
    for tok in tokens:
        if tok.startswith("-"):
            continue
        if re.fullmatch(r"HEAD|[0-9a-f]{7,40}", tok):
            return [tok]
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

    ceiling = ratio_over_ceiling(report)
    over_ceiling = bool(ceiling and ceiling[0])
    if not failed and not over_ceiling:
        return 0

    if failed:
        headline, advice = explain(report)
    else:
        headline, advice = ("", "")

    extra = ""
    if over_ceiling:
        _, code, comment = ceiling
        extra = (f"\n\nBlocked by the absolute CEILING: {comment} comment lines "
                 f"to {code} of code is past {MAX_RATIO:.0%}, which no baseline "
                 f"excuses. The file being comment-dense is not a licence to "
                 f"add more.")
        if not failed:
            headline = "Blocked by the absolute ceiling, not by the tool's own checks."
            advice = ("State the conclusion, not the derivation -- cut the "
                      "sentences a reader would not act on, then re-run.")

    emit_deny(f"{headline}\n\n{report}{extra}\n\n{advice}")
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
        # -a stages at commit time, so nothing is staged when the hook runs.
        ("git commit -a -m x", ["--worktree"]),
        ("git commit -am x", ["--worktree"]),
        ("git commit --all -m x", ["--worktree"]),
        ("git commit --amend -a --no-edit", ["--worktree"]),
        # -A belongs to the add, not the commit, and --amend is not --all.
        ("git add -A && git commit -m x", ["--staged"]),
        ("git commit --amend --no-edit", ["--staged"]),
        # An apostrophe in a heredoc body makes shlex raise; the fallback split
        # still sees -a as its own token.
        ("git commit -a -F - <<'MSG'\nthe parser's CPU\nMSG", ["--worktree"]),
        # The revision named by the post wins over one mentioned earlier in a
        # compound, and over a later segment.
        ('echo "HEAD=x"; post-review c7ad8c929c2a', ["c7ad8c929c2a"]),
        ("post-review c7ad8c929c2a | tail -20", ["c7ad8c929c2a"]),
        ("post-review c7ad8c929c2a; echo HEAD", ["c7ad8c929c2a"]),
        ("post-review --depends-on 1234 c7ad8c929c2a", ["c7ad8c929c2a"]),
    ]
    # The real post trigger names an employer's tooling and lives in the
    # untracked trigger file, so stand a neutral one in for the duration.
    import hook_triggers
    real_load = hook_triggers.load_triggers
    hook_triggers.load_triggers = lambda: [hook_triggers.GIT_COMMIT, r"\bpost-review\b"]
    try:
        for command, want in targets:
            got = target_for(command)
            if got != want:
                print(f"FAIL target_for({command!r}) = {got}, want {want}")
                bad += 1
    finally:
        hook_triggers.load_triggers = real_load

    def row(added, code, comment, ratio, baseline="33.6%"):
        return (f"FILE   ADDED  CODE  CMNT   RATIO  BASELINE\n"
                f"TOTAL  {added}  {code}  {comment}  {ratio}  {baseline}\n"
                f"Verdict: HEAVY")

    ceilings = [
        # Under the floor: a small fix carrying its reason is not a ratio
        # problem, whatever the percentage says. This is 725d3e0.
        (row(13, 5, 7, "58.3%"), False),
        # Over the floor and over the ceiling -- the case the multiple misses,
        # because a 0.35-baseline file makes 2.5x permit 87%.
        (row(120, 20, 80, "80.0%"), True),
        # Over the floor, under the ceiling: the densest accepted work measured.
        (row(110, 55, 45, "45.0%"), False),
        # Exactly at the floor, just over the ceiling.
        (row(45, 17, 23, "57.5%"), True),
        # No totals row: the cap cannot apply, and must not guess.
        ("Verdict: HEAVY -- no table here", None),
    ]
    for report, want in ceilings:
        got = ratio_over_ceiling(report)
        got = None if got is None else got[0]
        if got != want:
            print(f"FAIL ratio_over_ceiling(...) = {got}, want {want}")
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
