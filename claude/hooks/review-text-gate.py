#!/usr/bin/env python3
"""PreToolUse gate for Bash: keep a standalone `--` out of review-tool text.

A dash pair standing in for an em dash reads as machine-written, and a review
comment is the one place that costs something: it is addressed to a colleague,
under a person's name. Rewrite it as a comma, a colon, a semicolon, or two
sentences -- whichever the clause actually wanted.

Only text bound for a review tool is checked, and only the VALUES of the fields
that carry prose. Flags are left alone: `--data-urlencode` is itself a dash pair,
and a quoted build or test invocation inside a Testing Done field is a command
someone must be able to paste. So a dash pair is only refused when it stands
alone as a word, which is exactly the em-dash use and never a flag.

Code comments are out of scope on purpose. This is about what a colleague reads.

Fails OPEN, like its siblings: an unparseable command or an unreadable payload
file allows the command.

Self-test:  ./review-text-gate.py --test
"""

import json
import os
import re
import shlex
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from hook_triggers import acknowledged  # noqa: E402

# Review Board's own API vocabulary, not any one deployment's. A command has to
# carry one of these before its fields are read, so an unrelated `text=` post
# somewhere else is not this gate's business.
REVIEW_SIGNALS = ("reply_to_id", "review-requests", "review_request",
                  "diff-comments", "general-comments")

# Fields that carry prose a person reads. `summary` is the review title;
# body_top/body_bottom are the covering text of a review.
PROSE_FIELDS = {"text", "description", "testing_done", "summary",
                "body_top", "body_bottom", "changedescription"}

# A dash pair standing as its own word. `--flag`, `x--y` and a `----` rule are
# all left alone; only the em-dash use matches. The real character is caught
# too, since it reads the same way.
DASH = re.compile(r"(?:(?<=\s)|\A)--(?:(?=\s)|\Z)|—")


def payload_values(command, cwd):
    """[(field, value)] for prose fields this command would send."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return None

    out, i = [], 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("--data-urlencode", "--data", "--data-raw", "-d") \
                and i + 1 < len(argv):
            arg = argv[i + 1]
            i += 2
        elif tok.startswith("--data-urlencode=") or tok.startswith("--data="):
            arg = tok.split("=", 1)[1]
            i += 1
        else:
            i += 1
            continue

        if "=" not in arg:
            continue
        field, value = arg.split("=", 1)
        field = field.strip().lower()
        if field not in PROSE_FIELDS:
            continue
        # `field@path` sends the file's contents, so that is what to read.
        if value.startswith("@"):
            try:
                with open(os.path.join(cwd, value[1:])) as fh:
                    value = fh.read()
            except OSError:
                continue
        out.append((field, value))
    return out


def offending(values):
    hits = []
    for field, value in values:
        for line in value.splitlines():
            if DASH.search(line):
                hits.append((field, line.strip()))
    return hits


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
    if not command.strip() or acknowledged(command):
        return 0
    if not any(sig in command for sig in REVIEW_SIGNALS):
        return 0

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    values = payload_values(command, cwd)
    if not values:
        return 0
    hits = offending(values)
    if not hits:
        return 0

    shown = "\n".join(f"  [{field}] {line}" for field, line in hits[:8])
    more = f"\n  ... and {len(hits) - 8} more" if len(hits) > 8 else ""
    emit_deny(
        "A standalone `--` reads as machine-written, and this text is going to "
        "a reviewer:\n\n" + shown + more +
        "\n\nRewrite each as a comma, a colon, a semicolon, or two sentences."
    )
    return 0


def _selftest():
    bad = 0

    def check(label, got, want):
        nonlocal bad
        if got != want:
            print(f"FAIL {label}: {got!r} != {want!r}")
            bad += 1

    d = lambda s: bool(DASH.search(s))  # noqa: E731
    check("em dash use", d("done -- see below"), True)
    check("em dash at start", d("-- see below"), True)
    check("em dash at end", d("see below --"), True)
    check("real em dash", d("done — see below"), True)
    check("long flag", d("make --jobs 4"), False)
    check("flag at start", d("--amend keeps the message"), False)
    check("hyphenated word", d("a well-known case"), False)
    check("double hyphen in word", d("x--y"), False)
    check("horizontal rule", d("----"), False)
    check("plain text", d("nothing here"), False)

    cmd = ('curl -X POST url --data-urlencode "reply_to_id=1" '
           '--data-urlencode "text=Done -- fixed."')
    vals = payload_values(cmd, ".")
    check("text extracted", vals, [("text", "Done -- fixed.")])
    check("offending found", len(offending(vals)), 1)

    clean = ('curl -X POST url --data-urlencode "reply_to_id=1" '
             '--data-urlencode "text=Done. Ran make --jobs 4."')
    check("flag in prose is fine", offending(payload_values(clean, ".")), [])

    skip = 'curl -X POST url --data-urlencode "note=Done -- fixed."'
    check("non-prose field ignored", payload_values(skip, "."), [])

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
