"""Shared trigger matching for the pre-commit style gates.

Both gates fire on the same moment -- a change being committed, or posted for
someone to read -- so the list of commands that count lives here rather than
being copied into each. `git commit` is universal and built in; anything else
names a particular employer's review tooling and belongs in the sibling
`comment-ratio-triggers`, which is not published.
"""

import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))
TRIGGER_FILE = os.path.join(_HERE, "comment-ratio-triggers")

# Release valve, not a workflow. Both gates measure the command text, so a
# command that merely quotes a trigger -- testing a gate, grepping history --
# would otherwise be refused with no way through. Neither gate names it when it
# refuses: the answer to a refusal is to cut the writing.
MARKER = "COMMENT_RATIO_OK"

# The lookahead excludes a hyphen as well as a word character, or
# `git commit-tree` matches -- \b sees the hyphen as a boundary, which is the
# opposite of what is wanted here.
GIT_COMMIT = r"\bgit\s+commit(?![\w-])"

BASE_TRIGGERS = [GIT_COMMIT]


def load_triggers():
    """Base triggers plus the site-specific file, if it exists."""
    patterns = list(BASE_TRIGGERS)
    try:
        with open(TRIGGER_FILE) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except OSError:
        pass
    return patterns


def trigger_match(command):
    """The match object of the first trigger that fires, or None.

    Callers need where it matched, not just whether: the revision a post names
    follows the trigger, and reading one from anywhere in the command measures
    whatever a compound happened to mention first.
    """
    for pat in load_triggers():
        try:
            m = re.search(pat, command)
        except re.error:
            continue
        if m:
            return m
    return None


def triggered(command):
    return trigger_match(command) is not None


def acknowledged(command):
    return MARKER in command
