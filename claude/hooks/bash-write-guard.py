#!/usr/bin/env python3
"""PreToolUse guard for Bash: prompt on writes, clear safe read-only compounds.

Two jobs, both narrow:

1. The Bash(...) allow rules are literal prefix matches, so they cannot tell
   `sed -n` from `sed -i`, nor `cat f` from `cat f > g`. Write-capable forms are
   returned as permissionDecision "ask" so they drop back to a prompt.

2. Shell control flow (`for`, `if`) has no command name to allowlist, so such
   commands always prompt however read-only they are. When every command that
   could execute is verified read-only AND already allowlisted, the compound is
   returned as "allow".

The hook stays SILENT on anything it does not fully understand, so unrecognized
input falls through to the normal permission flow. It never guesses toward
"allow": that decision requires understanding every command position.

Nothing here is specific to a machine, employer, or toolchain. Grants that are
belong in a sibling `local_grants.py` -- see load_local_grants().

Self-test:  python3 bash-write-guard.py --test
"""

import json
import os
import re
import shlex
import sys

HOME = os.path.expanduser("~")
_HERE = os.path.dirname(os.path.abspath(__file__))
ALLOWLIST_FILE = os.path.join(_HERE, "unguarded-worktrees")

OPERATORS = {"&&", "||", "|", ";", "&", "|&", "(", ")"}
REDIRECTS = {">", ">>", ">|", ">&", "&>", "&>>"}

# Redirect targets that don't actually write a file. `2>/dev/null` discards
# stderr and `2>&1` just duplicates a descriptor -- both are read-only idioms.
DEV_SINKS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd"}

FIND_WRITE_FLAGS = {
    "-exec", "-execdir", "-delete", "-ok", "-okdir",
    "-fprintf", "-fls", "-fprint", "-fprint0",
}
# sed short flags bundle, and -i takes an optional suffix: -i -i.bak -ni -sni
SED_INPLACE = re.compile(r"^-[A-Za-z]*i|^--in-place")
# sort writes in place with -o/--output: sort -o f, sort -of, sort --output=f
SORT_OUTPUT = re.compile(r"^-o.*|^--output(=|$)")

# awk is a language, not a filter: it can redirect and shell out from inside
# the program text, where shlex has already stripped the quotes that hid it.
AWK_LIKE = {"awk", "gawk", "mawk", "nawk"}
AWK_WRITE = re.compile(r"system\s*\(|\bprintf?\s*>|>\s*[\"']|\|\s*[\"']")

# `git branch` is read-only except for the flags that delete or rename.
GIT_BRANCH_DESTRUCTIVE = {"-d", "-D", "--delete", "-m", "-M", "--move"}
# The diff machinery behind log/show/diff/format-patch can write its output to
# a file, so an allowlisted `git diff` is not unconditionally read-only.
GIT_OUTPUT_FLAG = re.compile(r"^--output(=|$)")

# Commands that write, delete, or change metadata whatever flags they are given.
# None of these are allowlisted, so they already prompt; naming them here is
# defence in depth and buys three things. The prompt carries an explicit reason
# instead of a bare "no rule matched". They keep prompting if a broad rule is
# ever added. And -- the real one -- a reason here makes the hook emit "ask",
# which stops a compound from being granted just because every *other* command
# in it happens to be read-only.
ALWAYS_ASK = {
    # -- explicit writers -------------------------------------------------
    "tee": "writes to a file",
    "dd": "writes blocks directly",
    "truncate": "resizes files",
    "shred": "overwrites files",
    "split": "writes output files",
    # -- deletion and relocation ------------------------------------------
    "rm": "deletes files",
    "rmdir": "removes directories",
    "mv": "moves files, overwriting the destination",
    "cp": "copies over the destination",
    "rsync": "copies files and can delete at the destination",
    "install": "copies files and sets their permissions",
    # -- creation and metadata --------------------------------------------
    "mkdir": "creates directories",
    "touch": "creates files and rewrites timestamps",
    "ln": "creates links",
    "mkfifo": "creates a filesystem object",
    "mktemp": "creates files",
    "chmod": "changes permissions",
    "chown": "changes ownership",
    "chgrp": "changes group ownership",
    # -- in-place rewriters -----------------------------------------------
    "patch": "edits files in place",
    "tar": "extracts over existing files",
    "unzip": "extracts over existing files",
    "gzip": "replaces the file with a compressed one",
    "gunzip": "replaces the file with an uncompressed one",
    "zstd": "replaces the file with a compressed one",
    # -- editors: interactive, and they write ------------------------------
    "ed": "is an editor", "ex": "is an editor", "vi": "is an editor",
    "vim": "is an editor", "nano": "is an editor", "emacs": "is an editor",
    # -- interpreters: the broadest write vector there is -------------------
    # Deliberately here rather than in REFUSED_WORDS. A refused word only makes
    # the guard fall silent, which defers to the rules; "ask" is stronger.
    "python": "runs arbitrary code", "python3": "runs arbitrary code",
    "perl": "runs arbitrary code", "ruby": "runs arbitrary code",
    "node": "runs arbitrary code", "php": "runs arbitrary code",
    "sh": "runs arbitrary code", "bash": "runs arbitrary code",
    "zsh": "runs arbitrary code", "ksh": "runs arbitrary code",
}

# ---------------------------------------------------------------------------
# Control-flow recognition
# ---------------------------------------------------------------------------

# Keywords that introduce a command position after them.
CONTROL_KEYWORDS = {"do", "then", "elif", "else", "if", "fi", "done"}

# Anything here means we refuse to reason about the command at all. Either it
# rewrites the execution environment (eval, export), or it is a construct
# outside the recognized subset (while, case), or it hides a command position.
REFUSED_WORDS = {
    "eval", "exec", "source", ".", "trap", "alias", "unalias", "command",
    "while", "until", "case", "esac", "select", "function", "coproc",
    "export", "declare", "typeset", "local", "set", "unset", "shift",
    "read", "mapfile", "readarray", "xargs", "env", "nohup", "sudo", "time",
}

GLOB_CHARS = "*?["


def substitutions(command):
    """Find $(...), `...`, <(...) the shell would actually expand.

    Single-quoted occurrences are literal text and are ignored.
    """
    found, index, quote = [], 0, None
    while index < len(command):
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = None
        elif quote == '"':
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quote = None
            elif command.startswith("$(", index):
                found.append("$(...)")
            elif char == "`":
                found.append("`...`")
        else:
            if char in "'\"":
                quote = char
            elif command.startswith("$(", index):
                found.append("$(...)")
            elif command.startswith("<(", index) or command.startswith(">(", index):
                found.append("<(...) process substitution")
            elif char == "`":
                found.append("`...`")
        index += 1
    return list(dict.fromkeys(found))


def tokenize(command):
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    # shlex treats '#' as starting a comment ANYWHERE, discarding the rest of
    # the input. The shell only does that at a word boundary, so `${v##pat}`
    # and `a#b` would be truncated -- and a truncated command could be verified
    # as safe while the shell still runs the part that was cut off. Disabling
    # comments makes any trailing '#' an ordinary word instead, which at worst
    # makes us verify more than the shell runs. That is the safe direction.
    lexer.commenters = ""
    return list(lexer)


def split_segments(tokens):
    """Split a token list on shell control operators."""
    segments, current = [], []
    for token in tokens:
        if token in OPERATORS:
            if current:
                segments.append(current)
            current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def strip_leading_keywords(segment):
    """Drop `do` / `then` / `else` etc. from the front of a segment.

    Splitting on operators alone leaves the keyword sitting where the command
    name should be, so `for f in a; do rm "$f"; done` yields `['do','rm','$f']`
    and argv0_of reports `do` -- hiding the `rm` from every write check.

    Only LEADING keywords go: one used as an argument must still be scanned, or
    `find . -name done -delete` would lose its `-delete`.
    """
    index = 0
    while index < len(segment) and segment[index] in CONTROL_KEYWORDS:
        index += 1
    return segment[index:]


def redirects_to_file(segment):
    """True only if a redirect names a real destination file."""
    for index, token in enumerate(segment):
        if token not in REDIRECTS:
            continue
        target = segment[index + 1] if index + 1 < len(segment) else ""
        if not target or target.isdigit():
            continue  # 2>&1 -- descriptor duplication, writes nothing
        if target in DEV_SINKS or target.startswith("/dev/fd/"):
            continue  # 2>/dev/null -- discarded, not written
        return True
    return False


def argv0_of(segment):
    """First real command word, skipping leading VAR=value assignments."""
    for index, token in enumerate(segment):
        if "=" in token and not token.startswith("-") and index == 0:
            continue
        if token.startswith("-"):
            continue
        return token.rsplit("/", 1)[-1], segment[index + 1:]
    return None, []


def segment_reasons(segment):
    """Write-capability reasons for one simple command."""
    segment = strip_leading_keywords(segment)
    if not segment:
        return []
    reasons = []
    if redirects_to_file(segment):
        reasons.append("redirects output to a file")

    name, rest = argv0_of(segment)
    if name is None:
        return reasons

    if name in ALWAYS_ASK:
        reasons.append(f"{name} {ALWAYS_ASK[name]}")

    if name == "sed" and any(SED_INPLACE.match(t) for t in rest):
        reasons.append("sed edits files in place")

    if name == "find":
        hit = sorted(FIND_WRITE_FLAGS.intersection(rest))
        if hit:
            reasons.append(f"find {' '.join(hit)} runs commands or deletes")

    if name == "sort" and any(SORT_OUTPUT.match(t) for t in rest):
        reasons.append("sort -o writes to a file")

    if name in AWK_LIKE:
        if any(AWK_WRITE.search(t) for t in rest):
            reasons.append("awk program redirects or shells out")
        # -f reads the program from a file this hook never opens, so its
        # redirects and system() calls are invisible to the check above.
        elif any(t == "-f" or t.startswith("--file") or
                 (t.startswith("-f") and len(t) > 2) for t in rest):
            reasons.append("awk -f runs a program file the guard cannot inspect")

    if name == "git":
        if rest[:1] == ["branch"]:
            hit = sorted(GIT_BRANCH_DESTRUCTIVE.intersection(rest[1:]))
            if hit:
                reasons.append(
                    f"git branch {' '.join(hit)} deletes or renames a branch")
        if any(GIT_OUTPUT_FLAG.match(token) for token in rest):
            reasons.append("git --output writes its output to a file")

    return reasons


def _flat_reasons(text):
    """Write reasons for text with no unexpanded $(...) left in it."""
    try:
        tokens = tokenize(text)
    except ValueError:
        # Unbalanced quotes and friends. Don't guess -- fall through to the
        # normal prompt rather than allowing or blocking on a bad parse.
        return ["command could not be parsed"]

    reasons = []
    for segment in split_segments(tokens):
        reasons.extend(segment_reasons(segment))
    return reasons


def find_reasons(command, depth=0):
    """Write-capability reasons for a command, substitution-aware.

    Raw text cannot go straight to shlex, which has no concept of `$(...)`: a
    double quote nested inside a substitution closes the outer quote, and the
    rest of that word is then re-read as syntax. In
    `"$(grep -c "img->$f" f)"` the `->` becomes a bare `>` token and the whole
    command is reported as a file redirect that the shell would never perform.

    So do what the shell does: replace each substitution with a placeholder,
    check the outer command, and check each substitution's own text separately.
    A redirect *into* a substitution still shows up, because the placeholder
    lands in the redirect target position.
    """
    if depth > MAX_SUBST_DEPTH:
        return list(dict.fromkeys(_flat_reasons(command) + [
            "substitution nested deeper than the guard inspects"]))

    spans = substitution_spans(command)
    if spans is None:
        # An unquoted backtick, `<(...)`, an unclosed `$(`, or an unbalanced
        # quote. The embedded commands cannot be located, and shlex cannot find
        # them either: `echo `tee f`` tokenizes to three harmless-looking
        # words. Staying silent would fall through to the rules, which see only
        # the leading `echo` and clear it. Ask instead.
        return list(dict.fromkeys(_flat_reasons(command) + [
            "contains a construct the guard cannot inspect for writes "
            "(backticks, process substitution, or unbalanced quotes)"]))

    reasons = _flat_reasons(strip_substitutions(command, spans))
    for start, end in spans:
        reasons.extend(find_reasons(command[start + 2:end - 1], depth + 1))
    return list(dict.fromkeys(reasons))


def executable_commands(tokens):
    """Every command that could run, or (None, _) if outside the subset.

    Returns (commands, saw_control). A command position holding a variable, an
    unrecognized construct, or a refused word aborts with None -- the guard
    then says nothing rather than allowing something it cannot see through.
    """
    commands, current = [], []
    expect_command = True
    saw_control = False
    index, total = 0, len(tokens)

    while index < total:
        token = tokens[index]

        if token in ("(", ")", "{", "}"):
            return None, False
        if token in REFUSED_WORDS:
            return None, False

        # bash recognizes a reserved word only where a command name may start;
        # anywhere else it is an ordinary argument. Without this, `cat done`
        # splits into a `cat` with no arguments and gets granted on that basis,
        # and `grep -n for f` is refused for no reason.
        if token == "for" and expect_command:
            saw_control = True
            index += 1
            if index >= total or not tokens[index].isidentifier():
                return None, False
            index += 1
            if index >= total or tokens[index] != "in":
                return None, False
            index += 1
            # The word list is data, but must be literal: a variable or glob
            # makes the iteration set unknown.
            while index < total and tokens[index] not in ("do", ";"):
                word = tokens[index]
                if "$" in word or any(ch in word for ch in GLOB_CHARS):
                    return None, False
                index += 1
            if current:
                commands.append(current)
                current = []
            expect_command = True
            continue

        if token in CONTROL_KEYWORDS and expect_command:
            saw_control = True
            if current:
                commands.append(current)
                current = []
            expect_command = True
            index += 1
            continue

        if token in OPERATORS:
            if current:
                commands.append(current)
                current = []
            expect_command = True
            index += 1
            continue

        if expect_command:
            # `$cmd x` puts an unknown command in command position.
            if token.startswith("$") or token.startswith("-"):
                return None, False
            expect_command = False

        current.append(token)
        index += 1

    if current:
        commands.append(current)
    return commands, saw_control


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def settings_sources(cwd):
    return [
        ("user", os.path.join(HOME, ".claude", "settings.json")),
        ("project", os.path.join(cwd, ".claude", "settings.json")),
        ("local", os.path.join(cwd, ".claude", "settings.local.json")),
    ]


def collect_rules(cwd):
    """(prefix, exact, deny) Bash rules, each as a (pattern, source) list."""
    prefix, exact, deny = [], [], []
    for label, path in settings_sources(cwd):
        try:
            with open(path) as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        perms = data.get("permissions") or {}
        for rule in perms.get("allow") or []:
            if rule.startswith("Bash(") and rule.endswith(")"):
                body = rule[5:-1]
                (prefix if body.endswith(":*") else exact).append(
                    (body[:-2] if body.endswith(":*") else body, label))
        for rule in perms.get("deny") or []:
            if rule.startswith("Bash(") and rule.endswith(")"):
                body = rule[5:-1]
                deny.append((body[:-2] if body.endswith(":*") else body, label))
    return prefix, exact, deny


def workspace_roots(cwd):
    """Directories Bash may touch without prompting: cwd + additionalDirectories.

    Paths outside these prompt even when the command matches an allow rule --
    the rule governs the command, this governs what it may reach.
    """
    roots = [os.path.realpath(cwd)]
    for _, path in settings_sources(cwd):
        try:
            with open(path) as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        for entry in (data.get("permissions") or {}).get(
                "additionalDirectories") or []:
            roots.append(os.path.realpath(os.path.expanduser(entry)))
    return roots


def outside_workspace(segment, roots):
    """Path-looking arguments in this command that fall outside the roots.

    Only absolute and ~-rooted tokens are considered: a bare `runner.stdout` or
    `src/pkg/x` resolves under cwd anyway, and treating every token
    containing a slash as a path would flag sed scripts like `s/a/b/`.
    """
    found = []
    for token in segment:
        if not (token.startswith("/") or token.startswith("~")):
            continue
        if token.startswith("/dev/"):
            continue  # /dev/null and friends are not workspace paths
        resolved = os.path.realpath(os.path.expanduser(token))
        if not any(resolved == root or resolved.startswith(root + os.sep)
                   for root in roots):
            found.append(token)
    return found


def matches(text, rules):
    for pattern, source in rules:
        if text == pattern or text.startswith(pattern + " "):
            return pattern, source
    return None, None


def read_list(path):
    """Non-comment, non-blank lines from a plain list file."""
    try:
        with open(path) as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []
    return [e for e in (l.split("#", 1)[0].strip() for l in lines) if e]


class _GuardView:
    """Live read-only view of this module's globals, handed to local_grants.py.

    Passing the module object itself would mean looking it up in sys.modules,
    where importlib.util.module_from_spec never registers it -- so importing the
    guard by path (why-prompt.py does) would raise KeyError and silently drop
    every local grant. Reading globals() directly works under any import style.
    """

    def __getattr__(self, name):
        try:
            return globals()[name]
        except KeyError:
            raise AttributeError(name) from None


GUARD_VIEW = _GuardView()


def load_local_grants():
    """`extra_grant` from hooks/local_grants.py, or None if there isn't one.

    Site-specific grants live outside this file so the guard stays portable and
    can be published without leaking internal tool or project names. Any failure
    to load means no extra grants, which only costs a prompt.
    """
    path = os.path.join(_HERE, "local_grants.py")
    if not os.path.exists(path):
        return None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("claude_local_grants", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grant = getattr(module, "extra_grant", None)
        return grant if callable(grant) else None
    except Exception:
        return None


LOCAL_GRANT = load_local_grants()


def segment_permitted(segment, prefix, deny):
    """Is this one command cleared to run? (rule match, or a local grant)"""
    text = " ".join(segment)
    if matches(text, deny)[0]:
        return False, False
    if matches(text, prefix)[0]:
        return True, False
    if LOCAL_GRANT is not None:
        try:
            if LOCAL_GRANT(segment, GUARD_VIEW):
                return True, True
        except Exception:
            return False, False
    return False, False


SUBST_PLACEHOLDER = "__CLAUDE_SUBST__"
MAX_SUBST_DEPTH = 2


def substitution_spans(text):
    """(start, end) of each outermost $(...) the shell would expand.

    Returns None -- meaning refuse -- for anything outside the supported subset:
    backticks, <(...) process substitution, unbalanced quotes or parens. Every
    ambiguity resolves to None rather than to an empty list, so a command we
    cannot read confidently is declined instead of waved through.

    Escapes follow the shell: inside double quotes `\\$(...)` is a literal
    dollar and is correctly NOT reported as a substitution, while `\\\\$(...)`
    escapes the backslash and IS one.
    """
    spans, index, quote, depth, start = [], 0, None, 0, None
    while index < len(text):
        char = text[index]
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if quote == '"':
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quote = None
                index += 1
                continue
        elif char in ("'", '"'):
            quote = char
            index += 1
            continue

        if char == "`" or text.startswith("<(", index) or text.startswith(">(", index):
            return None
        if text.startswith("$(", index):
            if depth == 0:
                start = index
            depth += 1
            index += 2
            continue
        if char == ")" and depth:
            depth -= 1
            if depth == 0:
                spans.append((start, index + 1))
                start = None
        index += 1

    if depth or quote is not None:
        return None
    return spans


def strip_substitutions(text, spans):
    """Replace each span with a placeholder so the outer command tokenizes."""
    for start, end in reversed(spans):
        text = text[:start] + SUBST_PLACEHOLDER + text[end:]
    return text


def analyze(text, prefix, deny, depth):
    """(permitted, needs_grant) over every command position in `text`.

    Recurses into $(...), which introduces command positions no prefix rule
    ever sees. This is safe because the shell does not re-parse substitution
    output as syntax -- output becomes data, never operators or redirections --
    so a substitution's only new risk is the commands inside its parens.
    """
    if depth > MAX_SUBST_DEPTH:
        return False, False

    spans = substitution_spans(text)
    if spans is None:
        return False, False

    for start, end in spans:
        inner_ok, _ = analyze(text[start + 2:end - 1], prefix, deny, depth + 1)
        if not inner_ok:
            return False, False

    try:
        tokens = tokenize(strip_substitutions(text, spans))
    except ValueError:
        return False, False

    commands, saw_control = executable_commands(tokens)
    if commands is None:
        return False, False

    needs_grant = saw_control or bool(spans)
    for segment in commands:
        if not segment:
            continue
        # A substitution in command position would run whatever it printed.
        if SUBST_PLACEHOLDER in segment[0]:
            return False, False
        if segment_reasons(segment):
            return False, False
        permitted, was_pb = segment_permitted(segment, prefix, deny)
        if not permitted:
            return False, False
        needs_grant = needs_grant or was_pb
    return True, needs_grant


def grant_verdict(command, cwd):
    """True to actively allow this command, bypassing the prompt.

    Speaks only for what the prefix rules cannot express: shell control flow,
    `$(...)` substitution, and whatever local_grants.py adds. If every
    command is already rule-matched and none of those appear, returns False so
    the normal permission flow decides -- the hook is not a replacement for the
    rules.
    """
    prefix, _, deny = collect_rules(cwd)
    permitted, needs_grant = analyze(command, prefix, deny, 0)
    return permitted and needs_grant


# Kept for callers that predate grant_verdict.
safe_compound = grant_verdict


# ---------------------------------------------------------------------------
# Worktree allowlist
# ---------------------------------------------------------------------------

def checkout_root(start):
    """(root, is_linked_worktree) for the enclosing checkout, else (None, False).

    In a linked worktree .git is a file holding a gitdir: pointer; in a main
    checkout it is a directory.
    """
    path = os.path.abspath(start)
    while True:
        marker = os.path.join(path, ".git")
        if os.path.exists(marker):
            return path, os.path.isfile(marker)
        parent = os.path.dirname(path)
        if parent == path:
            return None, False
        path = parent


def allowlisted_roots():
    """Absolute paths from the allowlist file. Missing file means none."""
    try:
        with open(ALLOWLIST_FILE) as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []
    roots = []
    for line in lines:
        entry = line.split("#", 1)[0].strip()
        if entry:
            roots.append(os.path.realpath(os.path.expanduser(entry)))
    return roots


def guard_disabled():
    """Stand down only inside a worktree that was explicitly allowlisted.

    Requires BOTH an allowlist entry and an actual linked worktree, so a stray
    entry naming a main checkout cannot switch the guard off there.
    """
    start = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    root, is_linked = checkout_root(start)
    if root is None or not is_linked:
        return False
    root = os.path.realpath(root)
    return any(root == allowed or root.startswith(allowed + os.sep)
               for allowed in allowlisted_roots())


# ---------------------------------------------------------------------------
# Self-test:  python3 bash-write-guard.py --test
# ---------------------------------------------------------------------------

# A fixed rule set, so these expectations don't shift when settings.json gains
# or loses a rule. The point is to pin the guard's own logic, not the config.
_TEST_RULES = [(pattern, "test") for pattern in (
    "ls", "cat", "echo", "printf", "grep", "sed", "find", "sort", "awk",
    "head", "tail", "cut", "wc", "git log", "git branch", "git merge-base",
)]


def _verdict(command):
    """What the hook would emit for this command: ask / allow / silent."""
    if find_reasons(command):
        return "ask"
    permitted, needs_grant = analyze(command, _TEST_RULES, [], 0)
    return "allow" if permitted and needs_grant else "silent"


# "silent" means the hook says nothing and the normal permission flow decides.
# For anything write-capable or opaque that is a bug -- those must be "ask".
# For an un-allowlisted command like `rm` it is correct: the rules prompt.
_CASES = [
    # -- redirects ---------------------------------------------------------
    ("ask",    "echo hi > /tmp/f"),
    ("ask",    "echo hi >> /tmp/f"),
    ("ask",    "cat a > b"),
    ("ask",    "grep -n foo f > out"),
    ("ask",    "echo x > $(printf /tmp/f)"),      # placeholder as the target
    ("ask",    "echo hi; sed -i s/a/b/ f"),       # write in a later segment
    ("silent", "echo hi 2>/dev/null"),            # discarded, not written
    ("silent", "grep -n foo f 2>&1"),             # fd dup, writes nothing
    ("silent", 'sed -n 1,5p f; echo "2>/dev/null"'),   # quoted, inert

    # -- in-place / write flags on read-only-looking tools -----------------
    ("ask",    "sed -i s/a/b/ f"),
    ("ask",    "sed -i.bak s/a/b/ f"),
    ("ask",    "sed -ni s/a/b/ f"),
    ("ask",    "sed --in-place s/a/b/ f"),
    ("ask",    "find . -delete"),
    ("ask",    "find . -exec rm {} ;"),
    ("ask",    "sort -o out f"),
    ("ask",    "sort --output=out f"),
    ("ask",    "awk '{print > \"/tmp/f\"}' f"),
    ("ask",    "awk 'BEGIN{system(\"rm x\")}'"),
    ("ask",    "awk -f prog.awk f"),              # program file we can't read
    ("ask",    "awk -fprog.awk f"),
    ("ask",    "git branch -D feature/x"),
    ("ask",    "git branch -m a b"),
    ("ask",    "tee /tmp/f"),
    ("ask",    "dd if=a of=b"),
    ("ask",    "truncate -s 0 f"),
    ("ask",    "shred f"),
    ("silent", "sed -n 1,5p f"),
    ("silent", "find . -name '*.c'"),
    ("silent", "git branch --list"),

    # -- $(...) substitution ----------------------------------------------
    # A nested double quote inside $(...) used to close the OUTER quote, so
    # `->` surfaced as a bare `>` and the whole command read as a redirect.
    ("allow",  'echo "$(grep -c "a->b" f)"'),
    ("allow",  'printf "%s\\n" "$(grep -c "x<y\\|p->q" f)"'),
    ("allow",  'for f in a b; do printf "%s %s\\n" "$f" "$(grep -c "s->$f" g)"; done'),
    ("allow",  'sed -n "1,$(echo 5)p" f'),
    ("ask",    'echo "$(tee /tmp/f)"'),           # write inside the parens
    ("ask",    'echo "$(sed -i s/a/b/ f)"'),
    ("ask",    'echo "$(echo "$(dd of=/tmp/f)")"'),
    ("ask",    'printf "$(grep -c "a->b" f)" > /tmp/out'),
    ("silent", "$(echo ls) -la"),                 # substitution as the command

    # -- constructs the guard cannot see through must ASK, never go silent -
    ("ask",    "echo `tee /tmp/f`"),              # backticks hide the write
    ("ask",    "cat <(tee /tmp/f)"),
    ("ask",    'echo "unterminated'),
    ("ask",    'echo "$(echo "$(echo "$(echo hi)")")"'),   # past depth cap
    # ...but a backtick or paren that is only literal text stays silent.
    ("silent", "grep -n '`' f"),
    ("silent", "echo 'use `cmd` here'"),
    ("silent", 'grep -c "(" f'),
    ("silent", 'sed -n "/a(/,/b)/p" f'),
    ("silent", "awk '{print $1}' f"),

    # -- control flow ------------------------------------------------------
    ("allow",  'for f in a b; do echo "$f"; done'),
    ("allow",  "if git merge-base --is-ancestor a b; then echo y; else echo n; fi"),
    # shlex treats '#' as a comment anywhere and would discard the rest of the
    # line -- verifying a command shorter than the one bash actually runs. If
    # commenters="" is ever dropped this becomes "allow", not merely "silent".
    ("ask",    "for c in a; do echo hi#; rm -rf /tmp/poc; done"),
    ("silent", 'for f in *; do echo "$f"; done'),        # unknown iteration set
    ("silent", "while true; do echo x; done"),
    ("silent", "case $x in a) echo 1;; esac"),
    ("silent", "F=/tmp; ls $F"),                         # assignment (phase 2)
    ("silent", "export PATH=x; ls"),
    ("silent", "eval ls"),
    ("silent", "xargs rm"),
    ("silent", "sudo ls"),
    ("silent", "env FOO=1 ls"),
    ("silent", "( echo x )"),

    # -- ALWAYS_ASK: none of these are allowlisted, so they would prompt on
    # their own. The point is that one of them anywhere in a compound denies
    # the grant outright, rather than the grant resting on the other commands.
    ("ask",    "rm -rf /tmp/x"),
    ("ask",    'for f in a; do rm "$f"; done'),
    ("ask",    'for f in a b; do echo "$f"; rm "$f"; done'),
    ("ask",    "ls -la && rm x"),
    ("ask",    "mv a b"),
    ("ask",    "cp a b"),
    ("ask",    "mkdir -p /tmp/x"),
    ("ask",    "touch f"),
    ("ask",    "chmod 0755 f"),
    ("ask",    "ln -s a b"),
    ("ask",    "tar -xzf x.tar.gz"),
    ("ask",    "patch -p1 < d.patch"),
    ("ask",    "python3 -c 'print(1)'"),
    ("ask",    "bash -c 'echo hi'"),
    ("ask",    "/bin/rm -f x"),                   # matched on the basename
    ("ask",    'echo "$(rm -f x)"'),              # inside a substitution
    ("silent", "zstdgrep foo f.zst"),             # not `zstd`; still read-only

    # -- a command straight after do/then/else must still be scanned. It sits
    # where argv0 belongs, so the keyword used to be read as the command name.
    ("ask",    'for f in a; do sed -i s/x/y/ "$f"; done'),
    ("ask",    "for f in a; do tee /tmp/x; done"),
    ("ask",    "if [ -f x ]; then rm x; fi"),
    ("ask",    "if [ -f x ]; then echo y; else rm x; fi"),
    ("ask",    'for f in a; do find . -name "$f" -delete; done'),
    # ...but only LEADING keywords are stripped: as an argument it still scans.
    ("ask",    "find . -name done -delete"),
    ("silent", "cat done"),
    ("silent", "grep -n then f"),
    ("silent", "grep -n for f"),
    # REFUSED_WORDS stays deliberately blunt -- it is not gated on command
    # position, so the word anywhere means the guard declines to reason at all.
    ("silent", "grep -n while f"),

    # -- allowlisted git subcommands are not unconditionally read-only -----
    ("ask",    "git diff --output=/tmp/d HEAD~1"),
    ("ask",    "git log --output /tmp/l"),
    ("silent", "git diff --stat HEAD~1"),
    ("silent", "git log --oneline -3"),

    # -- plain commands: the rules decide, the hook keeps quiet ------------
    ("silent", "ls -la"),
    ("silent", "grep -n foo f | head -3"),
    ("silent", "cat f | wc -l"),
]

# Known gaps, asserted at their CURRENT behavior so they are written down
# rather than rediscovered. Each is a shape where a write-capable flag reaches
# an allowlisted tool through data the guard cannot read. Closing one makes the
# assertion below fail -- that is the reminder to move it into _CASES.
_GAPS = [
    # A loop word becomes a flag: `sed $f x` with f=-i edits in place. The word
    # list is checked for literalness, not for looking like a flag.
    ("allow",  "for f in -i; do sed $f x; done"),
    # A $(...) word list passes the "must be literal" check because the
    # placeholder substituted in contains no '$'.
    ("allow",  'for f in $(cat list); do sed $f x; done'),
]


def _selftest():
    # Pin the generic logic only: a local_grants.py, if present, would make
    # results depend on a file that is deliberately not portable.
    global LOCAL_GRANT
    had_local, LOCAL_GRANT = LOCAL_GRANT is not None, None

    # segment_permitted turns any exception from a local grant into "no grant",
    # so a broken local_grants.py looks exactly like an absent one. Call it once
    # for real -- that silence is otherwise indistinguishable from working.
    local_error = None
    if had_local:
        try:
            load_local_grants()(["true"], GUARD_VIEW)
        except Exception as exc:
            local_error = f"{type(exc).__name__}: {exc}"

    failed = []
    for group, cases in (("case", _CASES), ("gap", _GAPS)):
        for expected, command in cases:
            try:
                got = _verdict(command)
            except Exception as exc:                  # a crash is a failure
                got = f"raised {type(exc).__name__}: {exc}"
            if got != expected:
                failed.append((group, expected, got, command))

    for group, expected, got, command in failed:
        label = "GAP CLOSED?" if group == "gap" else "FAIL"
        print(f"{label}  expected {expected}, got {got}\n          {command}")

    total = len(_CASES) + len(_GAPS)
    print(f"\n{total} cases ({len(_CASES)} behaviour, {len(_GAPS)} known gaps), "
          f"{len(failed)} unexpected")
    if local_error:
        print(f"local_grants.py FAILS TO RUN -- every local grant is silently "
              f"lost: {local_error}")
    elif had_local:
        print("note: local_grants.py loads and runs; disabled for the cases above")
    return 1 if failed or local_error else 0


def emit(decision, reason):
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }, sys.stdout)


def main():
    if "--test" in sys.argv[1:]:
        return _selftest()

    if guard_disabled():
        return 0

    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    command = (payload.get("tool_input") or {}).get("command") or ""
    if not command.strip():
        return 0

    reasons = find_reasons(command)
    if reasons:
        emit("ask", "Write-capable command: " + "; ".join(reasons))
        return 0

    cwd = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    if grant_verdict(command, cwd):
        emit("allow", "Every command is allowlisted and read-only, or "
                      "covered by a local grant")
    return 0


if __name__ == "__main__":
    sys.exit(main())
