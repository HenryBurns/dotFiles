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

Self-test:  ./bash-write-guard.py --test   (no `python3`: that always asks)
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

# `{ list; }` groups commands in the CURRENT shell. Only a bare `{` where a
# command may start is the group opener: brace expansion arrives as a single
# token (`{a,b}`), so the two can never be confused. Kept apart from OPERATORS
# because shlex does not treat these as punctuation, so they reach us as words.
GROUPING = {"{", "}"}
REDIRECTS = {">", ">>", ">|", ">&", "&>", "&>>"}

# Redirect targets that don't actually write a file. `2>/dev/null` discards
# stderr and `2>&1` just duplicates a descriptor -- both are read-only idioms.
DEV_SINKS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd"}

# What the guard knows about individual tools lives in a sibling module, both
# to keep this file readable and to keep each table beside the reasoning for
# it. Referenced as `T.NAME` rather than star-imported: in a file that decides
# whether a program may run, "where did this set come from" has to be
# answerable by reading.
#
# A failure here must NOT propagate as an uncaught import error. That exits
# non-zero with no stdout, which PreToolUse treats as a non-blocking error --
# the allow rules would then decide alone, and they permit `sed -i` under
# Bash(sed:*). So it is recorded and re-raised inside _decide(), where the
# fail-closed handler turns it into "ask". _fail_closed_ok() covers that path.
_TABLES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "bash-write-guard-tables.py")

try:
    import importlib.util as _importlib_util
    _spec = _importlib_util.spec_from_file_location(
        "bash_write_guard_tables", _TABLES_FILE)
    T = _importlib_util.module_from_spec(_spec)
    _spec.loader.exec_module(T)
    TABLES_ERROR = None
except Exception as _exc:            # any failure at all: recorded, not raised
    T, TABLES_ERROR = None, _exc

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
    # -- outward-facing tooling --------------------------------------------
    # Every orchestrator invocation asks, read-only subcommands included. This
    # is not a claim that `whoami` writes: orchestrator is how work reaches
    # shared branches, its subcommands are not reliably separable into readers
    # and writers from argv alone, and a wrong guess here lands on branches
    # other teams build on. Asking on all of it is cheap -- it is a
    # hand-driven tool, run a few times a day, and its SSO login is manual
    # anyway. Entries here beat any allow rule, and argv0_of basenames the
    # command word, so an absolute path to the tool matches this too -- which
    # is the form that gets typed, since ~/.local/bin is not on the PATH the
    # Bash tool's shell ends up with.
    "orchestrator": "submits and manages work on shared branches",
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
    # -- command wrappers ---------------------------------------------------
    # These take another command as their arguments, so argv0_of reports the
    # wrapper and every write check below it looks at the wrong word:
    # `timeout 30 rm -rf x` produced no reasons at all. Unwrapping instead
    # would mean knowing each wrapper's own flag arity, and guessing that wrong
    # is how you mistake the real command for a flag value. Refuse to guess.
    # timeout is unwrapped by unwrap_wrappers when its prefix parses; this
    # entry catches the leftovers -- an unknown flag or a bad duration.
    "timeout": "runs another command the guard cannot attribute",
    "nice": "runs another command the guard cannot attribute",
    "ionice": "runs another command the guard cannot attribute",
    "chrt": "runs another command the guard cannot attribute",
    "taskset": "runs another command the guard cannot attribute",
    "stdbuf": "runs another command the guard cannot attribute",
    "setsid": "runs another command the guard cannot attribute",
    "flock": "runs another command the guard cannot attribute",
    "watch": "runs another command the guard cannot attribute",
    "script": "records the session to a file",
    "xargs": "runs another command the guard cannot attribute",
    "env": "runs another command the guard cannot attribute",
    "nohup": "runs another command the guard cannot attribute",
    "time": "runs another command the guard cannot attribute",
    "command": "runs another command the guard cannot attribute",
    # -- privilege escalation ------------------------------------------------
    "sudo": "runs another command as another user",
    "doas": "runs another command as another user",
    "su": "runs another command as another user",
    "runuser": "runs another command as another user",
}

# ---------------------------------------------------------------------------
# Control-flow recognition
# ---------------------------------------------------------------------------

# Keywords that introduce a command position after them.
# `while cmd; do body; done` needs nothing beyond separating the words: the
# condition and the body are ordinary commands, and every existing check applies
# to each. Unlike `for` there is no word list to vet, so this is the SIMPLER
# loop -- it was refused out of caution, not difficulty. Running a read-only
# body a million times is still read-only, and a body that writes is caught the
# same way it is anywhere else.
CONTROL_KEYWORDS = {"do", "then", "elif", "else", "if", "fi", "done",
                    "while", "until"}

# Builtins that only steer control flow or return a status. They touch nothing,
# take no path, and have no write form -- but they are builtins, so no `Bash(..)`
# rule can ever match them and `|| continue` silenced the guard on an otherwise
# read-only loop. Cleared without a rule for the same reason `for` is handled:
# there is no command for a rule to name.
#
# `read` belongs here for a subtler reason: it writes no file, and the names it
# assigns are never resolved, so `$line` in the body stays opaque and is judged
# exactly like a value out of `$(...)`. A flag-sensitive command refuses it, an
# expansion in command position aborts, and everything else treats it as data.
# Treating what was read as unknown IS the safety property -- there is nothing
# to add beyond declining to resolve it.
NOOP_BUILTINS = {"continue", "break", "true", "false", ":", "read"}

# `set` has two jobs and only one of them is safe. Changing shell OPTIONS
# (`set -o pipefail`, `set -e`) writes nothing and hands nothing to a later
# command. Setting POSITIONAL PARAMETERS does: `set -- -i` followed by
# `sed $1 f` smuggles a flag exactly the way `for f in -i` does, and `$1` is
# never resolved. So the option forms are enumerated and everything else --
# `set --`, `set a b`, a bare `set` that dumps every variable -- still refuses.
# Single-letter option flags, which bash lets you combine: `set -euo pipefail`
# is one token carrying three of them. Matched letter by letter so a cluster
# needs no separate entry, and so an unknown letter anywhere in one refuses.
SET_SHELL_LETTERS = set("abefhkmnptuvxBCEHPTo")
SET_OPTION_NAMES = {
    "allexport", "braceexpand", "emacs", "errexit", "errtrace", "functrace",
    "hashall", "histexpand", "history", "ignoreeof", "interactive-comments",
    "keyword", "monitor", "noclobber", "noexec", "noglob", "nolog", "notify",
    "nounset", "onecmd", "physical", "pipefail", "posix", "privileged",
    "verbose", "vi", "xtrace",
}


def set_is_noop(args):
    """True if `set <args>` only changes shell options.

    A trailing `-o` with no name is allowed: that spelling PRINTS the current
    options, which is a read. An empty argument list is not -- a bare `set`
    dumps every shell variable, and while that writes nothing it is not a
    shape worth waving through.
    """
    expect_option_name = False
    for arg in args:
        if expect_option_name:
            if arg not in SET_OPTION_NAMES:
                return False
            expect_option_name = False
            continue
        if len(arg) < 2 or arg[0] not in "-+":
            return False       # `--`, `a`, and anything else positional
        letters = arg[1:]
        if not all(letter in SET_SHELL_LETTERS for letter in letters):
            return False
        # `o` takes the option name that follows, so it is only unambiguous as
        # the last letter of a cluster. `-oe` is refused rather than guessed at.
        if "o" in letters[:-1]:
            return False
        expect_option_name = letters.endswith("o")
    return bool(args)

# Anything here means we refuse to reason about the command at all. Either it
# rewrites the execution environment (eval, export), or it is a construct
# outside the recognized subset (case, select), or it hides a command position.
REFUSED_WORDS = {
    "eval", "exec", "source", ".", "trap", "alias", "unalias", "command",
    "case", "esac", "select", "function", "coproc",
    "export", "declare", "typeset", "local", "unset", "shift",
    "mapfile", "readarray", "xargs", "env", "nohup", "sudo", "time",
}

# T.FLAG_SENSITIVE (sed/sort/find/awk) is defined with the tool tables: it is
# built from T.AWK_LIKE, and evaluating that here would touch the tables before
# _decide() can check they loaded.

# ---------------------------------------------------------------------------
# Variable assignments
# ---------------------------------------------------------------------------

ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)

# A value is accepted only if every character is in this set and it does not
# begin with `-`. That is precisely what makes a later unquoted `$L` equivalent
# to the literal: no whitespace to word-split on, no glob character to expand,
# and no leading dash to be read as a flag. So the guard can substitute the
# value in and reason about the real command.
SAFE_VALUE = re.compile(r"^[A-Za-z0-9_@%+:,./=~-]+$")

# Names the shell -- or a tool the shell runs -- consults to decide WHAT gets
# executed or HOW. These are the reason assignments were refused outright:
# `GIT_EXTERNAL_DIFF=rm git diff` runs rm through an allowlisted `git diff`,
# and LD_PRELOAD injects code into every child process.
UNSAFE_VAR_NAMES = {
    "PATH", "IFS", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "CDPATH",
    "GLOBIGNORE", "PROMPT_COMMAND", "HOME", "PWD", "OLDPWD", "TMPDIR",
    "SHELL", "TERM", "TERMINFO", "EDITOR", "VISUAL", "PAGER", "MANPAGER",
    "LESS", "LESSOPEN", "LESSCLOSE", "AWKPATH", "AWKLIBPATH", "LOCPATH",
    "NLSPATH", "HOSTALIASES", "POSIXLY_CORRECT", "TZ",
}
UNSAFE_VAR_PREFIXES = (
    "LD_", "DYLD_", "BASH_", "GIT_", "PYTHON", "PERL", "NODE_", "RUBY",
    "GEM_", "JAVA_", "JDK_", "LC_", "LANG", "SSH_", "SSL_", "CURL_", "GPG_",
    "GNUPG", "PS", "PROXY", "HTTP_", "HTTPS_", "FTP_", "NO_",
)

_VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def safe_assignment(name, value):
    """True if `NAME=value` cannot change what runs or how it runs."""
    upper = name.upper()
    if upper in UNSAFE_VAR_NAMES:
        return False
    if any(upper.startswith(prefix) for prefix in UNSAFE_VAR_PREFIXES):
        return False
    # Anything already in the environment is load-bearing for something on this
    # machine, and reassigning it can change behaviour the guard cannot see.
    # This is the backstop for whatever the two lists above failed to name.
    if name in os.environ:
        return False
    # A value from $(...) arrives as the placeholder, which passes SAFE_VALUE.
    # That is deliberate: it is recorded as-is, so `$n` later carries the
    # placeholder and the flag-sensitive check catches `sed $n f` while
    # `printf "$n"` is left alone. The substitution's own commands are verified
    # separately, by analyze recursing into the span.
    # As with a loop word, the test is "could this arrive as a flag", not "can
    # I read it". `st=**MISMATCH**` is unreadable but provably not a flag, and
    # it was silencing the guard on a loop that only ran grep and printf. It is
    # accepted here and left UNSUBSTITUTED -- readable_assignment below decides
    # what may stand in for `$st` -- so the body still judges `$st` as opaque.
    pieces = value.split()
    return bool(pieces) and not any(p.startswith("-") for p in pieces)


def exported_assignments(tokens, index, total):
    """({name: value}, index past them) for `export NAME=value ...`, else None.

    None means "not the shape this models", which leaves `export` to
    REFUSED_WORDS. An empty dict is a bare `export`, which only lists the
    environment -- a read, like printenv.
    """
    found = {}
    while index < total and tokens[index] not in OPERATORS:
        assigned = ASSIGNMENT.match(tokens[index])
        if not assigned:
            return None
        name, value = assigned.group(1), assigned.group(2)
        if not safe_assignment(name, value):
            return None
        found[name] = value
        index += 1
    return found, index


def prefixes_read(tokens, index):
    """True if the assignment at `index` is a prefix to the `read` builtin.

    `IFS=: read -r a b` scopes IFS to that one command, where all it can do is
    change how read splits the line it was handed -- and read's results are
    opaque either way, so the value cannot make anything more dangerous. A bare
    `IFS=:; cmd` is a different thing entirely: it changes word splitting for
    every command after it, which is why IFS is refused in general. The two are
    told apart only by what follows, hence this lookahead.
    """
    while index < len(tokens) and ASSIGNMENT.match(tokens[index]):
        index += 1
    return index < len(tokens) and tokens[index] == "read"


def readable_assignment(name, value):
    """True if NAME=value is safe AND literal enough to substitute verbatim."""
    return safe_assignment(name, value) and bool(SAFE_VALUE.match(value))


def safe_loop_word(word):
    """True if a `for` word is a bare literal that cannot arrive as a flag.

    The same rule as a safe assignment value, for the same reason: the body
    sees `sed $f`, and every flag check runs against the token `$f` rather than
    against what it expands to. `for f in -i; do sed $f x; done` was therefore
    granted as a read-only sed and then edited the file in place.

    Whitespace is excluded too, not only a leading dash -- an unquoted `$f`
    word-splits, so `for f in "a -i"` smuggles the flag out of a single word.

    The substitution placeholder stays accepted on purpose: refusing it would
    also refuse `for sha in $(git rev-list ...)`. That remains a documented gap
    rather than an oversight.
    """
    if SUBST_PLACEHOLDER in word:
        return True
    # A word may legitimately contain spaces -- `for s in "namespace os76"`.
    # The loop still iterates over the WORDS (two items there, not three); the
    # splitting that matters happens later, if the BODY uses `$s` unquoted,
    # where `namespace os76` becomes two arguments. So the hazard is a piece
    # that could arrive as a flag, not the whitespace itself -- which makes
    # judging the pieces exact where rejecting all whitespace was merely
    # conservative. `a -i` still refuses, on its second piece.
    #
    # The test is "could this arrive as a flag", NOT "can I read it". A glob
    # like `conf/*.toml` is unreadable -- the matches depend on the directory
    # -- but no expansion of it can start with `-`, and an unreadable word is
    # exactly what the placeholder already records elsewhere. Refusing it made
    # the guard silent on a loop whose body only ran grep and printf. A word
    # that IS visibly a flag still refuses: that is a positive identification,
    # and those are never thrown away.
    pieces = word.split()
    return bool(pieces) and not any(p.startswith("-") for p in pieces)


def expand_known(token, assignments):
    """Substitute variables whose literal value was recorded; leave the rest."""
    if "$" not in token or not assignments:
        return token
    return _VAR_REF.sub(
        lambda m: assignments.get(m.group(1) or m.group(2), m.group(0)), token)


def newlines_to_separators(text):
    """Replace unquoted newlines with `;`.

    shlex treats a newline as ordinary whitespace under whitespace_split, so
    two commands on two lines collapsed into ONE. `echo "$(echo hi)"` followed
    by `rm -rf x` became a single command whose argv0 is echo: the rm was read
    as an argument, the segment matched Bash(echo:*), and the substitution made
    it grantable. That is an outright `allow` for a delete.

    A newline separates commands in the shell everywhere except inside quotes,
    and a backslash-newline joins lines instead of separating them.
    """
    out, index, quote = [], 0, None
    while index < len(text):
        char = text[index]
        if quote == "'":
            quote = None if char == "'" else quote
            out.append(char)
            index += 1
        elif quote == '"':
            if char == "\\" and index + 1 < len(text):
                out.append(text[index:index + 2])
                index += 2
                continue
            quote = None if char == '"' else quote
            out.append(char)
            index += 1
        elif char in ("'", '"'):
            quote = char
            out.append(char)
            index += 1
        elif char == "\\" and index + 1 < len(text):
            if text[index + 1] == "\n":
                index += 2  # line continuation joins, it does not separate
                continue
            out.append(text[index:index + 2])
            index += 2
        else:
            out.append(";" if char == "\n" else char)
            index += 1
    return "".join(out)


def tokenize(command):
    lexer = shlex.shlex(newlines_to_separators(command), posix=True,
                        punctuation_chars=True)
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
    """Drop `do` / `then` / `else` / `{` etc. from the front of a segment.

    Splitting on operators alone leaves the keyword sitting where the command
    name should be, so `for f in a; do rm "$f"; done` yields `['do','rm','$f']`
    and argv0_of reports `do` -- hiding the `rm` from every write check.

    A bare brace does exactly the same damage: `{ rm -rf x; }` yields
    `['{','rm','-rf','x']`, so argv0_of reported `{` and NO write check fired.
    That was survivable only because `{` matches no allow rule and the command
    prompted anyway -- the guard's own answer was wrong, and would have become
    a hole the moment it learned to grant brace groups.

    Only LEADING words go: one used as an argument must still be scanned, or
    `find . -name done -delete` would lose its `-delete`.
    """
    index = 0
    while index < len(segment) and (segment[index] in CONTROL_KEYWORDS
                                    or segment[index] in GROUPING):
        index += 1
    return segment[index:]


# A session scratchpad is disposable by construction: created per session under
# the running user's own /tmp tree, and never part of a repo. Writes landing
# provably inside one are not worth a prompt. The uid is pinned so another
# user's /tmp/claude-* directory is not somewhere we will write unprompted.
SANDBOX_DIR = re.compile(
    r"^/tmp/claude-%d/[^/]+/[^/]+/scratchpad(/|$)" % os.getuid())


def in_sandbox(target):
    """True only if `target` PROVABLY lands in a disposable scratchpad.

    Absolute and literal only. A relative path depends on the cwd, which a `cd`
    earlier in the line may have changed to something unreadable, and a path
    holding `$x` or a substitution is not a path we have read. Neither can be
    proven, so neither is sandboxed -- the whole value of this is that it never
    guesses a write is harmless.
    """
    if not target.startswith("/") or "$" in target:
        return False
    if SUBST_PLACEHOLDER in target:
        return False
    # normpath collapses `..` lexically, so `/tmp/claude-N/p/s/scratchpad/../..`
    # cannot masquerade as inside. realpath is deliberately NOT used: it touches
    # the filesystem, and the answer would then depend on what exists right now.
    return bool(SANDBOX_DIR.match(os.path.normpath(target)))


def sandboxed_targets(paths):
    """True if there is at least one target and every one is in a scratchpad.

    An empty list is False on purpose: "no targets found" means the parse did
    not locate them, which is not the same as "nothing is written".
    """
    return bool(paths) and all(in_sandbox(path) for path in paths)


# sed's script is its first positional -- unless -e/-f supplied one, in which
# case every positional is a file. Getting that wrong would drop a real file
# from the target list, so an unrecognized flag abandons the parse instead.
SED_SCRIPT_FLAGS = {"-e", "--expression", "-f", "--file"}
SED_VALUE_FLAGS = SED_SCRIPT_FLAGS | {"-l", "--line-length"}
SED_BOOL_FLAGS = {
    "-n", "--quiet", "--silent", "-r", "-E", "--regexp-extended",
    "-s", "--separate", "-z", "--null-data", "--posix", "--follow-symlinks",
    "--debug", "--sandbox", "-u", "--unbuffered",
}


def sed_targets(args):
    """Files `sed -i` would rewrite, or None if the parse is not provable."""
    positionals, script_from_flag, index = [], False, 0
    while index < len(args):
        token = args[index]
        if token == "--":
            positionals.extend(args[index + 1:])
            break
        if token.startswith("-") and token != "-":
            base = token.split("=", 1)[0]
            if base in SED_SCRIPT_FLAGS:
                script_from_flag = True
            if base in SED_VALUE_FLAGS:
                index += 1 if "=" in token else 2
            elif base in SED_BOOL_FLAGS or T.SED_INPLACE.match(token):
                index += 1
            else:
                return None
            continue
        positionals.append(token)
        index += 1
    if script_from_flag:
        return positionals
    return positionals[1:]          # the first positional is the script


# tee writes every positional. `-` is stdout, and no tee flag takes a separate
# value (--output-error carries its mode with `=`), so the parse is simple.
TEE_BOOL_FLAGS = {"-a", "--append", "-i", "--ignore-interrupts", "-p",
                  "--output-error"}


def tee_targets(args):
    """Files tee writes, or None if a flag makes the parse unprovable."""
    files = []
    for token in args:
        if token == "-":
            continue                # stdout, not a file
        if token.startswith("-"):
            if token.split("=", 1)[0] not in TEE_BOOL_FLAGS:
                return None
            continue
        files.append(token)
    return files


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
        if in_sandbox(target):
            continue  # disposable scratch, provably so
        return True
    return False


def without_redirections(segment):
    """`segment` with redirect operators and their targets removed.

    `2>&1` is three tokens -- `2`, `>&`, `1` -- and none of them is an argument
    to the command. Any check that counts positionals sees them otherwise:
    `uniq -c f 2>&1` counted three and reported an output file, and `git config
    user.name 2>/dev/null` counted two and reported a write. Both were plain
    reads. redirects_to_file is the one caller that wants them kept.
    """
    args, index = [], 0
    while index < len(segment):
        token = segment[index]
        following = segment[index + 1] if index + 1 < len(segment) else ""
        if token in REDIRECTS:
            index += 2                       # the operator and its target
        elif token.isdigit() and following in REDIRECTS:
            index += 1                       # the fd number in `2>&1`
        else:
            args.append(token)
            index += 1
    return args


def argv0_of(segment):
    """First real command word, skipping leading VAR=value assignments."""
    for index, token in enumerate(segment):
        if "=" in token and not token.startswith("-") and index == 0:
            continue
        if token.startswith("-"):
            continue
        return token.rsplit("/", 1)[-1], segment[index + 1:]
    return None, []




# `uniq [OPTION]... [INPUT [OUTPUT]]`: the SECOND positional is a file it
# OVERWRITES. Checked rather than assumed -- `uniq in out` produced the file.
# Like git config this counts positionals, so every value-taking flag has to be
# consumed exactly and an unknown flag makes the count unprovable.
UNIQ_BOOL_FLAGS = {
    "-c", "--count", "-d", "--repeated", "-D", "--all-repeated",
    "-i", "--ignore-case", "-u", "--unique", "-z", "--zero-terminated",
    "--group",
}
UNIQ_VALUE_FLAGS = {"-f", "--skip-fields", "-s", "--skip-chars",
                    "-w", "--check-chars"}


def uniq_writes(args):
    """True if `uniq <args>` names an OUTPUT file to overwrite."""
    positionals, index = [], 0
    while index < len(args):
        token = args[index]
        if token == "--":
            positionals.extend(args[index + 1:])
            break
        if token.startswith("-") and token != "-":   # bare `-` is stdin
            base = token.split("=", 1)[0]
            if base in UNIQ_BOOL_FLAGS:
                index += 1
            elif base in UNIQ_VALUE_FLAGS:
                index += 1 if "=" in token else 2
            elif len(base) > 2 and base[:2] in UNIQ_VALUE_FLAGS:
                index += 1                            # attached: -f2, -s3, -w5
            else:
                return True
            continue
        positionals.append(token)
        index += 1
    if len(positionals) < 2:
        return False
    return not in_sandbox(positionals[1])


# `ruff` reads -- except when it does not. `check --fix` rewrites what it finds,
# `format` edits in place unless asked for a --check or --diff, `clean` deletes
# cache directories, and -o writes a report. A prefix rule cannot tell these
# apart from a lint, so the guard has to.
# -o/--output-file is NOT here: it names an output path, so it is judged by
# where that path lands. --fix rewrites the source files ruff was pointed at,
# which no output path makes disposable.
RUFF_WRITE_FLAGS = {"--fix", "--fix-only"}
RUFF_FORMAT_READONLY = {"--check", "--diff"}


def ruff_writes(args):
    """Why `ruff <args>` writes, or "" if it only reads.

    Subcommands are matched anywhere among the non-flag words rather than by
    position: a value-taking flag before the subcommand (`--config x format`)
    would otherwise hide it. The cost is over-asking on a file literally named
    `format`, which is the right direction to be wrong in.
    """
    bases = {arg.split("=", 1)[0] for arg in args if arg.startswith("-")}
    hit = sorted(bases & RUFF_WRITE_FLAGS)
    if hit:
        return f"ruff {' '.join(hit)} rewrites files"
    if writes_outside_sandbox(args, T.RUFF_OUTPUT_FLAGS):
        return "ruff -o writes a report to a file"

    words = {arg for arg in args if not arg.startswith("-")}
    if "clean" in words:
        return "ruff clean deletes cache directories"
    if "format" in words and not (bases & RUFF_FORMAT_READONLY):
        return "ruff format rewrites files in place"
    if "server" in words:
        return "ruff server runs a language server"
    return ""


# systemctl queries and changes service state under one command name. Unlike
# git and ruff, its write side is far larger and more varied than its read side
# -- start, stop, restart, enable, mask, daemon-reload, isolate, set-property,
# reboot ... -- so this names what READS and treats everything else as a write.
# An unknown subcommand is then a prompt rather than a silent state change.
SYSTEMCTL_READONLY = {
    "is-active", "is-enabled", "is-failed", "is-system-running",
    "status", "show", "cat", "help", "get-default", "show-environment",
    "list-units", "list-unit-files", "list-timers", "list-sockets",
    "list-jobs", "list-dependencies", "list-machines", "list-paths",
    "list-automounts",
}
SYSTEMCTL_BOOL_FLAGS = {
    "--user", "--system", "--global", "--no-pager", "--no-legend",
    "--no-ask-password", "--no-block", "--full", "-l", "--all", "-a",
    "--plain", "--quiet", "-q", "--recursive", "-r", "--reverse", "--failed",
    "--value", "--show-types", "--version", "--help", "-h", "--runtime",
    "--dry-run", "--wait", "--no-reload", "--with-dependencies",
}
SYSTEMCTL_VALUE_FLAGS = {
    "--type", "-t", "--state", "--property", "-p", "--output", "-o",
    "--host", "-H", "--machine", "-M", "--signal", "-s", "--kill-who",
    "--job-mode", "--root", "--image", "--lines", "-n", "--since", "--until",
    "--what",
}


# ssh-add reports agent state and CHANGES it under one name, and changing is
# the default: a bare `ssh-add` loads the default identities, -d/-D delete them,
# -x/-X lock the agent, -s/-e add or remove a PKCS#11 provider, -t sets a
# lifetime. Only listing reads, so -- as with systemctl -- the read side is
# named and everything else asks, a bare invocation included.
SSH_ADD_READ_FLAGS = {"-l", "-L", "-v", "-q"}
SSH_ADD_LIST_FLAGS = {"-l", "-L"}
SSH_ADD_VALUE_FLAGS = {"-E"}          # -E md5 / -E sha256: fingerprint format


def ssh_add_writes(args):
    """Why `ssh-add <args>` changes agent state, or "" if it only lists."""
    listing, index = False, 0
    while index < len(args):
        arg = args[index]
        if not arg.startswith("-"):
            return f"ssh-add would load the identity file {arg}"
        base = arg.split("=", 1)[0]
        if base in SSH_ADD_VALUE_FLAGS:
            index += 1 if "=" in arg else 2
            continue
        if base not in SSH_ADD_READ_FLAGS:
            return f"ssh-add {base} changes agent state"
        listing = listing or base in SSH_ADD_LIST_FLAGS
        index += 1
    if not listing:
        return "ssh-add with no -l/-L loads the default identities"
    return ""


def systemctl_writes(args):
    """Why `systemctl <args>` may change state, or "" if it only queries."""
    index = 0
    while index < len(args) and args[index].startswith("-"):
        token = args[index]
        base = token.split("=", 1)[0]
        if base in SYSTEMCTL_BOOL_FLAGS and "=" not in token:
            index += 1
        elif base in SYSTEMCTL_VALUE_FLAGS:
            index += 1 if "=" in token else 2
        else:
            return ("systemctl is passed an option the guard cannot attribute "
                    "to a subcommand")
    if index >= len(args):
        return ""                       # bare `systemctl` lists units
    sub = args[index]
    if sub in SYSTEMCTL_READONLY:
        return ""
    return f"systemctl {sub} is not a known read-only subcommand"


def git_subcommand_index(rest):
    """Index of the real subcommand in `git <globals> SUB ...`, or None.

    None means either no subcommand or an option this does not know -- and an
    unknown option makes the position unprovable, so callers must treat that as
    "cannot attribute" rather than "no subcommand".
    """
    index = 0
    while index < len(rest) and rest[index].startswith("-"):
        token = rest[index]
        base = token.split("=", 1)[0]
        if base in T.GIT_GLOBAL_BOOL and "=" not in token:
            index += 1
        elif base in T.GIT_GLOBAL_VALUE:
            index += 1 if "=" in token else 2
        else:
            return None
    return index if index < len(rest) else None




def git_prints_and_exits(rest):
    """True if these global options make git print and exit.

    Scanned left to right because git acts on the first option it recognizes.
    The BARE spellings only: `--exec-path=DIR` is not terminal -- it repoints
    where git finds its helper programs and then runs the subcommand anyway
    (`git --exec-path=/tmp/nope version` printed the version). Anything this
    does not recognize stops the scan rather than being skipped over, so an
    option that could take a value can never hide a subcommand behind it.
    """
    for token in rest:
        if token in T.GIT_TERMINAL_OPTIONS:
            return True
        if token in T.GIT_PAGER_OPTIONS:
            continue
        return False
    return False


def git_fetch_writes(args):
    """Why `git fetch <args>` writes more than tracking refs, or "" if it does not."""
    positional_only, index = False, 0
    while index < len(args):
        token = args[index]
        if not positional_only and token == "--":
            positional_only = True
            index += 1
            continue
        if not positional_only and token.startswith("-"):
            base = token.split("=", 1)[0]
            if base in T.GIT_FETCH_WRITE_FLAGS:
                return f"git fetch {base} writes local refs or config"
            if base in T.GIT_FETCH_VALUE_FLAGS and "=" not in token:
                index += 2
                continue
            index += 1
            continue
        # A colon means a destination refspec (writes a local ref) or an scp-style
        # URL (fetches from somewhere unreviewed). Both are worth the prompt, so
        # the over-ask on a URL is deliberate rather than a gap.
        if ":" in token:
            return f"git fetch {token} writes a local ref, or fetches from a URL"
        index += 1
    return ""


# orchestrator is in ALWAYS_ASK because its subcommands are not separable into
# readers and writers from argv alone -- submit, abort, resubmit, queue_reorder
# and pull_request_delete all sit in the same namespace. The exception is a
# subcommand whose implementation has been READ and shown to be a GET: the
# reason for the blanket rule is uncertainty, so removing the uncertainty for
# one subcommand is the honest thing to do, not a weakening of it.
#
# request_status: pull_request_status() does one http_session.get and log.info;
# job_status has no HTTP write verb, no open(), no subprocess. Its whole
# surface is one positional id plus five store_true flags, listed here so a
# sixth appearing in a later version refuses instead of riding along.
# queue_status: two http_session.get calls and log.info to stdout. No HTTP
# write verb, no open(), no subprocess of its own. Its whole surface is one
# optional `to_branch` positional plus the three flags below.
#
# --commits and --orig-commits are NOT pure reads, in either subcommand: both
# reach print_commits -> ensure_commits_fetched, which runs
# `git fetch origin --quiet <sha>` when a commit is not present locally. They
# stay granted because that is the same fetch `Bash(git fetch:*)` already
# allows -- no destination refspec and none of T.GIT_FETCH_WRITE_FLAGS -- but it
# is written down because "status query" does not suggest a network fetch.
#
# Flags are per subcommand rather than one shared set: --color and
# --sort-by-name come from _configure_common_status_arguments, which
# queue_status does not call, and a set that overstates what a subcommand
# accepts is a set nobody can check against the source.
ORCHESTRATOR_READ_FLAGS = {
    "request_status": {"--show-history", "--commits", "--color",
                       "--orig-commits", "--sort-by-name"},
    "queue_status": {"--commits", "--fail-summary", "--num-completed"},
}
# `to_branch` defaults to the cwd's upstream, so a bare `orchestrator
# queue_status` is a vetted shape. A bare `request_status` is not: argparse
# requires its id.
ORCHESTRATOR_OPTIONAL_POSITIONAL = {"queue_status"}


def orchestrator_reads(args):
    """True if `orchestrator <args>` is a subcommand proven to only read."""
    if not args:
        return False
    flags = ORCHESTRATOR_READ_FLAGS.get(args[0])
    if flags is None:
        return False
    saw_id = False
    for arg in args[1:]:
        # An argument the guard cannot read could BE one of the flags it has
        # not vetted, so the exemption cannot be proven and is not given.
        if arg.startswith("$") or SUBST_PLACEHOLDER in arg:
            return False
        if arg.startswith("-"):
            # `--num-completed=5` is one token; split so the value does not
            # make a vetted flag look like an unknown one.
            if arg.split("=", 1)[0] not in flags:
                return False
            continue
        saw_id = True   # an id, a branch, or a flag's value: all only steer
    # No positional at all is not the shape that was vetted, unless the
    # subcommand documents a default for it.
    return saw_id or args[0] in ORCHESTRATOR_OPTIONAL_POSITIONAL


def git_ls_remote_writes(args):
    """Reason `git ls-remote <args>` is more than a ref lookup, or None."""
    for arg in args:
        base = arg.split("=", 1)[0]
        if base in T.GIT_LS_REMOTE_ASK_FLAGS:
            return (f"git ls-remote {base} hands the remote a program to run "
                    f"or an option to act on")
    return None


def git_remote_writes(args):
    """Reason `git remote <args>` changes a remote, or None if it only reads."""
    for arg in args:
        if not arg.startswith("-"):
            if arg in T.GIT_REMOTE_WRITE_SUBCOMMANDS:
                return f"git remote {arg} changes a configured remote"
            return None  # bare, `show` or `get-url`: reads only
        if arg not in T.GIT_REMOTE_BOOL_FLAGS:
            return ("git remote is passed an option the guard cannot size, so "
                    "its subcommand cannot be located")
    return None  # no subcommand at all: `git remote` / `git remote -v`


def git_archive_writes(args):
    """Reason `git archive <args>` is more than a stream to stdout, or None."""
    for arg in args:
        if arg.split("=", 1)[0] in T.GIT_ARCHIVE_ASK_FLAGS:
            return "git archive --exec names a program for the remote to run"
    return None


def flag_values(args, flags):
    """Every value `flags` are given in `args`, in all three spellings.

    `--output=f`, `--output f`, and the attached short `-of`. A flag with no
    value at all yields None: `--output` at the end of a line names nothing,
    and a target that cannot be read cannot be proven disposable.

    Attached values are read for SHORT flags only. `--outputfoo` is a different
    option, not `--output` carrying a value, and treating it as one would
    invent a target out of a typo.

    One function for every tool that names an output file, because they had
    drifted: git's targets were checked against the scratchpad while sort's and
    ruff's were not, so the same disposable destination asked for two of them
    and not the others.
    """
    values, index = [], 0
    while index < len(args):
        token = args[index]
        base, sep, attached = token.partition("=")
        if sep and base in flags:
            values.append(attached)
        elif token in flags:
            values.append(args[index + 1] if index + 1 < len(args) else None)
            index += 1
        elif (len(token) > 2 and not token.startswith("--")
              and token[:2] in flags):
            values.append(token[2:])
        index += 1
    return values


def writes_outside_sandbox(args, flags):
    """True if `flags` name an output file that is not provably disposable."""
    targets = flag_values(args, flags)
    return bool(targets) and (None in targets
                              or not sandboxed_targets(targets))


def git_bundle_target(args):
    """The bundle file `git bundle create <args>` writes, or None.

    None for every other subcommand, `unbundle` included: that one writes
    objects and refs INTO the repository, which no scratchpad makes disposable.
    """
    if not args or args[0] != "create":
        return None
    for arg in args[1:]:
        if arg.startswith("-"):
            continue      # --progress and --version=N are not the file
        return arg
    return None


def git_bundle_writes(args):
    """Reason `git bundle <args>` writes, or None if it only reads."""
    for arg in args:
        if not arg.startswith("-"):
            if arg in T.GIT_BUNDLE_READ_SUBCOMMANDS:
                return None
            # create and unbundle both write; so does anything we do not
            # recognize, since a subcommand we cannot name we cannot vouch for.
            return f"git bundle {arg} writes a bundle file or repository objects"
        if arg not in T.GIT_BUNDLE_BOOL_FLAGS:
            return ("git bundle is passed an option the guard cannot size, so "
                    "its subcommand cannot be located")
    # No subcommand at all: `git bundle` alone is a usage error, not a write.
    return None


def git_config_writes(args):
    """True if `git config <args>` could modify configuration."""
    positionals, index = [], 0
    while index < len(args):
        token = args[index]
        if token == "--":
            positionals.extend(args[index + 1:])
            break
        if token.startswith("-"):
            base = token.split("=", 1)[0]
            if base in T.GIT_CONFIG_WRITE_FLAGS:
                return True
            if base in T.GIT_CONFIG_VALUE_FLAGS:
                index += 1 if "=" in token else 2
                continue
            if base in T.GIT_CONFIG_BOOL_FLAGS:
                index += 1
                continue
            return True  # unknown flag: the positional count is unprovable
        positionals.append(token)
        index += 1

    if positionals[:1] and positionals[0] in T.GIT_CONFIG_WRITE_SUBCOMMANDS:
        return True
    if positionals[:1] and positionals[0] in T.GIT_CONFIG_READ_SUBCOMMANDS:
        return False
    # `git config KEY VALUE` sets; `git config KEY` reads.
    return len(positionals) >= 2


def segment_reasons(segment):
    """Write-capability reasons for one simple command."""
    segment = strip_leading_keywords(segment)
    if not segment:
        return []
    reasons = []
    if redirects_to_file(segment):
        reasons.append("redirects output to a file")

    # Every check below reasons about the command's real arguments, so the
    # redirections go first -- in one place, rather than each check learning to
    # skip them. redirects_to_file above is the one that needs them.
    name, rest = argv0_of(without_redirections(segment))
    if name is None:
        return reasons

    # tee is unconditionally in ALWAYS_ASK, but every file it writes is right
    # there in argv -- so when all of them are scratchpad paths it is no more
    # of a write than a redirect into the same directory.
    tee_to_scratch = (name == "tee"
                      and sandboxed_targets(tee_targets(rest) or []))
    # Same exemption shape as tee: orchestrator asks on everything except the
    # subcommands read out of its own source and proven to be reads.
    orchestrator_read = (name == "orchestrator" and orchestrator_reads(rest))
    if name in ALWAYS_ASK and not tee_to_scratch and not orchestrator_read:
        reasons.append(f"{name} {ALWAYS_ASK[name]}")

    if name == "sed" and any(T.SED_INPLACE.match(t) for t in rest):
        if not sandboxed_targets(sed_targets(rest) or []):
            reasons.append("sed edits files in place")

    if name == "uniq" and uniq_writes(rest):
        reasons.append("uniq overwrites its second argument")

    if name == "ruff":
        why = ruff_writes(rest)
        if why:
            reasons.append(why)

    if name == "ssh-add":
        why = ssh_add_writes(rest)
        if why:
            reasons.append(why)

    if name == "systemctl":
        why = systemctl_writes(rest)
        if why:
            reasons.append(why)

    if name == "find":
        hit = sorted(T.FIND_WRITE_FLAGS.intersection(rest))
        if hit:
            reasons.append(f"find {' '.join(hit)} runs commands or deletes")

    if name == "sort" and writes_outside_sandbox(rest, T.SORT_OUTPUT_FLAGS):
        reasons.append("sort -o writes to a file")

    if name in T.AWK_LIKE:
        if any(T.AWK_WRITE.search(t) for t in rest):
            reasons.append("awk program redirects or shells out")
        # -f reads the program from a file this hook never opens, so its
        # redirects and system() calls are invisible to the check above.
        elif any(t == "-f" or t.startswith("--file") or
                 (t.startswith("-f") and len(t) > 2) for t in rest):
            reasons.append("awk -f runs a program file the guard cannot inspect")

    # Everything below wants the subcommand, which global options push right.
    sub_at = git_subcommand_index(rest) if name == "git" else None
    sub = rest[sub_at] if sub_at is not None else None
    sub_args = rest[sub_at + 1:] if sub_at is not None else []

    git_sub = sub in T.GIT_FLAG_SENSITIVE
    flag_args = sub_args if git_sub else rest
    if name in T.FLAG_SENSITIVE or git_sub:
        if any(a.startswith("$") or a.startswith(SUBST_PLACEHOLDER)
               for a in flag_args):
            reasons.append(f"{name} takes an argument from an expansion the "
                           f"guard cannot see, which could be a write flag")

    if name == "git":
        if rest and sub_at is None and not git_prints_and_exits(rest):
            # An option we cannot size, so the subcommand cannot be located and
            # none of the checks below can be trusted to have run.
            reasons.append("git is passed an option the guard cannot attribute "
                           "to a subcommand")
        if sub == "branch":
            hit = sorted(T.GIT_BRANCH_DESTRUCTIVE.intersection(sub_args))
            if hit:
                reasons.append(f"git branch {' '.join(hit)} deletes, renames "
                               f"or moves a branch")
        if sub in T.GIT_WRITE_SUBCOMMANDS:
            reasons.append(f"git {sub} writes")
        if sub == "fetch":
            why = git_fetch_writes(sub_args)
            if why:
                reasons.append(why)
        if sub == "ls-remote":
            why = git_ls_remote_writes(sub_args)
            if why:
                reasons.append(why)
        if sub == "remote":
            why = git_remote_writes(sub_args)
            if why:
                reasons.append(why)
        if sub == "config" and git_config_writes(sub_args):
            reasons.append("git config writes configuration")
        if sub == "archive":
            why = git_archive_writes(sub_args)
            if why:
                reasons.append(why)
        # A write is still a write, but one landing PROVABLY in the session
        # scratchpad is disposable -- the same exemption redirects and `tee`
        # already get, applied to the flags that name a file. An unreadable or
        # missing value gives no target to prove, so it keeps asking.
        if sub == "bundle":
            why = git_bundle_writes(sub_args)
            target = git_bundle_target(sub_args)
            if why and not (target and in_sandbox(target)):
                reasons.append(why)
        if writes_outside_sandbox(rest, T.GIT_OUTPUT_FLAGS):
            reasons.append("git --output writes its output to a file")
        if (sub in T.GIT_SHORT_OUTPUT_SUBCOMMANDS
                and writes_outside_sandbox(sub_args, T.GIT_SHORT_OUTPUT_FLAGS)):
            reasons.append(f"git {sub} -o writes its output to a file")

    return reasons


def _flat_reasons(text):
    """Write reasons for text with no unexpanded $(...) left in it."""
    try:
        tokens, _ = expand(tokenize(text))
    except ValueError:
        # Unbalanced quotes and friends. Don't guess -- fall through to the
        # normal prompt rather than allowing or blocking on a bad parse.
        return ["command could not be parsed"]

    reasons = []
    for segment in split_segments(tokens):
        reasons.extend(segment_reasons(segment))
    return reasons


def _parse_loop(tokens, index):
    """(name, words, body, index_after_done) for the `for` at `index`, or None.

    None means "not a shape worth rewriting" -- nested, unterminated, or
    malformed. The caller then leaves the tokens exactly as they were.
    """
    total = len(tokens)
    i = index + 1
    if i >= total or not tokens[i].isidentifier():
        return None
    name = tokens[i]
    i += 1
    if i >= total or tokens[i] != "in":
        return None
    i += 1
    words = []
    while i < total and tokens[i] not in ("do", ";"):
        words.append(tokens[i])
        i += 1
    while i < total and tokens[i] != "do":
        i += 1
    if i >= total:
        return None
    i += 1
    body = []
    while i < total and tokens[i] != "done":
        if tokens[i] == "for":
            return None  # nested; judge it as written rather than guess
        body.append(tokens[i])
        i += 1
    if i >= total:
        return None
    return name, words, body, i + 1


def _expandable_word(word):
    """A loop word we can substitute verbatim: literal, and not a $(...)."""
    return SUBST_PLACEHOLDER not in word and bool(SAFE_VALUE.match(word))


def expand_loops(tokens):
    """(tokens, expanded_any). Rewrite `for N in a b; do BODY; done` as
    BODY(a) ; BODY(b) ; so every downstream check sees the real command.

    This is what lets one rule cover several symptoms. `for f in -i; do sed $f
    x; done` becomes `sed -i x` and is caught by the ordinary sed check, with
    no special case for loop flags. `for f in a.txt b.txt; do sed -n 1,5p $f;
    done` becomes literal and is correctly seen as read-only, rather than being
    refused for merely containing a variable.

    A loop whose word list is not all literal -- `for f in $(cat list)` -- is
    left untouched, so the `$f` in its body survives to be judged as the opaque
    argument it is.
    """
    out, index, total, changed = [], 0, len(tokens), False
    expect_command = True

    while index < total:
        token = tokens[index]
        if token == "for" and expect_command:
            parsed = _parse_loop(tokens, index)
            if parsed:
                name, words, body, after = parsed
                if words and all(_expandable_word(w) for w in words):
                    for word in words:
                        if out and out[-1] != ";":
                            out.append(";")
                        out.extend(_substitute_var(tok, name, word)
                                   for tok in body)
                    out.append(";")
                    index, expect_command, changed = after, True, True
                    continue
        expect_command = (token in OPERATORS or token in CONTROL_KEYWORDS
                          or token in GROUPING)
        out.append(token)
        index += 1
    return out, changed


def expand_assignments(tokens):
    """Substitute NAME=value assignments whose value is a safe literal.

    Runs before both the write check and the permission check, so `L=/tmp/x;
    sed -n 1,5p "$L"` is judged on the real path rather than on the token `$L`.
    Unsafe assignments are left alone here and refused by executable_commands.
    """
    out, assignments, changed = [], {}, False
    expect_command = True
    for token in tokens:
        if expect_command:
            # `export A=/workspace/d` records A for the same reason `A=...` does;
            # the word after it is still a command position. executable_commands
            # is what decides whether the export is acceptable at all.
            if token == "export":
                out.append(token)
                continue
            assigned = ASSIGNMENT.match(token)
            if assigned and readable_assignment(assigned.group(1),
                                                assigned.group(2)):
                assignments[assigned.group(1)] = assigned.group(2)
                out.append(token)
                continue  # still a command position: `A=1 B=2 cmd`
        replaced = expand_known(token, assignments)
        changed = changed or replaced != token
        out.append(replaced)
        expect_command = (token in OPERATORS or token in CONTROL_KEYWORDS
                          or token in GROUPING)
    return out, changed


# Wrappers the guard will see through, as `NAME [OPTION]... [POSITIONAL]...
# COMMAND [ARG]...`. Adding one is a data entry, but read this first -- an
# unwrapper that parses wrongly hides the command that actually runs, which is
# strictly worse than not unwrapping at all.
#
#   value        flags taking an argument. Listing one with the wrong arity is
#                the whole hazard: the command gets eaten as a flag's value.
#   bool         flags taking no argument.
#   attached     short value flags may carry the value in the same token
#                (`stdbuf -o0`). Leave False unless the tool needs it.
#   positional   one regex per fixed argument BEFORE the command. This is the
#                safety net, not a convenience: if the token where a positional
#                belongs does not match its shape, the flag parse was wrong and
#                the command is not where we think it is, so we refuse.
#
# A wrapper does NOT belong here if:
#   * it writes something of its own -- `nohup` redirects stdout into
#     nohup.out, `script` records a transcript;
#   * its command is one shell string (`watch`, `flock -c`, `sh -c`) or its
#     arguments arrive from elsewhere (`xargs`) -- there is no argv to inspect;
#   * it changes who or what the command runs as (`sudo`, `su`, `env`).
# Those stay in ALWAYS_ASK, which is also where anything failing to parse lands.
WRAPPERS = {
    "timeout": {
        "bool": {"--preserve-status", "--foreground", "-v", "--verbose"},
        "value": {"-k", "--kill-after", "-s", "--signal"},
        "attached": False,
        "positional": (re.compile(r"^[0-9]+(\.[0-9]+)?[smhd]?$"),),  # DURATION
    },
    # xargs was long excluded because its arguments come from stdin, where the
    # guard cannot read them. But the COMMAND is right there in argv, and xargs
    # passes stdin through as arguments only -- it never re-parses them as shell
    # syntax, so no redirect or operator can arrive that way. That is the same
    # property that makes $(...) safe to read. `unknown_args` marks the args it
    # will receive, so `xargs sed s/a/b/` asks (stdin could supply -i) while
    # `xargs cat` clears. Optional-argument flags (-i, -e, -l) are deliberately
    # absent: their arity is ambiguous, so they fall through to "unknown flag"
    # and xargs stays wrapped for ALWAYS_ASK to catch.
    "xargs": {
        "bool": {"-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose",
                 "-p", "--interactive", "-x", "--exit", "-o", "--open-tty"},
        "value": {"-a", "--arg-file", "-d", "--delimiter", "-E", "-I",
                  "--replace", "-L", "--max-lines", "-n", "--max-args",
                  "-P", "--max-procs", "-s", "--max-chars",
                  "--process-slot-var"},
        "attached": True,
        "positional": (),
        "unknown_args": True,
    },
}


def _unwrap(tokens, index, spec):
    """Index of the wrapped command's first token, or None to leave it alone."""
    total = len(tokens)
    i = index + 1

    while i < total and tokens[i].startswith("-") and tokens[i] != "--":
        base = tokens[i].split("=", 1)[0]
        if base in spec["bool"] and "=" not in tokens[i]:
            i += 1
        elif base in spec["value"]:
            i += 1 if "=" in tokens[i] else 2
        elif spec["attached"] and len(base) > 2 and base[:2] in spec["value"]:
            i += 1
        else:
            return None  # unknown flag: arity unknown, so the parse is unsafe
    if i < total and tokens[i] == "--":
        i += 1

    for shape in spec["positional"]:
        if i >= total or not shape.match(tokens[i]):
            return None
        i += 1

    if i >= total or tokens[i].startswith("-") or tokens[i].startswith("$"):
        return None  # nothing recognizable in the command position
    return i


def unwrap_wrappers(tokens):
    """(tokens, changed) with recognized wrapper prefixes removed.

    A listed wrapper writes nothing itself, so dropping the prefix loses
    nothing and lets the ordinary checks see the command that really runs:
    `timeout 40 rm -rf x` is caught as rm, and `timeout 40 grep -c x f` is seen
    to be read-only rather than refused for the wrapper's sake. A prefix that
    will not parse is left in place for ALWAYS_ASK to catch. Wrappers nest,
    since the command position is re-examined after each removal.
    """
    out, index, total, changed = [], 0, len(tokens), False
    expect_command = True
    while index < total:
        token = tokens[index]
        # `A=1 timeout 5 grep x f` is still at a command position after the
        # assignment -- bash allows any number of VAR=value words before the
        # command name. Treating one as an ordinary argument hid the wrapper
        # from this pass, so `timeout` was judged as an unattributable command
        # and the whole line asked. The assignment itself is left in place and
        # is still vetted by safe_assignment in executable_commands; all this
        # decides is that a wrapper may follow it.
        if expect_command and ASSIGNMENT.match(token):
            out.append(token)
            index += 1
            continue
        spec = WRAPPERS.get(token.rsplit("/", 1)[-1]) if expect_command else None
        if spec is not None:
            start = _unwrap(tokens, index, spec)
            if start is not None:
                if spec.get("unknown_args"):
                    # The unwrapped command also receives arguments the guard
                    # cannot read. Marking them with the same placeholder an
                    # expansion leaves means the flag checks treat both alike,
                    # instead of reading the command as if argv were complete.
                    tokens = (tokens[:start + 1] + [SUBST_PLACEHOLDER]
                              + tokens[start + 1:])
                    total = len(tokens)
                index, changed = start, True
                continue
        expect_command = (token in OPERATORS or token in CONTROL_KEYWORDS
                          or token in GROUPING)
        out.append(token)
        index += 1
    return out, changed


def expand(tokens):
    """(tokens, changed) with assignments and literal loops substituted in.

    One pass, one place. Both the write check and the permission check consume
    the result, so neither can judge a command the other has already resolved.
    """
    tokens, substituted = expand_assignments(tokens)
    tokens, unrolled = expand_loops(tokens)
    tokens, unwrapped = unwrap_wrappers(tokens)
    return tokens, (substituted or unrolled or unwrapped)


def _substitute_var(token, name, value):
    """Replace $name / ${name} in one token. Other variables are left alone."""
    pattern = r"\$\{" + name + r"\}|\$" + name + r"(?![A-Za-z0-9_])"
    return re.sub(pattern, lambda _match: value, token)


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

    stripped = strip_substitutions(command, spans)
    reasons = _flat_reasons(stripped)
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
    assignments, saw_assignment = {}, False
    index, total = 0, len(tokens)

    while index < total:
        token = tokens[index]

        # A subshell is a separate evaluation and `f() { ...; }` is a definition
        # whose body does not run here; this pass models neither, so both abort.
        if token in ("(", ")"):
            return None, False

        # `{ list; }` adds no capability of its own -- it runs the list in the
        # current shell -- so the commands inside are simply the commands that
        # can run. A brace anywhere a command CANNOT start means we misread the
        # line (bash requires the `;` in `{ echo a; }`), so that still aborts.
        if token in GROUPING:
            if not expect_command:
                return None, False
            if current:
                commands.append(current)
                current = []
            saw_control = True
            index += 1
            continue
        # Like the reserved words below, these are special only where a command
        # name may start. Checking them everywhere refused `stat -f -c %T .`
        # and `find . -name x` outright, because `.` is the source builtin.
        # `export NAME=value` is an assignment that outlives the command, so it
        # gets the assignment vetting and nothing more: safe_assignment asks the
        # only question that matters -- can this name change what runs or how --
        # and the answer does not depend on how long the value lives. So
        # `export PATH=...` is refused here exactly as `PATH=... cmd` is.
        #
        # Only that shape is intercepted. `export -p`, `export -f fn`,
        # `export $x` and a bare `export NAME` (which re-exports a value we
        # never saw) are all something else, and fall through to REFUSED_WORDS
        # immediately below, which still lists export for them.
        if expect_command and token == "export":
            exported = exported_assignments(tokens, index + 1, total)
            if exported is not None:
                found, index = exported
                assignments.update(found)
                saw_assignment = True
                continue

        if token in REFUSED_WORDS and expect_command:
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
            # The word list is data, but every word must be a bare literal:
            # a variable or glob makes the iteration set unknown, and a word
            # that is (or splits into) a flag reaches the body unchecked.
            while index < total and tokens[index] not in ("do", ";"):
                word = tokens[index]
                if not safe_loop_word(word):
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
            assigned = ASSIGNMENT.match(token)
            if assigned:
                name, value = assigned.group(1), assigned.group(2)
                if (not safe_assignment(name, value)
                        and not (name == "IFS"
                                 and prefixes_read(tokens, index))):
                    return None, False
                assignments[name] = value
                saw_assignment = True
                index += 1
                continue  # still a command position: `A=1 B=2 cmd args`
            # `$cmd x` puts an unknown command in command position.
            if token.startswith("$") or token.startswith("-"):
                return None, False
            expect_command = False

        current.append(token)
        index += 1

    if current:
        commands.append(current)
    return commands, saw_control or saw_assignment


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


def touches_sandbox(segment):
    """True if any argument names a path inside the session scratchpad.

    Values fused into a flag count -- `--output=/tmp/.../scratchpad/f` -- which
    is exactly what outside_workspace above will not look at: it considers only
    tokens that START with `/` or `~`, so a fused path leaves the guard silent
    on a write it had just decided to permit. Silence is then betting that
    Claude Code's path gate does not notice the path either, and that is not a
    property this guard can check. Where it has made a judgement the allow
    rules cannot express -- `Bash(sort:*)` permits `sort -o /etc/passwd` just
    as happily -- it should say so and vouch.
    """
    for token in segment:
        candidates = [token, token.partition("=")[2]]
        # `-o/tmp/.../scratchpad/f`: a short flag with its value attached.
        if len(token) > 2 and token[0] == "-" and token[1] != "-":
            candidates.append(token[2:])
        if any(candidate and in_sandbox(candidate) for candidate in candidates):
            return True
    return False


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
    # `git -C dir rev-parse HEAD` is the same operation as `git rev-parse HEAD`
    # -- git's global options change where it looks, not what it does -- but a
    # prefix rule is literal text, so `Bash(git rev-parse:*)` misses it. Match
    # the subcommand form too. Safe only because segment_reasons above now
    # locates the subcommand past those options, so a write still asks first;
    # the directory itself is still checked by the workspace test.
    if segment[0] == "git" and len(segment) > 1:
        sub_at = git_subcommand_index(segment[1:])
        if sub_at:  # zero means no globals, already handled above
            normalized = " ".join(["git"] + segment[1 + sub_at:])
            if matches(normalized, deny)[0]:
                return False, False
            if matches(normalized, prefix)[0]:
                # Granted, not merely permitted. The plain path above can say
                # "no grant needed" because the rules matched the literal text
                # and will match it again; here they did NOT, and saying
                # nothing sends `git -C dir status` to a prompt on the strength
                # of a match we just made. Recognizing the command and then
                # withholding that is the one thing this guard must not do.
                return True, True
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
    """(start, end) of each outermost $(...) or unquoted <(...) the shell expands.

    Returns None -- meaning refuse -- for anything outside the supported subset:
    backticks, >(...) output process substitution, unbalanced quotes or parens.
    Every ambiguity resolves to None rather than to an empty list, so a command
    we cannot read confidently is declined instead of waved through.

    Escapes follow the shell: inside double quotes `\\$(...)` is a literal
    dollar and is correctly NOT reported as a substitution, while `\\\\$(...)`
    escapes the backslash and IS one.
    """
    spans, index, quote, depth, start = [], 0, None, 0, None
    # Quote state to restore when each `$(` closes. A substitution opens a
    # FRESH quoting context: in `"$(... '(a)' ...)"` the single quotes are
    # significant again, even though the `$(` itself sat inside double quotes.
    # Carrying the outer `"` inwards makes `'` look ordinary, so a `)` inside
    # single quotes closes the substitution early and everything after it is
    # misread.
    quote_stack = []
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

        if char == "`" or text.startswith(">(", index):
            return None
        # `<(cmd)` runs cmd and substitutes a /dev/fd path. Like $(...), the
        # result is data rather than syntax, so its only new risk is the
        # commands inside the parens -- which the recursion below reads. It is
        # a substitution only UNQUOTED: inside double quotes bash leaves the
        # text literal, so treating it as one there would inspect a string that
        # never runs. `>(cmd)` still refuses: that one is fed output, not read.
        proc_sub = quote is None and text.startswith("<(", index)
        if proc_sub or text.startswith("$(", index):
            if depth == 0:
                start = index
            depth += 1
            quote_stack.append(quote)
            quote = None
            index += 2
            continue
        # `quote is None` matters: a `)` inside double quotes is literal text,
        # not the end of the substitution. The single-quote branch above
        # `continue`s so it never reaches here, but the double-quote branch
        # falls through for ordinary characters -- so without this test,
        # `$(git log -S"Bash(uniq:*)")` closes at the quoted paren, and the
        # real `)` then reads as unbalanced and refuses the whole command.
        if char == ")" and depth and quote is None:
            depth -= 1
            quote = quote_stack.pop()
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


def analyze(text, prefix, deny, depth, roots=()):
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
        inner_ok, _ = analyze(text[start + 2:end - 1], prefix, deny,
                              depth + 1, roots)
        if not inner_ok:
            return False, False

    try:
        tokens = tokenize(strip_substitutions(text, spans))
    except ValueError:
        return False, False

    expanded, unrolled = expand(tokens)
    commands, saw_control = executable_commands(expanded)
    if commands is None:
        return False, False

    needs_grant = saw_control or unrolled or bool(spans)
    for segment in commands:
        if not segment:
            continue
        # A substitution in command position would run whatever it printed.
        if SUBST_PLACEHOLDER in segment[0]:
            return False, False
        if segment_reasons(segment):
            return False, False
        if segment[0] in NOOP_BUILTINS:
            continue
        if segment[0] == "set":
            if not set_is_noop(segment[1:]):
                return False, False
            # Vouched for like control flow: no prefix rule can express a
            # shell builtin, so leaving this to the rules means `set -o
            # pipefail` withdraws the grant from everything beside it.
            needs_grant = True
            continue
        permitted, was_local = segment_permitted(segment, prefix, deny)
        if not permitted:
            return False, False
        needs_grant = needs_grant or was_local
        # A path outside the workspace is a reason to speak up. Reads there are
        # wanted -- the point of this hook is to gate WRITES -- but the path
        # gate prompts for them, and it reads a leading-slash sed address like
        # `/addr/,/^}/p` as an absolute path. Granting suppresses that prompt
        # and costs nothing: a command matching an allow rule is already
        # permitted by the rules, and find_reasons runs first, so anything
        # write-capable has already become "ask" before we get here.
        if roots and outside_workspace(segment, roots):
            needs_grant = True
        if touches_sandbox(segment):
            needs_grant = True
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
    permitted, needs_grant = analyze(command, prefix, deny, 0,
                                     workspace_roots(cwd))
    return permitted and needs_grant


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
# Self-test:  ./bash-write-guard.py --test   (no `python3`: that always asks)
# ---------------------------------------------------------------------------


_CASES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "bash-write-guard-cases.py")


def _load_cases():
    """The test fixtures, from the sibling file that holds them.

    Imported here rather than at module scope, and only under --test: the
    decision path must never depend on a file that exists solely for testing.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("bash_write_guard_cases",
                                                  _CASES_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verdict(command, fixtures):
    """What the hook would emit for this command: ask / allow / silent."""
    if find_reasons(command):
        return "ask"
    permitted, needs_grant = analyze(command, fixtures.TEST_RULES, [], 0,
                                     fixtures.TEST_ROOTS)
    return "allow" if permitted and needs_grant else "silent"



def _raise_for_test():
    raise RuntimeError("simulated failure in the decision path")


def _fail_closed_ok():
    """Does a crash in the decision path still produce "ask"?

    This is the property that makes a broad `Bash(sed:*)` acceptable at all:
    the rules cannot tell `sed -n` from `sed -i`, so they permit both, and only
    this hook separates them. A hook that crashes silently hands the decision
    back to those rules -- which is why it must never crash silently.
    """
    import contextlib
    import io

    saved_decide, saved_argv = _decide, sys.argv
    try:
        globals()["_decide"] = _raise_for_test
        sys.argv = ["bash-write-guard.py"]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main()
        emitted = json.loads(buf.getvalue() or "{}")
        decision = emitted.get("hookSpecificOutput", {}).get("permissionDecision")
        return decision == "ask", decision
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        globals()["_decide"] = saved_decide
        sys.argv = saved_argv


def _missing_tables_ok():
    """Does an unloadable tables file still produce "ask"?

    Its own check because the first attempt at this got it wrong: _decide()
    raised on `T is None`, but a module-scope `T.AWK_LIKE` dereferenced the
    tables during import, long before _decide could run. That exits non-zero
    with no stdout -- fail-OPEN. Anything that reads T at module scope
    reintroduces exactly that, and only this notices.
    """
    import contextlib
    import io

    saved_tables, saved_argv = T, sys.argv
    try:
        globals()["T"] = None
        sys.argv = ["bash-write-guard.py"]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main()
        emitted = json.loads(buf.getvalue() or "{}")
        decision = emitted.get("hookSpecificOutput", {}).get("permissionDecision")
        return decision == "ask", decision
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        globals()["T"] = saved_tables
        sys.argv = saved_argv


def _selftest():
    if T is None:
        print(f"cannot load {_TABLES_FILE}: {TABLES_ERROR}")
        return 2
    try:
        fixtures = _load_cases()
    except Exception as exc:
        print(f"cannot load {_CASES_FILE}: {type(exc).__name__}: {exc}")
        return 2

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

    # A malformed WRAPPERS entry is the one bug that would fail silently: the
    # parser would refuse everything, or worse, mis-locate the command. Check
    # the shape here rather than discovering it from a missed prompt.
    wrapper_errors = []
    for name, spec in WRAPPERS.items():
        for key, kind in (("bool", (set, frozenset)), ("value", (set, frozenset)),
                          ("attached", bool), ("positional", tuple)):
            if key not in spec:
                wrapper_errors.append(f"WRAPPERS[{name!r}] is missing {key!r}")
            elif not isinstance(spec[key], kind):
                wrapper_errors.append(
                    f"WRAPPERS[{name!r}][{key!r}] should be {kind}, "
                    f"got {type(spec[key])}")
        for shape in spec.get("positional", ()):
            if not hasattr(shape, "match"):
                wrapper_errors.append(
                    f"WRAPPERS[{name!r}] positional entries must be compiled "
                    f"regexes; got {shape!r}")
        if set(spec) - {"bool", "value", "attached", "positional", "unknown_args"}:
            wrapper_errors.append(
                f"WRAPPERS[{name!r}] has unrecognized keys: "
                f"{sorted(set(spec) - {'bool', 'value', 'attached', 'positional'})}")
        # xargs was on this list for a different reason than the rest: not that
        # unwrapping it is unsound, but that its arguments are unreadable. That
        # is now represented (`unknown_args`) rather than avoided, so it moved.
        # These have no such answer -- nohup and script write, watch takes a
        # shell string, and sudo/su/env change what the command can do at all.
        if name in ("nohup", "script", "watch", "sudo", "su", "env"):
            wrapper_errors.append(
                f"WRAPPERS[{name!r}] must not be unwrapped: it writes, takes a "
                f"shell string, or changes identity. See the WRAPPERS comment.")

    fail_closed, fail_closed_got = _fail_closed_ok()
    tables_closed, tables_got = _missing_tables_ok()

    failed = []
    for group, cases in (("case", fixtures.CASES), ("gap", fixtures.GAPS)):
        for expected, command in cases:
            try:
                got = _verdict(command, fixtures)
            except Exception as exc:                  # a crash is a failure
                got = f"raised {type(exc).__name__}: {exc}"
            if got != expected:
                failed.append((group, expected, got, command))

    for group, expected, got, command in failed:
        label = "GAP CLOSED?" if group == "gap" else "FAIL"
        print(f"{label}  expected {expected}, got {got}\n          {command}")

    total = len(fixtures.CASES) + len(fixtures.GAPS)
    print(f"\n{total} cases ({len(fixtures.CASES)} behaviour, "
          f"{len(fixtures.GAPS)} known gaps), "
          f"{len(failed)} unexpected")
    for problem in wrapper_errors:
        print(f"WRAPPERS  {problem}")
    if not fail_closed:
        print(f"FAIL-OPEN  a crash in the decision path emitted "
              f"{fail_closed_got!r}, not 'ask'. The allow rules would then "
              f"decide alone, and they permit `sed -i` under Bash(sed:*).")
    if not tables_closed:
        print(f"FAIL-OPEN  an unloadable tables file emitted {tables_got!r}, "
              f"not 'ask'. Something reads T at module scope, so the import "
              f"dies before _decide() can turn it into a prompt.")

    if local_error:
        print(f"local_grants.py FAILS TO RUN -- every local grant is silently "
              f"lost: {local_error}")
    elif had_local:
        print("note: local_grants.py loads and runs; disabled for the cases above")
    return 1 if failed or local_error or wrapper_errors \
        or not fail_closed or not tables_closed else 0


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

    try:
        return _decide()
    except Exception as exc:
        # Fail CLOSED. Without this, a crash prints a traceback, emits no
        # decision, and leaves the allow rules to decide alone -- and those are
        # broad on purpose, because a prefix rule cannot tell `sed -n` from
        # `sed -i`. The whole reason `Bash(sed:*)` is acceptable is that this
        # hook vouches for it, so a hook that cannot run must not be silent.
        # Only the exception type is reported: the message could quote the
        # command, and this text is shown in the prompt.
        emit("ask", f"write-guard could not check this command and is not "
                    f"vouching for it ({type(exc).__name__})")
        return 0


def _decide():
    # Raised HERE, not at import: main()'s handler turns this into "ask", where
    # an uncaught import error would have exited silently and left the allow
    # rules to decide alone. Before guard_disabled() on purpose -- a guard that
    # cannot read its own tables should not be quietly switched off either.
    if T is None:
        raise RuntimeError(f"cannot load {_TABLES_FILE}: {TABLES_ERROR}")

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
