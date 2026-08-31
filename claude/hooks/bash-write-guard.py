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

# `git branch` is read-only except for the flags that delete, rename or move.
# -f/--force is the subtle one: `git branch -f name start` RESETS an existing
# branch to start, discarding where it pointed. It was missing here, so it was
# allowlisted by Bash(git branch:*) and produced no reason -- an unprompted
# write to a ref.
GIT_BRANCH_DESTRUCTIVE = {"-d", "-D", "--delete", "-m", "-M", "--move",
                          "-f", "--force", "-c", "-C", "--copy"}

# git subcommands that always write. Naming them makes the prompt say why, and
# stops a compound being granted because every OTHER command in it is read-only.
# Deliberately excludes subcommands with read-only forms (worktree list, remote
# show, stash list, reflog show, tag -l) rather than report something false
# about them -- and `fetch`, which left this set when it was allowlisted: see
# GIT_FETCH_WRITE_FLAGS for the forms that still ask.
GIT_WRITE_SUBCOMMANDS = {
    "checkout", "switch", "restore", "reset", "clean", "apply", "am",
    "rm", "mv", "commit", "merge", "rebase", "cherry-pick", "revert",
    "pull", "push", "clone", "init", "gc", "prune", "repack",
    "update-ref", "update-index", "write-tree", "commit-tree", "mktree",
    "filter-branch", "replace", "checkout-index", "sparse-checkout",
}
# `git config` reads in its query forms and writes in the rest. Three ways it
# writes: an explicit write flag, one of the newer write subcommands, or the
# bare `git config KEY VALUE` two-argument form, which sets with NO flag at all.
# That last one forces us to count positionals, which means every value-taking
# flag has to be consumed correctly -- so an unrecognized flag makes the count
# unprovable and counts as a write.
GIT_CONFIG_WRITE_FLAGS = {
    "--add", "--unset", "--unset-all", "--replace-all",
    "--rename-section", "--remove-section", "--edit", "-e",
}
GIT_CONFIG_WRITE_SUBCOMMANDS = {
    "set", "unset", "add", "edit", "rename-section", "remove-section",
}
GIT_CONFIG_READ_SUBCOMMANDS = {"get", "list"}
GIT_CONFIG_VALUE_FLAGS = {
    "-f", "--file", "--blob", "-t", "--type", "--default", "--comment",
}
GIT_CONFIG_BOOL_FLAGS = {
    "--global", "--system", "--local", "--worktree", "-z", "--null",
    "--name-only", "--show-origin", "--show-scope", "--includes",
    "--no-includes", "--fixed-value", "--all", "--regexp", "--no-type",
    "--list", "-l", "--get", "--get-all", "--get-regexp", "--get-urlmatch",
    "--bool", "--int", "--bool-or-int", "--path", "--expiry-date",
}
# git subcommands where one flag flips read into write, so an argument that
# begins with an expansion could be that flag.
# Subcommands driven by the diff machinery, which all accept --output. The
# literal flag is caught by GIT_OUTPUT_FLAG below, but a value the guard cannot
# read could BE that flag: `A=$(cat f); git log $A` was granted outright, and
# `--output=/tmp/x` there turns an allowlisted read into a file write. Listing
# them here makes an argument that begins with an expansion ask, exactly as it
# already did for sed and git branch.
GIT_DIFF_MACHINERY = {
    "log", "show", "diff", "format-patch", "range-diff", "whatchanged",
    "diff-tree", "diff-index", "diff-files",
}
GIT_FLAG_SENSITIVE = {"branch", "config", "fetch", "remote"} | GIT_DIFF_MACHINERY

# `git remote` reads in its bare, `show` and `get-url` forms and writes in all
# the rest. Unlike git config, the write is selected by a POSITIONAL rather than
# a flag, so the subcommand has to be located before anything can be said about
# it -- and only -v may legally precede it. Any other option and we cannot say
# which word is the subcommand, so it counts as a write. `set-url` is the one
# that earns this its own check: it silently repoints where a later push goes.
GIT_REMOTE_WRITE_SUBCOMMANDS = {
    "add", "rename", "remove", "rm", "set-head", "set-branches", "set-url",
    "prune", "update",
}
GIT_REMOTE_BOOL_FLAGS = {"-v", "--verbose"}

# `git fetch` usually only advances remote-tracking refs, so it is allowlisted
# rather than sitting in GIT_WRITE_SUBCOMMANDS. Two things make it write
# something you care about, and neither is visible from the subcommand name:
#
#   * a refspec with a destination -- `git fetch origin master:master` moves
#     your LOCAL master. On a shared base branch that is exactly the accident
#     the prompt is for.
#   * the flags below, which delete tracking refs (--prune), overwrite a
#     non-fast-forward (--force), or write config (--set-upstream).
#
# Enumerated rather than defaulting unknown flags to "write", following the
# GIT_BRANCH_DESTRUCTIVE precedent: nothing here counts positionals, so an
# unrecognized flag cannot throw the parse off.
GIT_FETCH_WRITE_FLAGS = {
    "-p", "--prune", "--prune-tags", "-f", "--force",
    "-u", "--update-head-ok", "--set-upstream", "--stdin", "--refmap",
}
# Value-taking flags whose value may legitimately contain a colon, e.g.
# `--filter blob:none`. Skipping the value stops the refspec test below from
# reading it as a destination.
GIT_FETCH_VALUE_FLAGS = {
    "--filter", "--depth", "--deepen", "--shallow-since", "--shallow-exclude",
    "--negotiation-tip", "--upload-pack", "--server-option", "-o", "-j",
    "--jobs",
}

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
CONTROL_KEYWORDS = {"do", "then", "elif", "else", "if", "fi", "done"}

# Builtins that only steer control flow or return a status. They touch nothing,
# take no path, and have no write form -- but they are builtins, so no `Bash(..)`
# rule can ever match them and `|| continue` silenced the guard on an otherwise
# read-only loop. Cleared without a rule for the same reason `for` is handled:
# there is no command for a rule to name.
NOOP_BUILTINS = {"continue", "break", "true", "false", ":"}

# Anything here means we refuse to reason about the command at all. Either it
# rewrites the execution environment (eval, export), or it is a construct
# outside the recognized subset (while, case), or it hides a command position.
REFUSED_WORDS = {
    "eval", "exec", "source", ".", "trap", "alias", "unalias", "command",
    "while", "until", "case", "esac", "select", "function", "coproc",
    "export", "declare", "typeset", "local", "set", "unset", "shift",
    "read", "mapfile", "readarray", "xargs", "env", "nohup", "sudo", "time",
}

# Commands where a single flag flips read into write, so an argument the guard
# cannot see through is a real hazard: `sed $(echo -i) s/a/b/ f` edits in place
# while every check above tests the token, not what it expands to. A flag has
# to start a token, so only an argument that BEGINS with an expansion can
# become one -- `sed -n "1,$(echo 5)p" f` never can.
FLAG_SENSITIVE = {"sed", "sort", "find"} | AWK_LIKE

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
            elif base in SED_BOOL_FLAGS or SED_INPLACE.match(token):
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


# git's own options sit BEFORE the subcommand, so `git -C dir reset --hard`
# puts `-C` where every check below looked for the subcommand name. reset,
# branch -D and the rest were producing no write reason at all; only the fact
# that `git -C ...` matches no allow rule was prompting them.
GIT_GLOBAL_BOOL = {
    "-p", "--paginate", "-P", "--no-pager", "--bare", "--no-replace-objects",
    "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
    "--icase-pathspecs", "--no-optional-locks",
}
GIT_GLOBAL_VALUE = {
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env",
}


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
RUFF_WRITE_FLAGS = {"--fix", "--fix-only", "-o", "--output-file"}
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
        return f"ruff {' '.join(hit)} rewrites files or writes a report"

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
        if base in GIT_GLOBAL_BOOL and "=" not in token:
            index += 1
        elif base in GIT_GLOBAL_VALUE:
            index += 1 if "=" in token else 2
        else:
            return None
    return index if index < len(rest) else None


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
            if base in GIT_FETCH_WRITE_FLAGS:
                return f"git fetch {base} writes local refs or config"
            if base in GIT_FETCH_VALUE_FLAGS and "=" not in token:
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


def git_remote_writes(args):
    """Reason `git remote <args>` changes a remote, or None if it only reads."""
    for arg in args:
        if not arg.startswith("-"):
            if arg in GIT_REMOTE_WRITE_SUBCOMMANDS:
                return f"git remote {arg} changes a configured remote"
            return None  # bare, `show` or `get-url`: reads only
        if arg not in GIT_REMOTE_BOOL_FLAGS:
            return ("git remote is passed an option the guard cannot size, so "
                    "its subcommand cannot be located")
    return None  # no subcommand at all: `git remote` / `git remote -v`


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
            if base in GIT_CONFIG_WRITE_FLAGS:
                return True
            if base in GIT_CONFIG_VALUE_FLAGS:
                index += 1 if "=" in token else 2
                continue
            if base in GIT_CONFIG_BOOL_FLAGS:
                index += 1
                continue
            return True  # unknown flag: the positional count is unprovable
        positionals.append(token)
        index += 1

    if positionals[:1] and positionals[0] in GIT_CONFIG_WRITE_SUBCOMMANDS:
        return True
    if positionals[:1] and positionals[0] in GIT_CONFIG_READ_SUBCOMMANDS:
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
    if name in ALWAYS_ASK and not tee_to_scratch:
        reasons.append(f"{name} {ALWAYS_ASK[name]}")

    if name == "sed" and any(SED_INPLACE.match(t) for t in rest):
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

    # Everything below wants the subcommand, which global options push right.
    sub_at = git_subcommand_index(rest) if name == "git" else None
    sub = rest[sub_at] if sub_at is not None else None
    sub_args = rest[sub_at + 1:] if sub_at is not None else []

    git_sub = sub in GIT_FLAG_SENSITIVE
    flag_args = sub_args if git_sub else rest
    if name in FLAG_SENSITIVE or git_sub:
        if any(a.startswith("$") or a.startswith(SUBST_PLACEHOLDER)
               for a in flag_args):
            reasons.append(f"{name} takes an argument from an expansion the "
                           f"guard cannot see, which could be a write flag")

    if name == "git":
        if rest and sub_at is None:
            # An option we cannot size, so the subcommand cannot be located and
            # none of the checks below can be trusted to have run.
            reasons.append("git is passed an option the guard cannot attribute "
                           "to a subcommand")
        if sub == "branch":
            hit = sorted(GIT_BRANCH_DESTRUCTIVE.intersection(sub_args))
            if hit:
                reasons.append(f"git branch {' '.join(hit)} deletes, renames "
                               f"or moves a branch")
        if sub in GIT_WRITE_SUBCOMMANDS:
            reasons.append(f"git {sub} writes")
        if sub == "fetch":
            why = git_fetch_writes(sub_args)
            if why:
                reasons.append(why)
        if sub == "remote":
            why = git_remote_writes(sub_args)
            if why:
                reasons.append(why)
        if sub == "config" and git_config_writes(sub_args):
            reasons.append("git config writes configuration")
        if any(GIT_OUTPUT_FLAG.match(token) for token in rest):
            reasons.append("git --output writes its output to a file")

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
                if not safe_assignment(name, value):
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
        if char == ")" and depth:
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

# A fixed rule set, so these expectations don't shift when settings.json gains
# or loses a rule. The point is to pin the guard's own logic, not the config.
_TEST_RULES = [(pattern, "test") for pattern in (
    "ls", "cd", "cat", "echo", "printf", "grep", "sed", "find", "sort", "awk",
    "diff",
    "head", "tail", "cut", "wc", "uniq", "tee", "paste", "bc", "systemctl",
    "ssh-add",
    "[", "test",
    "git log",
    "git branch",
    "git merge-base",
    "git grep", "git status", "git show", "git diff", "git rev-parse",
    "git rev-list", "git config", "git remote", "stat",
)]


_TEST_ROOTS = ("/workspace",)

# Built from the running uid rather than written out: SANDBOX_DIR pins the uid,
# so a literal here would have to carry this machine's, and this file is
# published. The project and session components are deliberately fictional.
_SANDBOX = f"/tmp/claude-{os.getuid()}/proj/session/scratchpad"


def _verdict(command):
    """What the hook would emit for this command: ask / allow / silent."""
    if find_reasons(command):
        return "ask"
    permitted, needs_grant = analyze(command, _TEST_RULES, [], 0,
                                     _TEST_ROOTS)
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
    # -f RESETS an existing branch to a new start point, discarding where it
    # pointed. Allowlisted by Bash(git branch:*) and previously unflagged.
    ("ask",    "git branch -f backup/pre-fix HEAD"),
    ("ask",    "git branch --force backup/pre-fix HEAD"),
    ("ask",    "git branch -c old new"),
    ("silent", "git branch --list"),
    ("silent", "git branch -a"),
    ("allow",  'echo "on: $(git branch --show-current)"'),
    # git subcommands that always write: not allowlisted, but say why
    ("ask",    "git checkout -q b31304ed6e19"),
    ("ask",    "git reset --hard HEAD~1"),
    ("ask",    "git clean -fd"),
    ("ask",    "git commit -m x"),
    ("ask",    "git push origin master"),
    ("ask",    'cd /workspace\ngit checkout -q abc123 && echo "at $(git rev-parse --short HEAD)"'),
    # ...and the read-only forms of mixed subcommands are left alone
    ("silent", "git worktree list"),
    ("silent", "git stash list"),
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
    # `$(` opens a fresh quoting context. Inside "$( ... )" a single quote is
    # significant again, so '(none)' is literal text -- carrying the outer `"`
    # inwards made that `)` close the substitution early and mangled the rest.
    ("allow",  'echo "$(grep -oE \'x[0-9]+\' f || echo \'(none)\')"'),
    # Same nesting, but `git log "$s"` now asks on the unreadable argument, so
    # this pins the quote handling with a subcommand that has no --output.
    ("allow",  'printf "%s %s" "$(git grep -c x "$s")" "$(git grep -l x "$s" | cut -c1-9)"'),
    ("ask",    'printf "%s" "$(git log -1 "$s")"'),
    ("ask",    'echo "$(tee /tmp/f || echo \'(none)\')"'),
    # ...and a substitution that is only literal text stays inert.
    ("silent", "echo '$(rm -rf /)'"),

    # -- constructs the guard cannot see through must ASK, never go silent -
    ("ask",    "echo `tee /tmp/f`"),              # backticks hide the write
    ("ask",    "cat <(tee /tmp/f)"),
    ("ask",    'echo "unterminated'),
    ("ask",    'echo "$(echo "$(echo "$(echo hi)")")"'),   # past depth cap
    # ...but a backtick or paren that is only literal text stays silent.
    ("silent", "grep -n '`' f"),
    ("silent", "echo 'use `cmd` here'"),
    ("silent", 'grep -c "(" f'),
    # the sed address is read as an absolute path by the path gate, so the
    # guard grants to suppress a prompt for what is only a read
    ("allow",  'sed -n "/a(/,/b)/p" f'),
    ("silent", "awk '{print $1}' f"),

    # -- control flow ------------------------------------------------------
    ("allow",  'for f in a b; do echo "$f"; done'),
    ("allow",  "if git merge-base --is-ancestor a b; then echo y; else echo n; fi"),
    # shlex treats '#' as a comment anywhere and would discard the rest of the
    # line -- verifying a command shorter than the one bash actually runs. If
    # commenters="" is ever dropped this becomes "allow", not merely "silent".
    ("ask",    "for c in a; do echo hi#; rm -rf /tmp/poc; done"),
    # An unknown iteration set is opaque, not forbidden: a glob cannot be read,
    # but the body then judges `$f` as the unknown value it is.
    ("allow",  'for f in *; do echo "$f"; done'),
    ("allow",  'for t in conf/*.toml; do cat "$t"; done'),
    ("ask",    "for f in conf/*; do sed $f x; done"),    # unknown value into sed
    ("ask",    "for f in -i; do sed $f x; done"),        # visibly a flag: refused
    # A loop word that is a flag reaches the body as `sed $f`, where every flag
    # check runs against the token rather than the value. Each of these was
    # granted as read-only and then wrote to a file. The word is substituted in
    # now, so the write is positively identified and named: "ask", not silence.
    ("ask",    "for f in -i; do sed $f 's/a/b/' data.txt; done"),
    ("ask",    "for f in -o; do sort $f out.txt in.txt; done"),
    ("ask",    "for f in -D; do git branch $f release-1; done"),
    ("ask",    "for f in -f; do awk $f prog.awk data.txt; done"),
    # an argument that BEGINS with an expansion could be anything, including a
    # write flag -- no loop required. This was live and uncaught.
    ("ask",    'sed $(echo "-i") s/a/b/ data.txt'),
    ("ask",    'sed "$(echo -i)" s/a/b/ data.txt'),
    ("ask",    "sort $(echo -o) out.txt in.txt"),
    ("ask",    "awk $(echo -f) prog.awk data.txt"),
    ("ask",    "git branch $(echo -D) release-1"),
    ("ask",    "for f in $(cat list); do sed $f x; done"),   # was gap 2
    ("ask",    'sed -n "$SCRIPT" data.txt'),                 # accepted loss
    # ...but an expansion with a literal in front of it cannot start a flag
    ("allow",  'sed -n "1,$(echo 5)p" f'),
    ("allow",  "for f in a.txt b.txt; do sed -n 1,5p $f; done"),
    ("allow",  'L=/tmp/x.log; sed -n 1,5p "$L"'),
    ("silent", 'grep -c "$s" f'),                  # grep has no write flag
    # git log DOES have one. This case asserted the opposite until `git log
    # --output=FILE` was run and produced a 524-byte file; every diff-machinery
    # subcommand accepts it. An unreadable "$sha" could be that flag, so the
    # idiom now costs a prompt -- the alternative is granting the hole.
    ("ask",    'git log -1 --format=%s "$sha"'),
    # ...and expansion is exact, so a read-only flag is no longer refused
    ("allow",  "for f in -n; do sed $f 1,5p data.txt; done"),
    ("allow",  "for f in -c; do grep $f pattern data.txt; done"),
    ("allow",  "for f in -i; do grep $f pattern data.txt; done"),
    # a loop that cannot be expanded, but whose word could be a flag, says so
    ("ask",    "for f in -i; do for g in a; do sed $f x; done; done"),
    # not expandable (the word would split), so `$f` survives into the body
    # and is caught there as an argument the guard cannot see through
    ("ask",    'for f in "a -i"; do sed $f x; done'),
    # ...while ordinary literal word lists keep working
    ("allow",  'for u in https://a.example/ https://b.example/; do echo "$u"; done'),
    ("allow",  "for c in 0fe44dfb28e2:495458 aedc918bcd:1234; do echo $c; done"),
    ("allow",  'for s in WRONG_COUNTS BAD_NODE; do git grep -c "$s" HEAD; done'),
    ("silent", "while true; do echo x; done"),
    ("silent", "case $x in a) echo 1;; esac"),

    # -- variable assignments ----------------------------------------------
    # Accepted only when the name cannot steer execution AND the value is a
    # bare literal -- no whitespace to word-split on, no glob character, no
    # leading dash. That is what makes an unquoted "$L" equal to the literal.
    ("allow",  "F=/tmp; ls $F"),
    ("allow",  'L=/tmp/x.log; tail -2 "$L"'),
    ("allow",  'L=/tmp/x.log; tail -2 "$L"; grep -c foo "$L"'),
    ("allow",  "D=/tmp; ls ${D}/sub"),
    ("allow",  "F=/tmp/a.log grep -c x /tmp/a.log"),      # prefix-form assign
    # names that decide WHAT runs, or HOW
    ("silent", "PATH=/evil ls"),
    ("silent", "GIT_EXTERNAL_DIFF=rm git diff HEAD"),     # would execute rm
    ("silent", "LD_PRELOAD=/tmp/x.so cat f"),
    ("silent", "IFS=. ls"),
    ("silent", "HOME=/tmp ls"),
    ("ask",    "BASH_ENV=/tmp/x sh -c date"),          # `sh` asks regardless
    ("silent", "PYTHONPATH=/tmp cat f"),
    ("silent", "http_proxy=http://x cat f"),              # matched uppercased
    # Values that are not bare literals are opaque, not forbidden: accepted,
    # left unsubstituted, and judged as `$L`. Only a value that is VISIBLY a
    # flag still refuses -- that is a positive identification.
    ("allow",  'L="a b"; cat $L'),                        # word-splits: harmless
    ("allow",  "L=*.c; ls $L"),                           # globs: harmless
    ("ask",    "L=-i; sed $L f"),                         # would become a flag
    ("ask",    'L="a -i"; sed $L f'),                     # flag in a later piece
    # `export NAME=value` is judged as the assignment it is. The value outlives
    # the command, but safe_assignment asks whether the NAME can steer what runs
    # -- and that answer does not depend on how long the value lives.
    ("allow",  "export FOO=bar"),                         # sets nothing that runs
    ("allow",  "export FOO=bar BAZ=qux; grep -c x f"),
    ("allow",  "export D=/workspace/d; grep -c x $D/f"),  # value still expands
    ("silent", "export PATH=/evil; ls"),                  # refused as a prefix is
    ("silent", "export LD_PRELOAD=/tmp/x.so; ls"),
    ("silent", "export GIT_EXTERNAL_DIFF=rm; git diff"),
    ("silent", "export IFS=x; ls"),
    ("ask",    "export FOO=-i; sed $FOO s/a/b/ f"),       # opaque, flag-sensitive
    ("ask",    "export FOO=bar; rm -rf /tmp/x"),          # the command still runs
    # shapes this does NOT model, left to REFUSED_WORDS
    ("silent", "export -p"),                              # a listing
    ("silent", "export -f fn"),                           # a function
    ("silent", "export $x"),                              # unknown name
    ("silent", "export FOO"),                             # re-exports an unseen value
    ("silent", "grep -n export f"),                       # argument, not a builtin
    # a value from $(...) is opaque, not forbidden: recorded as the placeholder
    # so a flag-sensitive command refuses it and everything else is fine
    ("allow",  'L=$(cat /tmp/p); cat "$L"'),
    ("ask",    'n=$(cat flags); sed $n f'),
    ("ask",    'n=$(cat flags); sed "$n" f'),      # quoting is no defence here
    ("ask",    'n=$(cat flags); sort $n a b'),
    ("allow",  'n=$(grep -c foo f); printf "%s\n" "$n"'),
    ("allow",  'n=$(wc -l f); echo "lines: $n"'),
    # a loop word may contain spaces; the pieces are what must not be flags
    ("allow",  'for s in "namespace os76" "register_elide"; do grep -c -F "$s" f; done'),
    ("allow",  'for s in "ftl::for_each" "label::SLOW"; do grep -rIl -F "$s" k t; done'),
    ("allow",  '''for s in "namespace os76" "a b"; do n=$(grep -c -F "$s" f); printf "%-20s %s\n" "$s" "$n"; done'''),
    ("silent", "L=; cat $L"),                             # empty
    # the value is substituted in, so the real command is what gets judged
    ("ask",    'L=/tmp/x; rm "$L"'),
    ("ask",    'L=/tmp/x; tee "$L"'),
    ("silent", "export PATH=x; ls"),
    ("silent", "eval ls"),
    # these three were "silent" until command wrappers joined ALWAYS_ASK;
    # "ask" is the stronger verdict, so the expectation moved, not the code
    ("ask",    "xargs rm"),
    ("ask",    "sudo ls"),
    ("ask",    "env FOO=1 ls"),
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
    # orchestrator asks on EVERY subcommand, reads included -- see the table.
    # These pin the ways a command word can arrive, since each bypasses a
    # different check: the bare name, an absolute path (basenamed by argv0_of,
    # and the only form that works here because ~/.local/bin is not on PATH),
    # behind a wrapper, inside a substitution, and behind an env prefix.
    ("ask",    "orchestrator whoami"),
    ("ask",    "orchestrator submit --branch users/me/x"),
    ("ask",    "/opt/local/bin/orchestrator whoami"),
    ("ask",    "timeout 60 orchestrator whoami"),
    ("ask",    'echo "$(orchestrator whoami)"'),
    ("ask",    "A=1 orchestrator whoami"),
    ("ask",    "ls -la && orchestrator whoami"),
    ("silent", "grep -n orchestrator f"),   # an argument is just an argument
    ("ask",    "patch -p1 < d.patch"),
    ("ask",    "python3 -c 'print(1)'"),
    ("ask",    "bash -c 'echo hi'"),
    # An interpreter always asks, with no exception carved out for our own
    # tools -- so the diagnostic tools are run directly instead. They keep a
    # shebang and the executable bit for exactly this reason, and a rule then
    # clears them. Otherwise why-prompt costs a prompt to explain a prompt.
    ("ask",    "python3 ~/.claude/tools/why-prompt.py ls"),
    ("silent", "~/.claude/tools/why-prompt.py ls"),

    # ssh-add changes agent state by DEFAULT, so listing is named and the rest
    # asks -- a bare invocation loads the default identities.
    ("silent", "ssh-add -l"),
    ("silent", "ssh-add -L"),
    ("silent", "ssh-add -l -E sha256"),        # -E takes a value
    ("ask",    "ssh-add"),                     # loads default identities
    ("ask",    "ssh-add -D"),
    ("ask",    "ssh-add -d ~/.ssh/id_ed25519"),
    ("ask",    "ssh-add -x"),
    ("ask",    "ssh-add ~/.ssh/id_ed25519"),
    ("ask",    "ssh-add -t 3600"),

    # systemctl reads and changes state under one name, and the write side is
    # the larger one -- so the READ side is named and everything else asks.
    # silent, not allow: nothing here needs a grant, so the rule decides.
    ("silent", "systemctl --user is-active ssh-auth-sock.timer"),
    ("silent", "systemctl --user list-timers --no-pager"),
    ("silent", "systemctl -p MainPID show foo"),   # value flag before the sub
    ("silent", "systemctl"),                       # bare: lists units
    ("ask",    "systemctl --user restart foo"),
    ("ask",    "systemctl --user enable --now foo"),
    ("ask",    "systemctl daemon-reload"),
    ("ask",    "systemctl --user stop foo"),
    ("ask",    "systemctl --bogus is-active foo"), # option: cannot attribute

    # paste and bc write nothing: every paste flag goes to stdout, and bc's
    # language has no file output and no shell escape -- unlike awk, which is
    # why AWK_LIKE needs a check and these do not. Blockers inside a $(...) do
    # not show up as segments, so this shape is easy to misread.
    ("allow",  "echo \"$(cut -d: -f2 f | paste -sd+ | bc)\""),

    # A redirection is not an argument. Any check that counts positionals saw
    # `2>&1` as two of them, so these ordinary reads reported writes.
    ("silent", "uniq -c f 2>&1"),
    ("silent", "git config user.name 2>/dev/null"),
    ("ask",    "uniq a b"),                      # still counted when real
    ("ask",    "git config user.name Henry"),
    ("ask",    "echo hi > f 2>&1"),              # the redirect itself still asks

    # ruff lints (read) and formats/fixes (write) under one command name.
    ("silent", "ruff check --select E9,F --no-cache f.py"),
    ("silent", "ruff format --check f.py"),
    ("silent", "ruff format --diff f.py"),
    ("ask",    "ruff check --fix f.py"),
    ("ask",    "ruff check --fix-only f.py"),
    ("ask",    "ruff format f.py"),
    ("ask",    "ruff clean"),
    ("ask",    "ruff check -o report.json f.py"),
    ("ask",    "ruff --config x.toml format f.py"),   # sub behind a value flag
    ("ask",    "ruff server"),

    # A session scratchpad is disposable, so a write PROVABLY landing in one is
    # not worth a prompt. Provably means absolute and literal: a relative path
    # depends on a cwd an earlier `cd` may have changed, and `$P/f` is not a
    # path we have read. Deletion is never sandboxed.
    ("allow",  f"echo hi > {_SANDBOX}/notes.md"),
    ("allow",  f"uniq {_SANDBOX}/a {_SANDBOX}/b"),
    ("ask",    "echo hi > /tmp/other.txt"),
    ("ask",    "echo hi > notes.md"),            # relative: cwd unprovable
    ("ask",    'echo hi > "$P/notes.md"'),       # variable: not read
    ("ask",    f"echo hi > {_SANDBOX}/../../../../etc/x"),
    ("ask",    f"rm -rf {_SANDBOX}/f"),          # deletion still asks
    # sed -i and tee name their targets in argv, so they are sandboxed too --
    # all or nothing: one target outside the scratchpad and the whole command
    # asks, since a partial write is not a partial risk.
    ("allow",  f"sed -i s/a/b/ {_SANDBOX}/f"),
    ("allow",  f"echo x | tee {_SANDBOX}/f"),
    ("allow",  f"echo x | tee -a {_SANDBOX}/f {_SANDBOX}/g"),
    ("ask",    "sed -i s/a/b/ /etc/passwd"),
    ("ask",    f"sed -i s/a/b/ /etc/passwd {_SANDBOX}/f"),
    ("ask",    "sed -i -e s/a/b/ /etc/passwd"),  # script from a flag
    ("ask",    "sed -i s/a/b/ f.txt"),           # relative: cwd unprovable
    ("ask",    f"echo x | tee {_SANDBOX}/f /etc/passwd"),
    ("ask",    f"sed --bogus -i s/a/b/ {_SANDBOX}/f"),   # unknown flag
    ("ask",    f"echo x | tee --bogus {_SANDBOX}/f"),
    ("ask",    "echo hi > /tmp/claude-99999999/p/s/scratchpad/f"),  # other uid

    # uniq's SECOND positional is an output file it overwrites, so the tool is
    # not unconditionally read-only even though it reads like a filter.
    ("silent", "uniq -c f"),
    ("silent", "sort f | uniq -c"),
    ("silent", "uniq -f2 f"),
    ("silent", "uniq"),
    ("ask",    "uniq a b"),
    ("ask",    "uniq -c in.txt out.txt"),
    ("ask",    "uniq --bogus f"),          # unknown flag: count unprovable
    ("allow",  'P=/workspace/d; sort "$P/f" | uniq -c | head -3'),

    # git's global options sit BEFORE the subcommand, so `-C dir` was landing
    # where every git check looked for it. These produced no reason at all.
    ("ask",    "git -C /tmp/x reset --hard"),
    ("ask",    "git -C /tmp/x branch -D main"),
    ("ask",    "git --git-dir=/tmp/x/.git fetch --prune origin"),
    ("ask",    "git --bogus-opt log"),          # unsizeable option: cannot attribute
    ("allow",  "git -C /tmp/x rev-parse HEAD"), # same op as `git rev-parse`
    # A directory INSIDE the workspace is the case that exposed the second half
    # of this: the normalized match was made and then dropped as "no grant
    # needed", so the prompt came anyway. The cases above passed regardless,
    # because a path outside the workspace sets needs_grant by another route.
    ("allow",  "git -C /workspace/d status --short"),
    ("allow",  "git -C /workspace/d diff claude/settings.json"),
    ("allow",  "git -C /workspace/d log --oneline -1"),
    ("ask",    "git -C /workspace/d push origin master"),   # still a write
    ("ask",    "git -C /workspace/d remote set-url origin git@x:y.git"),
    # `continue` and friends are builtins, so no rule can ever name them.
    ("allow",  'for f in a b; do [ -e "$f" ] || continue; cat "$f"; done'),

    # xargs takes its arguments from stdin but its COMMAND from argv, and it
    # never re-parses stdin as shell syntax -- so the command can be read, with
    # the arguments marked unknown.
    ("allow",  "grep -rl alloy conf/*.toml | head -1 | xargs cat"),
    ("allow",  "xargs -0 grep -c x"),
    ("allow",  "xargs -I{} cat {}"),
    ("ask",    "xargs rm < list"),
    ("ask",    "xargs -n 1 rm"),                  # value flag consumed, rm found
    ("ask",    "xargs sed -i s/a/b/"),
    ("ask",    "xargs sed s/a/b/"),               # stdin could supply -i
    ("ask",    "xargs --bogus cat"),              # unknown flag: stays wrapped
    ("ask",    "xargs"),                          # no command to attribute
    ("ask",    "xargs timeout 5 rm"),

    # `<(cmd)` substitutes a /dev/fd path, so like $(...) its only new risk is
    # the commands inside. `diff <(a) <(b)` is the whole reason to read it.
    ("allow",  "diff <(git log -1 aa) <(git log -1 bb) | head -30"),
    ("allow",  "diff <(sort a) <(sort b)"),
    ("ask",    "diff <(rm -rf /tmp/x) f"),        # inner write still caught
    ("ask",    "diff <(git log $A) f"),           # and so is a smuggled flag
    ("silent", 'echo "<(rm -rf x)"'),             # quoted: literal, never runs
    ("ask",    "cat > >(tee /tmp/f)"),            # >(...) is fed output: refused
    ("ask",    "diff `git show a` f"),            # backticks still refused

    # An unreadable value reaching the diff machinery could BE --output, which
    # turns an allowlisted read into a file write. These were granted outright.
    ("ask",    'A=$(cat f); git log $A'),
    ("ask",    'A=$(cat f); git diff $A'),
    ("ask",    'A=$(cat f); git show $A'),
    ("ask",    'A=$(cat f); git format-patch $A'),
    # ...but a `for` word is expanded to its literal first, so it still clears.
    ("allow",  "for s in aa bb; do git log -1 --format=%h $s; done"),

    # `git fetch` is allowlisted, so the guard is the ONLY thing standing
    # between a plain fetch and one that moves a local branch.
    ("silent", "git fetch origin feature/one feature/two"),
    ("silent", "git fetch --all"),
    ("silent", "git fetch -q --depth 1 origin main"),
    ("silent", "git fetch --filter blob:none origin main"),   # value, not refspec
    ("silent", "git fetch --filter=blob:none origin main"),
    ("ask",    "git fetch origin master:master"),             # writes LOCAL master
    ("ask",    "git fetch --prune origin"),
    ("ask",    "git fetch -p origin"),
    ("ask",    "git fetch --set-upstream origin"),            # writes config
    ("ask",    "git fetch --force origin a:b"),
    ("ask",    "git fetch --refmap=+refs/heads/*:refs/heads/* origin"),
    ("ask",    "git fetch git@host:repo.git"),                # deliberate over-ask
    ("ask",    'git fetch origin "$SPEC"'),                   # refspec via expansion
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
    # A bare `{` is the same trap as `do`: it sits where argv0 belongs, so a
    # brace group hid every write inside it from the checks below. Only the
    # rule gate was prompting these -- the guard's own answer said nothing.
    ("ask",    "{ rm -rf /tmp/x; }"),
    ("ask",    "{ sed -i s/a/b/ f; }"),
    ("ask",    "true || { sed -i s/a/b/ f; }"),
    ("ask",    "{ timeout 5 rm -rf /tmp/x; }"),   # unwrapped inside the group
    ("ask",    "{ echo a; } > /tmp/f"),           # redirect on the group itself
    # Grouping adds no capability, so a read-only group is grantable.
    ("allow",  "grep -c x f || { echo no; tail -2 f; }"),
    ("allow",  "F=/tmp/out\ngrep -q x \"$F\" 2>/dev/null || { echo no; tail -2 \"$F\"; }"),
    # Only a BARE brace in command position is a group: brace expansion is one
    # token, a brace where no command can start means we misread the line, and
    # a function definition aborts on its parentheses.
    ("silent", "echo {a,b}"),
    ("silent", "echo a }"),
    ("silent", "f() { rm -rf x; }"),
    # ...but only LEADING keywords are stripped: as an argument it still scans.
    ("ask",    "find . -name done -delete"),
    ("silent", "cat done"),
    ("silent", "grep -n then f"),
    ("silent", "grep -n for f"),
    # REFUSED_WORDS is gated on command position, like bash's own reserved
    # words: as a plain argument the word is just an argument.
    ("silent", "grep -n while f"),
    ("silent", "ls eval"),
    ("silent", "echo export PATH=x"),
    ("allow",  'echo "$(grep -c eval f)"'),
    # `.` is the source builtin only in command position; as an argument it is
    # the current directory, and checking it everywhere refused these outright.
    ("allow",  'echo "fs: $(stat -f -c %T .)"'),
    ("ask",    "find . -name x $(echo -delete)"),
    ("ask",    "for f in -delete; do find . -name x $f; done"),

    # -- command wrappers hide the real argv0 from every write check ---------
    # Safe today only because none are allowlisted; allowlisting `timeout`
    # would have let `timeout 30 rm -rf x` through with no prompt at all,
    # because nothing about it needs a grant.
    ("ask",    "timeout 30 rm -rf /tmp/x"),
    ("ask",    "nice rm -rf /tmp/x"),
    ("ask",    "stdbuf -o0 rm -rf /tmp/x"),
    ("ask",    "setsid rm -rf /tmp/x"),
    ("ask",    "flock /tmp/l rm -rf /tmp/x"),
    ("ask",    "watch rm -rf /tmp/x"),
    ("ask",    "env rm -rf /tmp/x"),
    ("ask",    "sudo rm -rf /tmp/x"),
    # `timeout [OPTION] DURATION COMMAND` parses, so the wrapper is removed and
    # the real command is judged. curl is simply not allowlisted -> the rules
    # decide, which is a prompt, but no longer timeout's doing.
    ("silent", "timeout 30 curl -s -o /dev/null https://example.invalid"),
    ("silent", 'for u in a b; do timeout 5 curl -s "$u"; done'),
    ("ask",    "timeout 40 rm -rf /tmp/x"),               # caught as rm
    ("ask",    "timeout 40 sed -i s/a/b/ f"),             # caught as sed -i
    ("ask",    "timeout -k 5 40 rm -rf /tmp/x"),          # flags consumed
    ("ask",    "timeout --signal=KILL 40 tee /tmp/f"),
    ("allow",  "timeout 40 grep -c x f"),                 # read-only, granted
    ("allow",  "timeout 5 wc -l f"),
    ("allow",  "timeout 1.5s grep -c x f"),
    ("allow",  "timeout --foreground 40 grep -c x f"),
    ("allow",  'for f in a b; do timeout 5 grep -c x "$f"; done'),
    # a prefix that will not parse keeps the wrapper, and ALWAYS_ASK catches it
    ("ask",    "timeout --bogus 40 grep -c x f"),         # unknown flag arity
    ("ask",    "timeout notaduration grep -c x f"),       # duration check fails
    ("ask",    "timeout 40 $CMD -c x f"),                 # unknown command
    # `--` ends the options, and per `timeout [OPTION] DURATION COMMAND` it
    # must precede DURATION -- after it, `--` would BE the command name.
    ("allow",  "timeout -- 5 grep -c x f"),
    ("ask",    "timeout -- 5 rm -rf /tmp/x"),
    ("ask",    "timeout 5 -- grep -c x f"),   # invalid for timeout; not unwrapped
    # wrappers nest: the command position is re-examined after each removal
    ("allow",  "timeout 5 timeout 3 grep -c x f"),
    ("ask",    "timeout 5 timeout 3 rm -rf /tmp/x"),
    # an environment prefix does not end the command position, so the wrapper
    # behind it is still unwrapped. Getting this wrong made `VAR=x timeout N cmd`
    # ask for the wrapper's sake and silently voided a grant on cmd.
    ("allow",  "A=1 timeout 5 grep -c x f"),
    ("allow",  "A=1 B=2 timeout 5 grep -c x f"),
    ("ask",    "A=1 timeout 5 rm -rf /tmp/x"),   # the real command still caught
    ("ask",    "A=1 timeout 5 sed -i s/a/b/ f"),
    ("silent", "PATH=/evil timeout 5 grep -c x f"),  # unsafe name still refused
    # only in command position: an argument that looks like one is an argument
    ("silent", "grep -n A=1 f"),
    # the other wrappers stay opaque on purpose
    ("ask",    "nice 40 grep -c x f"),
    ("ask",    "stdbuf -o0 grep -c x f"),
    # the wrapper name as an argument is still just an argument
    ("silent", "grep -n timeout f"),
    ("silent", "git log --oneline --grep=timeout"),

    # -- allowlisted git subcommands are not unconditionally read-only -----
    ("ask",    "git diff --output=/tmp/d HEAD~1"),
    ("ask",    "git log --output /tmp/l"),
    ("silent", "git diff --stat HEAD~1"),
    ("silent", "git log --oneline -3"),

    # -- git config: reads are fine, and one write form has no flag at all ---
    ("silent", "git config --get user.email"),
    ("silent", "git config user.email"),               # one arg reads
    ("silent", "git config --list"),
    ("silent", "git config get user.email"),           # newer read subcommand
    ("silent", "git config --file cfg --get user.email"),
    ("silent", "stat -f -c %T ."),
    ("allow",  'echo "$(git config --get user.email)"'),
    ("allow",  'echo "fs: $(stat -f -c %T .)"'),
    ("ask",    "git config user.email a@b.c"),         # two args SETS
    ("ask",    "git config --file cfg user.email a@b.c"),
    ("ask",    "git config --add user.email a@b.c"),
    ("ask",    "git config --unset user.email"),
    ("ask",    "git config --unset-all user.email"),
    ("ask",    "git config --replace-all core.editor vim"),
    ("ask",    "git config --remove-section alias"),
    ("ask",    "git config --rename-section old new"),
    ("ask",    "git config --edit"),
    ("ask",    "git config set user.email a@b.c"),     # newer write subcommand
    ("ask",    "git config unset user.email"),
    ("ask",    "git config --bogus user.email"),       # arity unknown -> unprovable
    # `git remote`: the write is chosen by a positional, not a flag
    ("silent", "git remote"),
    ("silent", "git remote -v"),
    ("silent", "git remote show origin"),
    ("silent", "git remote get-url origin"),
    ("allow",  'echo "$(git remote -v)"'),
    ("ask",    "git remote add origin git@example.com:x/y.git"),
    ("ask",    "git remote set-url origin git@example.com:z/w.git"),
    ("ask",    "git remote remove origin"),
    ("ask",    "git remote rename origin upstream"),
    ("ask",    "git remote set-head origin -a"),
    ("ask",    "git remote set-branches origin master"),
    ("ask",    "git remote prune origin"),
    ("ask",    "git remote update"),
    ("ask",    "git remote -v add origin git@example.com:x/y.git"),
    ("ask",    "git remote --bogus show origin"),      # cannot locate the subcommand
    ("ask",    "git remote $SUB origin"),              # could expand to set-url
    # an argument beginning with an expansion could be --unset, and unquoted it
    # would even word-split into `--unset user.email`
    ("ask",    "git config $(echo --unset) user.email"),
    ("ask",    'git config --get "$(echo --unset)"'),

    # -- plain commands: the rules decide, the hook keeps quiet ------------
    ("silent", "ls -la"),
    ("silent", "grep -n foo f | head -3"),
    ("silent", "cat f | wc -l"),

    # -- out-of-workspace reads --------------------------------------------
    # Reads outside the workspace are wanted; the path gate prompts for them.
    # Granting suppresses that, and adds no write risk: the command already
    # matches an allow rule, and anything write-capable became "ask" earlier.
    ("allow",  "ls -d /etc"),
    ("allow",  "cd /workspace\nsed -n '/GatewayError.*Corrupt/,/^}/p' f | head -10"),
    ("allow",  'grep -c foo /etc/hosts'),
    ("ask",    "rm -rf /etc/x"),               # write anywhere still asks
    ("ask",    "tee /etc/x"),
    ("silent", "curl -s /etc/hosts"),          # not allowlisted -> rules decide

    # -- newlines separate commands -----------------------------------------
    # shlex treats a newline as whitespace under whitespace_split, so two
    # commands on two lines collapsed into one whose argv0 was the FIRST one.
    # The second became an argument, the segment matched the first command's
    # rule, and a substitution anywhere made the whole thing grantable.
    ("ask",    'echo "$(echo hi)"\nrm -rf /tmp/x'),
    ("ask",    "ls\nrm -rf /tmp/x"),
    ("ask",    'echo "$(echo hi)"\nsed -i s/a/b/ f'),
    ("ask",    "grep -n x f\ntee /tmp/out"),
    ("allow",  'cd /tmp\nF=/tmp/x.log\necho "=== size ==="; wc -l $F'),
    ("silent", "ls -la\nls -l sub/dir"),      # in-workspace: nothing to say
    ("allow",  "ls -la\nls -l /tmp"),         # /tmp is outside -> grant
    # a newline inside quotes is data, and a backslash-newline joins lines
    ("silent", 'echo "line1\nline2"'),
    ("silent", "grep -c 'a\nb' f"),
    ("allow",  'F=/tmp/x.log\nwc -l \\\n  "$F"'),
]

# Known gaps, asserted at their CURRENT behavior so they are written down
# rather than rediscovered. Each is a shape where a write-capable flag reaches
# an allowlisted tool through data the guard cannot read. Closing one makes the
# assertion below fail -- that is the reminder to move it into _CASES.
_GAPS = [
    # Empty. Both original entries were closed by expanding literal loop words
    # and by treating an argument that begins with an expansion as opaque.
    # Keep the list and its handling: the next gap wants writing down, not
    # rediscovering.
]


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
    for problem in wrapper_errors:
        print(f"WRAPPERS  {problem}")
    if not fail_closed:
        print(f"FAIL-OPEN  a crash in the decision path emitted "
              f"{fail_closed_got!r}, not 'ask'. The allow rules would then "
              f"decide alone, and they permit `sed -i` under Bash(sed:*).")

    if local_error:
        print(f"local_grants.py FAILS TO RUN -- every local grant is silently "
              f"lost: {local_error}")
    elif had_local:
        print("note: local_grants.py loads and runs; disabled for the cases above")
    return 1 if failed or local_error or wrapper_errors \
        or not fail_closed else 0


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
