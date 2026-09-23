"""What bash-write-guard.py knows about individual tools -- data only.

Every entry answers one question: which flags, subcommands or patterns turn a
read into a write. The reasoning for each lives beside it, because the reason a
set has the members it does is the part that goes stale.

Loaded by the guard at import as `T`, and required: a decision cannot be made
without it, so a failure to load here makes the guard emit "ask" rather than
letting the allow rules decide alone. Nothing in this file imports the guard.
"""

import re

# This repo's own read-only tools, granted by path: the settings rules spell
# them with `~`, and a prefix rule is literal text, so the absolute spelling
# matches nothing. The guard resolves these. A name that cannot be published
# belongs in local_grants.py instead.
OWN_TOOLS = frozenset({
    "~/.claude/hooks/bash-write-guard.py",
    "~/.claude/hooks/comment-ratio-gate.py",
    "~/.claude/hooks/commit-message-gate.py",
    "~/.claude/hooks/review-text-gate.py",
    "~/.claude/tools/why-prompt.py",
    "~/.claude/tools/why-prompted.py",
    "~/.claude/tools/guard-verdict.py",
    "~/.claude/tools/check-settings.py",
    "~/.claude/tools/comment-ratio.py",
    "~/.claude/tools/transcript_cost.py",
})

# `env` with no COMMAND prints the environment. Only these boolean flags are
# recognised: a value-taking flag (-u, -C, -S) would have to be counted
# correctly to know where the COMMAND starts, and -S carries one outright.
ENV_READ_LETTERS = set("i0v")
ENV_READ_LONG = frozenset({
    "--ignore-environment", "--null", "--debug", "--help", "--version",
    "--list-signal-handling",
})

FIND_WRITE_FLAGS = {
    "-exec", "-execdir", "-delete", "-ok", "-okdir",
    "-fprintf", "-fls", "-fprint", "-fprint0",
}
# sed short flags bundle, and -i takes an optional suffix: -i -i.bak -ni -sni
SED_INPLACE = re.compile(r"^-[A-Za-z]*i|^--in-place")
# Flags that name a file the command WRITES, per tool, so every spelling one
# tool accepts is reviewable beside the others. They are all read by the same
# extractor, which is the point: --output-directory was missed for months
# because git's spellings lived in a regex of their own, and sort's and ruff's
# targets were never checked against the scratchpad at all.
#
# Only flags that name an OUTPUT belong here. ruff --fix rewrites the source
# files it was pointed at, which no output path makes disposable, so it stays
# with the flags that write unconditionally.
SORT_OUTPUT_FLAGS = {"-o", "--output"}
RUFF_OUTPUT_FLAGS = {"-o", "--output-file"}

# `file` reads magic bytes -- except -C/--compile, which WRITES a pre-parsed
# magic.mgc beside the magic file named by -m. Not in OUTPUT_FLAGS above
# because the path is DERIVED from -m rather than given, so there is no target
# to prove disposable; it simply asks. Uppercase only: -c prints the parsed
# form of the magic file and writes nothing.
FILE_COMPILE_FLAGS = {"-C", "--compile"}

# Interpreter flags that cannot introduce code and cannot outlive the script:
# they tune bytecode writing, buffering, site imports and optimization. Clusters
# are allowed, so `-uB` is read letter by letter.
#
# Everything absent refuses, and four in particular must: -c takes code, -m
# takes a module, -i keeps the interpreter alive after the script, and a bare
# `-` reads the program from stdin. -W and -X are absent only because they take
# values, which is enough reason not to guess.
PYTHON_SAFE_FLAG_LETTERS = set("BEIOPSbdqsuvx")

# `date` prints, except `-s` and the bare `MMDDhhmm` operand of its second usage
# form, which set the system clock. Read flags are allowlisted rather than -s
# refused because short options cluster: `-Is` is -I carrying its optional
# argument, so any "does this cluster contain s" test rejects the commonest
# read there is.
DATE_BOOL_FLAGS = {"-R", "-u", "--utc", "--universal", "--rfc-email",
                   "--debug", "--help", "--version"}
DATE_VALUE_FLAGS = {"-d", "--date", "-f", "--file", "-r", "--reference"}
# -I/--iso-8601 and --rfc-3339 carry their argument attached, if at all.
DATE_ATTACHED_PREFIXES = ("-I", "--iso-8601", "--rfc-3339=", "--date=",
                          "--file=", "--reference=")

# awk is a language, not a filter: it can redirect and shell out from inside
# the program text, where shlex has already stripped the quotes that hid it.
AWK_LIKE = {"awk", "gawk", "mawk", "nawk"}
AWK_WRITE = re.compile(r"system\s*\(|\bprintf?\s*>|>\s*[\"']|\|\s*[\"']")

# Commands where a single flag flips read into write, so an argument the guard
# cannot see through is a real hazard: `sed $(echo -i) s/a/b/ f` edits in place
# while every check tests the token, not what it expands to. A flag has to
# start a token, so only an argument that BEGINS with an expansion can become
# one -- `sed -n "1,$(echo 5)p" f` never can.
#
# Lives here rather than in the guard because it is built from AWK_LIKE: as a
# module-scope `T.AWK_LIKE` in the guard it dereferenced the tables before
# _decide() could check they had loaded, which turned a missing tables file
# into a silent fail-OPEN. Derived tables belong beside what they derive from.
FLAG_SENSITIVE = {"sed", "sort", "find"} | AWK_LIKE

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
# shortlog is NOT diff machinery -- it has its own option parser -- but it takes
# the same --output, so an expansion in its arguments carries the same risk.
# Kept out of the set above so that name stays true to what it names.
GIT_FLAG_SENSITIVE = ({"branch", "config", "fetch", "remote", "ls-remote",
                       "shortlog", "archive", "bundle"}
                      | GIT_DIFF_MACHINERY)

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

# `git ls-remote` lists refs on a remote and writes nothing on this machine, so
# it is allowlisted rather than sitting in GIT_WRITE_SUBCOMMANDS. Two of its
# flags are not a lookup: --upload-pack names a program for the REMOTE to run,
# and --server-option hands the server an opaque instruction to act on. Neither
# can touch this machine, and a server is free to refuse both -- but they stop
# the command being the plain ref lookup the allow rule implies, and "the other
# end decides" is not a property this guard can verify.
#
# Enumerated rather than defaulting unknown flags to "write": nothing here
# counts positionals, so an unrecognized flag cannot throw the parse off. Same
# reasoning as GIT_FETCH_WRITE_FLAGS.
GIT_LS_REMOTE_ASK_FLAGS = {"--upload-pack", "-o", "--server-option"}

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
# --output-directory is format-patch's spelling and writes a whole directory of
# patches. Listed exactly rather than matched as a --output prefix because git
# does NOT accept abbreviated long options -- `--out=`, `--outp=` and
# `--outpu=` are all rejected outright (measured), so there is no shorter
# spelling to catch, and a prefix would swallow unrelated `--output*` options.
GIT_OUTPUT_FLAGS = {"--output", "--output-directory"}

# `-o` is the same write in two subcommands -- `git archive -o f.tar` and
# `git format-patch -o dir/` -- but it is NOT a write everywhere: it is
# --server-option for ls-remote and push, and the remote's name for clone. So
# it is scoped by subcommand rather than folded into GIT_OUTPUT_FLAGS.
GIT_SHORT_OUTPUT_SUBCOMMANDS = {"archive", "format-patch"}
GIT_SHORT_OUTPUT_FLAGS = {"-o"}

# `git archive` streams to stdout and is a read -- until -o/--output names a
# file. --exec names the program git runs on the REMOTE end, which is the same
# "the other end decides" that GIT_LS_REMOTE_ASK_FLAGS refuses to vouch for.
GIT_ARCHIVE_ASK_FLAGS = {"--exec"}

# `git bundle` dispatches on a positional like `git remote` does. create writes
# a bundle file named by the next positional -- no flag involved, so nothing
# else in this hook would catch it -- and unbundle writes objects and refs into
# the repository. verify and list-heads only read.
GIT_BUNDLE_WRITE_SUBCOMMANDS = {"create", "unbundle"}
GIT_BUNDLE_READ_SUBCOMMANDS = {"verify", "list-heads"}
GIT_BUNDLE_BOOL_FLAGS = {"-q", "--quiet", "--progress"}

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
# Global options that make git print something and exit without ever reaching
# a subcommand, so "cannot attribute this option to a subcommand" is the wrong
# complaint: there is no subcommand to attribute it to.
GIT_TERMINAL_OPTIONS = {
    "-v", "--version", "-h", "--help",
    "--exec-path", "--html-path", "--man-path", "--info-path",
}
# Only these may precede one, and only in their bare form.
GIT_PAGER_OPTIONS = {"-p", "--paginate", "-P", "--no-pager"}

# `command` exists to run something while bypassing functions and aliases, so
# it hides a command position and asks. Its two lookup flags are the exception:
# -v prints how the shell would resolve a name and -V describes it, and NEITHER
# executes anything. That is `which` with a builtin instead of a subprocess.
# -p only swaps in the default PATH, so it is accepted alongside them but
# vouches for nothing on its own. Letters are matched one at a time because
# bash clusters them (`command -pv ruff`), and an unrecognized letter means a
# form nobody here has reasoned about -- which might well execute.
COMMAND_FLAG_LETTERS = set("pvV")
COMMAND_LOOKUP_LETTERS = set("vV")

# ssh runs an arbitrary command on another machine, so it sits in ALWAYS_ASK and
# the tables below are its one exemption. They enumerate rather than skip,
# because ssh's OWN flags act LOCALLY before the remote command is reached:
#   -o ProxyCommand=/-o LocalCommand= run a local program
#   -E writes a local log file
#   -L -R -D -W -w open tunnels, -A hands the remote host your agent
#   -F names a config that can set any of the above
#   -M -S -O manage a control socket, -f backgrounds, -s selects a subsystem
# Letters that only pick an address family, quiet/verbosity, or a tty, plus the
# flags that DISABLE forwarding, are all that is accepted.
SSH_BOOL_LETTERS = set("46CqvTtnxa")
# Value-taking flags whose value cannot name a program or a file to write.
SSH_VALUE_FLAGS = {"-p", "-l", "-c", "-m"}
# Vetted `-o` keys. ssh config keys are CASE-INSENSITIVE, so the check
# lowercases before comparing -- `-o proxycommand=x` must not walk past a list
# written in camel case.
SSH_SAFE_OPTIONS = {
    "batchmode", "connecttimeout", "connectionattempts", "loglevel",
    "stricthostkeychecking", "serveraliveinterval", "serveralivecountmax",
    "port", "user", "requesttty", "identitiesonly",
    "passwordauthentication", "pubkeyauthentication", "preferredauthentications",
}

# tmux is the same problem as ssh in a different costume: `new-session`,
# `run-shell`, `send-keys`, `if-shell` and `split-window` all execute a shell
# command, and `kill-server` throws away running work. So tmux is in ALWAYS_ASK
# and these are its exemptions -- the subcommands that only report.
#
# Two traps make this narrower than it looks, and both are checked in the guard
# rather than here, because neither is a property of the subcommand:
#   * a -F format string may contain #(...), which tmux runs as a shell command;
#   * one invocation can hold SEVERAL commands, separated by a literal ';'
#     argument, so a read-only subcommand in front vouches for nothing.
TMUX_READ_SUBCOMMANDS = {
    "ls", "list-sessions",
    "lsw", "list-windows",
    "lsp", "list-panes",
    "lsc", "list-clients",
    "lscm", "list-commands",
    "lsk", "list-keys",
    "lsb", "list-buffers",
    "show", "show-options",
    "showw", "show-window-options",
    "showenv", "show-environment",
    "display", "display-message",
    "info",
}
# capture-pane is a read ONLY with -p, which prints to stdout. Without it the
# pane goes into a paste buffer, which `save-buffer` can then write to disk.
TMUX_CAPTURE_REQUIRES = {"capture-pane": "-p"}
# tmux's own options, before the subcommand. Deliberately tiny: -c runs a shell
# command, -f sources a config file that is itself a list of tmux commands, and
# -C is control mode. What is left only picks a server socket or adjusts output.
TMUX_GLOBAL_BOOL_LETTERS = set("2Dluvq")
TMUX_GLOBAL_VALUE_FLAGS = {"-L", "-S"}
# tmux runs what is inside #(...) -- #{...} is only a variable, but the two are
# a character apart, so the check looks for the executing spelling anywhere in
# an argument rather than trying to parse the format language.
TMUX_FORMAT_EXEC = "#("

# docker runs arbitrary code with the host's resources: `run -v /:/host` mounts
# the filesystem into a container and `exec` enters a running one, so docker is
# in ALWAYS_ASK and these are its exemptions.
#
# Flags are per subcommand rather than pooled, because the same letter means
# different things: -f follows for logs, and takes a filter value for ps. A
# pooled table would read one as the other and mis-count the arguments.
#
# No GLOBAL option is vouched at all, which is why there is no table for them:
# -H and -c/--context reach a different daemon, --config and --tls* repoint the
# credentials used to do it, and the rest are cosmetic.
DOCKER_READ_FLAGS = {
    "ps": ({"-a", "--all", "-l", "--latest", "--no-trunc", "-q", "--quiet",
            "-s", "--size"},
           {"-f", "--filter", "--format", "-n", "--last"}),
    "images": ({"-a", "--all", "--digests", "--no-trunc", "-q", "--quiet",
                "--tree"},
               {"-f", "--filter", "--format"}),
    "stats": ({"-a", "--all", "--no-stream", "--no-trunc"}, {"--format"}),
    "inspect": ({"-s", "--size"}, {"-f", "--format", "--type"}),
    "logs": ({"--details", "-f", "--follow", "-t", "--timestamps"},
             {"--since", "-n", "--tail", "--until"}),
    # `docker top CONTAINER [ps OPTIONS]` hands everything after the container
    # to ps inside it, so no flag here was vetted.
    "top": (set(), set()),
}

# mount's usage line separates its two jobs itself: `mount [-lhV]` lists what
# is already mounted, and every other form takes a source or a target and
# changes the filesystem. So only the listing flags are here, and the
# exemption additionally refuses any positional at all.
#
# Deliberately absent, each of which acts rather than reports: -a mounts
# everything in fstab, -o/-r/-w set mount options, -B/-M/-R and --make-* move
# or re-share a subtree, -L/-U/--source/--target name what to mount, -f
# (--fake) still walks the mount path, and -T/-N redirect which fstab or
# namespace is acted on.
MOUNT_READ_BOOL_FLAGS = frozenset({"-l", "--show-labels",
                                   "-h", "--help", "-V", "--version"})
# With no operand -t only filters the listing, which is checked here; with one
# it selects the type to mount, which the no-positional rule refuses.
MOUNT_READ_VALUE_FLAGS = frozenset({"-t", "--types"})

# man formats a page to stdout, which is a read -- but not under every flag,
# and the exceptions are why a prefix rule cannot stand in for this table
# (`man --help`, 2026-09-21). Withheld: -P/--pager and -H/--html hand the text
# to a program the caller names, -C reads a config file that can set either,
# -c/--catman and -u/--update rewrite man's own caches, and -t/-T/-X/-Z run
# groff or a viewer. Searching and locating are reads, so -k, -f, -w and -l
# are here.
MAN_READ_BOOL_FLAGS = frozenset({
    "-a", "--all", "-f", "--whatis", "-k", "--apropos",
    "-K", "--global-apropos", "-w", "--where", "--path", "--location",
    "-W", "--where-cat", "--location-cat", "-i", "--ignore-case",
    "-I", "--match-case", "--regex", "--wildcard", "--names-only",
    "--no-subpages", "-7", "--ascii", "--no-hyphenation", "--nh",
    "--no-justification", "--nj", "-l", "--local-file", "-D", "--default",
    "-h", "-?", "--help", "--usage"})
MAN_READ_VALUE_FLAGS = frozenset({
    "-s", "-S", "--sections", "-e", "--extension", "-L", "--locale",
    "-m", "--systems", "-M", "--manpath", "-E", "--encoding"})

# dmesg reads the kernel ring buffer (`dmesg --help`, util-linux 2.37). Withheld:
# -c/--read-clear and -C/--clear empty the buffer, and -n/--console-level,
# -D/--console-off and -E/--console-on change what reaches the console. dmesg
# takes no operand, so the exemption also refuses any positional.
DMESG_READ_BOOL_FLAGS = frozenset({
    "-H", "--human", "-k", "--kernel", "-P", "--nopager",
    "-p", "--force-prefix", "-r", "--raw", "--noescape", "-S", "--syslog",
    "-u", "--userspace", "-w", "--follow", "-W", "--follow-new",
    "-x", "--decode", "-d", "--show-delta", "-e", "--reltime",
    "-T", "--ctime", "-t", "--notime", "-h", "--help", "-V", "--version"})
DMESG_READ_VALUE_FLAGS = frozenset({
    "-F", "--file", "-f", "--facility", "-l", "--level",
    "-s", "--buffer-size", "--time-format", "--since", "--until"})
DMESG_READ_OPTIONAL_FLAGS = frozenset({"-L", "--color"})

# journalctl queries the journal (`journalctl --help`, systemd 249). Its
# Commands section also acts: --vacuum-*, --rotate, --flush, --sync,
# --relinquish-var and --smart-relinquish-var change the journal itself,
# --update-catalog rewrites the catalog, --setup-keys (with --force and
# --interval) generates sealing keys, and --cursor-file rewrites the file it
# names. Positionals are MATCHES (`_PID=1`), which only filter.
JOURNALCTL_READ_BOOL_FLAGS = frozenset({
    "--system", "--user", "--show-cursor", "--list-boots", "-k", "--dmesg",
    "-e", "--pager-end", "-f", "--follow", "--no-tail", "-r", "--reverse",
    "--utc", "-x", "--catalog", "--no-full", "-a", "--all", "-q", "--quiet",
    "--no-pager", "--no-hostname", "-m", "--merge", "-h", "--help",
    "--version", "-N", "--fields", "--disk-usage", "--verify", "--header",
    "--list-catalog", "--dump-catalog"})
JOURNALCTL_READ_VALUE_FLAGS = frozenset({
    "-M", "--machine", "-S", "--since", "-U", "--until", "-c", "--cursor",
    "--after-cursor", "-u", "--unit", "--user-unit", "-t", "--identifier",
    "-p", "--priority", "--facility", "-g", "--grep", "-o", "--output",
    "--output-fields", "-D", "--directory", "--file", "--root", "--image",
    "--namespace", "--verify-key", "-F", "--field"})
# Optional values are taken attached, except that -b and -n also peek at the
# next word when it is a boot offset or a count: `journalctl -b -1`.
JOURNALCTL_READ_OPTIONAL_FLAGS = frozenset({
    "-b", "--boot", "-n", "--lines", "--case-sensitive"})
JOURNALCTL_PEEK = {
    "-b": re.compile(r"[+-]?\d+|[0-9a-fA-F]{32}"),
    "--boot": re.compile(r"[+-]?\d+|[0-9a-fA-F]{32}"),
    "-n": re.compile(r"\+?\d+|all"),
    "--lines": re.compile(r"\+?\d+|all"),
}
