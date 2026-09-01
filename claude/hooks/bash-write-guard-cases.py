"""Test fixtures for bash-write-guard.py -- data only, no logic.

Loaded by `bash-write-guard.py --test`, and by nothing else. It lives here
rather than in the guard so the hook does not parse ~830 lines of case data on
every command it judges; the guard is executed once per Bash tool call.

Nothing here imports the guard. The harness passes the guard in, so running the
suite does not execute the guard module a second time.
"""

import os

# A fixed rule set, so these expectations don't shift when settings.json gains
# or loses a rule. The point is to pin the guard's own logic, not the config.
TEST_RULES = [(pattern, "test") for pattern in (
    "ls", "cd", "cat", "echo", "printf", "grep", "sed", "find", "sort", "awk",
    "diff",
    "head", "tail", "cut", "wc", "uniq", "tee", "paste", "bc", "systemctl",
    "ssh-add",
    "[", "test",
    "git log",
    "git branch",
    "git merge-base",
    "git grep", "git status", "git show", "git diff", "git rev-parse",
    "git rev-list", "git config", "git remote", "git ls-remote", "stat",
    "git shortlog", "git archive", "git bundle", "git format-patch",
    "ruff",
)]


TEST_ROOTS = ("/workspace",)

# Built from the running uid rather than written out: SANDBOX_DIR pins the uid,
# so a literal here would have to carry this machine's, and this file is
# published. The project and session components are deliberately fictional.
SANDBOX = f"/tmp/claude-{os.getuid()}/proj/session/scratchpad"
# "silent" means the hook says nothing and the normal permission flow decides.
# For anything write-capable or opaque that is a bug -- those must be "ask".
# For an un-allowlisted command like `rm` it is correct: the rules prompt.
CASES = [
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

    # A `)` inside DOUBLE quotes within a substitution is literal text. The
    # scanner used to close the substitution on it, then read the real `)` as
    # unbalanced and refuse -- so `git log -S"Bash(uniq:*)"` asked. Single
    # quotes always worked, which is why this survived so long.
    ("allow",  'echo "$(grep -c "f(x)" /workspace/a)"'),
    ("allow",  """echo "$(grep -c 'f(x)' /workspace/a)\""""),
    ("allow",  'c=$(git log -S"Bash(uniq:*)" -- f | head -1); echo "$c"'),
    ("allow",  'echo "$(echo "$(echo "x)y")")"'),
    ("silent", 'echo "a)b"'),                     # literal, no substitution
    # The fix must not blind the scan to what follows the quoted paren.
    ("ask",    'echo "$(rm -rf /workspace/x)"'),
    ("ask",    'echo "$(grep -c "f(x)" /workspace/a; rm -rf /workspace/y)"'),
    ("ask",    'echo "$(grep -c "f(x /workspace/a)"'),   # truly unbalanced
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
    ("silent", "case $x in a) echo 1;; esac"),

    # -- while / until -------------------------------------------------------
    # The condition and the body are ordinary commands and every check applies
    # to each, so these need no word-list vetting the way `for` does. What read
    # assigns is deliberately never resolved: the body judges `$line` exactly as
    # it judges a value out of `$(...)`, which is the whole safety property.
    ("allow",  "while true; do echo x; done"),
    ("allow",  'while read -r line; do echo "$line"; done'),
    ("allow",  'cat f | while read -r a b; do printf "%s %s\\n" "$a" "$b"; done'),
    ("allow",  'cat f | while IFS=: read -r a b; do printf "%s\\n" "$a"; done'),
    ("allow",  'until [ -e /workspace/f ]; do echo waiting; done'),
    # a write in the body is caught exactly as it is anywhere else
    ("ask",    'while read -r a; do rm "$a"; done'),
    ("ask",    'while read -r a; do cp "$a" /tmp/x; done'),
    ("ask",    'until [ -e f ]; do touch f; done'),
    # what was read is opaque, so a flag-sensitive command still refuses it
    ("ask",    'while read -r a; do sed $a f; done'),
    ("ask",    'while read -r a; do git log $a; done'),
    # and an expansion in command position is still not a command we can read
    ("silent", 'while read -r a; do $a; done'),
    # IFS is scoped to `read` only -- the forms that change word splitting for
    # everything after them are still refused
    ("silent", "IFS=: ls /workspace"),
    ("silent", "IFS=:; ls /workspace"),
    ("silent", "IFS=: cat f"),
    # the keywords are only keywords where a command may start
    ("silent", "grep -n while f"),
    ("silent", "grep -n read f"),

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

    # `set` changing shell OPTIONS writes nothing and hands nothing to a later
    # command, so it is vouched for like control flow. It was in REFUSED_WORDS,
    # where a leading `set -o pipefail` withdrew the grant from the whole line.
    ("allow",  "set -o pipefail; echo hi"),
    ("allow",  "set -euo pipefail; echo hi"),      # a combined cluster
    ("allow",  "set -eu; echo hi"),
    ("allow",  "set +o pipefail; echo hi"),
    ("allow",  "set -o; echo hi"),                 # prints the options: a read
    ("allow",  "set -x; grep -n foo f"),
    # Setting POSITIONAL PARAMETERS is the other half, and still refuses: the
    # names are never resolved, so `$1` could arrive as any flag at all.
    ("ask",    "set -- -i; sed $1 f"),             # sed catches this one
    ("silent", "set -- a b; echo hi"),
    ("silent", "set a b; echo hi"),
    ("silent", "set; echo hi"),                    # dumps every variable
    ("silent", "set --; echo hi"),
    # An option name or letter that was not vetted refuses rather than guessing.
    ("silent", "set -o badoption; echo hi"),
    ("silent", "set -eZ; echo hi"),
    ("silent", "set -oe pipefail; echo hi"),       # `o` must end the cluster

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
    # The one exemption: subcommands read out of the client source and shown to
    # be a GET. "silent" not "allow" because no rule names orchestrator -- a
    # local grant supplies the permission, and grants are off in these tests.
    ("silent", "orchestrator request_status 68625"),
    ("silent", "orchestrator request_status 68625 --show-history"),
    ("silent", "orchestrator request_status --commits --color 68625"),
    ("silent", "orchestrator request_status 68625 | tail -3"),
    ("silent", "orchestrator request_status 68625 2>&1 | tail -3"),
    # the exemption has to be PROVEN, so anything unreadable withdraws it
    ("ask",    "orchestrator request_status --newflag 68625"),
    ("ask",    "orchestrator request_status"),          # no id: unvetted shape
    ("ask",    "orchestrator request_status $ID"),      # could expand to a flag
    ("ask",    'orchestrator request_status "$(cat id)"'),
    ("ask",    "orchestrator request_status --show-history $F"),
    # queue_status is the second vetted subcommand. Its to_branch defaults to
    # the cwd's upstream, so the bare form is a vetted shape too.
    ("silent", "orchestrator queue_status"),
    ("silent", "orchestrator queue_status feature/some_queue"),
    ("silent", "orchestrator queue_status --commits --fail-summary x"),
    ("silent", "orchestrator queue_status --num-completed 5 x"),
    ("silent", "orchestrator queue_status --num-completed=5"),
    ("silent", "timeout 120 orchestrator queue_status x 2>&1 | head -40"),
    ("ask",    "orchestrator queue_status $BRANCH"),
    ("ask",    "orchestrator queue_status --newflag x"),
    # Flags are per subcommand: --color and --sort-by-name belong to
    # request_status only, and --csv is not a queue_status flag at all.
    ("ask",    "orchestrator queue_status --color x"),
    ("ask",    "orchestrator queue_status --csv"),
    ("ask",    "orchestrator request_status --fail-summary 68625"),
    # every other subcommand still asks, in every position
    ("ask",    "orchestrator submit"),
    ("ask",    "orchestrator resubmit 68625"),
    ("ask",    "orchestrator abort 68625"),
    ("ask",    "orchestrator pull_request_delete 68625"),
    ("ask",    "orchestrator queue_reorder"),
    ("ask",    'echo "$(orchestrator submit)"'),
    ("ask",    'echo "$(orchestrator abort 68625)"'),
    ("silent", 'echo "$(orchestrator request_status 68625)"'),
    ("ask",    "orchestrator request_status 68625 && orchestrator submit"),
    ("ask",    "orchestrator submit; orchestrator request_status 68625"),
    ("ask",    "timeout 60 orchestrator submit"),
    ("ask",    "A=1 orchestrator submit"),
    ("ask",    "xargs orchestrator submit"),
    ("ask",    "/opt/local/bin/orchestrator submit"),
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
    ("allow",  f"echo hi > {SANDBOX}/notes.md"),
    ("allow",  f"uniq {SANDBOX}/a {SANDBOX}/b"),
    ("ask",    "echo hi > /tmp/other.txt"),
    ("ask",    "echo hi > notes.md"),            # relative: cwd unprovable
    ("ask",    'echo hi > "$P/notes.md"'),       # variable: not read
    ("ask",    f"echo hi > {SANDBOX}/../../../../etc/x"),
    ("ask",    f"rm -rf {SANDBOX}/f"),          # deletion still asks
    # sed -i and tee name their targets in argv, so they are sandboxed too --
    # all or nothing: one target outside the scratchpad and the whole command
    # asks, since a partial write is not a partial risk.
    ("allow",  f"sed -i s/a/b/ {SANDBOX}/f"),
    ("allow",  f"echo x | tee {SANDBOX}/f"),
    ("allow",  f"echo x | tee -a {SANDBOX}/f {SANDBOX}/g"),
    ("ask",    "sed -i s/a/b/ /etc/passwd"),
    ("ask",    f"sed -i s/a/b/ /etc/passwd {SANDBOX}/f"),
    ("ask",    "sed -i -e s/a/b/ /etc/passwd"),  # script from a flag
    ("ask",    "sed -i s/a/b/ f.txt"),           # relative: cwd unprovable
    ("ask",    f"echo x | tee {SANDBOX}/f /etc/passwd"),
    ("ask",    f"sed --bogus -i s/a/b/ {SANDBOX}/f"),   # unknown flag
    # Every tool that names an output file goes through one extractor, so the
    # same destination gets the same answer. sort and ruff used to ask here
    # while git, sed, tee and uniq did not -- their output knowledge simply
    # lived somewhere the scratchpad check never reached.
    ("allow",  f"sort -o {SANDBOX}/s.txt f"),
    ("allow",  f"sort --output={SANDBOX}/s.txt f"),
    ("allow",  f"sort -o{SANDBOX}/s.txt f"),          # attached short value
    ("allow",  f"ruff check -o {SANDBOX}/r.json f.py"),
    ("allow",  f"ruff check --output-file={SANDBOX}/r.json f.py"),
    ("ask",    "sort -o /tmp/other.txt f"),
    ("ask",    "sort -o f"),                          # no value: names nothing
    ("ask",    "ruff check -o /tmp/r.json f.py"),
    # --fix rewrites the SOURCE files, which no output path makes disposable.
    ("ask",    f"ruff check --fix {SANDBOX}/f.py"),
    ("silent", "ruff check --select E9 f.py"),
    ("silent", "sort -n f"),
    # An attached value is read for short flags only: `--outputfoo` is a
    # different option, not `--output` carrying one.
    ("silent", "git diff --outputfoo=/tmp/x HEAD"),

    # git's output flags name their target in argv too, so the same exemption
    # applies -- in every spelling: `=`-joined, separate, and attached short.
    ("allow",  f"git diff --output={SANDBOX}/d HEAD"),
    ("allow",  f"git diff --output {SANDBOX}/d HEAD"),
    ("allow",  f"git format-patch --output-directory={SANDBOX}/p -1 HEAD"),
    ("allow",  f"git archive -o {SANDBOX}/a.tar HEAD"),
    ("allow",  f"git archive -o{SANDBOX}/a.tar HEAD"),
    ("allow",  f"git bundle create {SANDBOX}/b.bundle HEAD"),
    ("ask",    "git diff --output=/tmp/other.diff HEAD"),
    ("ask",    "git archive -o /tmp/other.tar HEAD"),
    ("ask",    "git bundle create /tmp/other.bundle HEAD"),
    # Three that a scratchpad target does NOT make disposable. unbundle writes
    # objects and refs into the REPOSITORY; --exec names a program for the far
    # end to run, not a file; and a flag with no value names no target at all.
    ("ask",    f"git bundle unbundle {SANDBOX}/b.bundle"),
    ("ask",    f"git archive --remote=origin --exec={SANDBOX}/p HEAD"),
    ("ask",    "git diff --output HEAD"),
    ("ask",    "git diff --output=$OUT HEAD"),           # value not read
    ("ask",    f"git diff --output={SANDBOX}/../../../../etc/x HEAD"),
    ("ask",    f"echo x | tee --bogus {SANDBOX}/f"),
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

    # shortlog is not diff machinery but takes the same --output. The literal
    # flag was always caught; an unreadable value was granted outright.
    ("silent", "git shortlog -sn HEAD~3..HEAD"),
    ("ask",    "git shortlog --output=/tmp/x HEAD"),
    ("ask",    'A=$(cat f); git shortlog $A'),
    ("ask",    'git shortlog "$(cat f)"'),
    # `--end-of-options` does NOT rescue shortlog: its own parser ignores the
    # marker and honours a later --output. Measured, not assumed -- so if the
    # marker is ever taught to the guard, it must not cover this subcommand.
    ("ask",    'A=$(cat f); git shortlog --end-of-options $A'),

    # git archive streams to stdout; -o/--output is what makes it a write, and
    # --exec hands the remote a program to run.
    ("silent", "git archive --format=tar HEAD"),
    ("silent", "git archive --list"),
    ("ask",    "git archive -o /tmp/x.tar HEAD"),
    ("ask",    "git archive -o/tmp/x.tar HEAD"),      # attached short form
    ("ask",    "git archive --output=/tmp/x.tar HEAD"),
    ("ask",    "git archive --remote=origin --exec=/tmp/p HEAD"),
    ("ask",    'A=$(cat f); git archive $A'),

    # git bundle dispatches on a positional, so the subcommand must be located
    # before anything can be said -- same shape as git remote.
    ("silent", "git bundle verify /workspace/x.bundle"),
    # same read, but the bundle is outside the workspace: the guard vouches for
    # it rather than leaving it to the path gate.
    ("allow",  "git bundle list-heads /tmp/x.bundle"),
    ("ask",    "git bundle create /tmp/x.bundle HEAD"),
    ("ask",    "git bundle unbundle /tmp/x.bundle"),
    ("ask",    "git bundle --progress create /tmp/x.bundle HEAD"),
    ("ask",    "git bundle --version=3 create /tmp/x.bundle HEAD"),  # unsizable
    ("ask",    'A=$(cat f); git bundle $A /tmp/x.bundle'),

    # format-patch writes a directory of patches under a flag GIT_OUTPUT_FLAG
    # used to miss, and its -o is the same write spelled short.
    ("ask",    "git format-patch --output-directory=/tmp/x -1 HEAD"),
    ("ask",    "git format-patch --output-directory /tmp/x -1 HEAD"),
    ("ask",    "git format-patch -o /tmp/x -1 HEAD"),

    # Global options that print and exit reach no subcommand, so "cannot
    # attribute this option to a subcommand" was the wrong complaint.
    ("silent", "git --version"),
    ("silent", "git -v"),
    ("silent", "git --help"),
    ("silent", "git -h"),
    ("silent", "git --exec-path"),
    ("silent", "git --no-pager --version"),
    ("silent", "git --version status"),          # git ignores the trailing word
    # ...but `--exec-path=DIR` repoints where git finds its helper programs and
    # then runs the subcommand, so only the bare spelling is terminal.
    ("ask",    "git --exec-path=/tmp/evil status"),
    # Anything unrecognized stops the scan rather than being skipped, so an
    # option that takes a value can never hide a subcommand behind it.
    ("ask",    "git -c core.pager=cat --version"),
    ("ask",    "git --literal-pathspecs --version"),

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
    # `git ls-remote` is a ref lookup, except for the two flags that talk to the
    # far end about something other than refs. "silent" here means the guard
    # steps aside and Bash(git ls-remote:*) permits it -- no prompt; only the
    # substitution needs an actual grant, since no prefix rule can match one.
    ("silent", "git ls-remote origin"),
    ("silent", "git ls-remote origin refs/heads/main"),
    ("silent", "git ls-remote --branches --tags --refs origin"),
    ("silent", "git ls-remote --sort=version:refname --symref origin"),
    ("silent", "git ls-remote --get-url origin"),
    ("allow",  'echo "$(git ls-remote origin)"'),
    ("ask",    "git ls-remote --upload-pack=/tmp/x origin"),
    ("ask",    "git ls-remote --upload-pack /tmp/x origin"),
    ("ask",    "git ls-remote -o key=value origin"),
    ("ask",    "git ls-remote --server-option=key=value origin"),
    ("ask",    "git ls-remote $FLAGS origin"),          # could be --upload-pack
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
# assertion below fail -- that is the reminder to move it into CASES.
GAPS = [
    # Empty. Both original entries were closed by expanding literal loop words
    # and by treating an argument that begins with an expansion as opaque.
    # Keep the list and its handling: the next gap wants writing down, not
    # rediscovering.
]
