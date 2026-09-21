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
    "git check-ignore",
    "git shortlog", "git archive", "git bundle", "git format-patch",
    "ruff", "realpath", "basename", "dirname", "file", "readlink",
    "command -v", "command -V", "ps",
    # Stands in for an allowlisted script, so the python3 cases can test the
    # unwrapping without depending on a local grant (grants are off in --test).
    "/workspace/tool.py",
    # Same, but OUTSIDE TEST_ROOTS. The cd cases need this: a grant -- and so
    # an `allow` -- is only emitted when a path falls outside the roots, so a
    # script inside /workspace could never show that the cwd was resolved.
    "/opt/bin/tool.py",
)]
# No tmux rule, deliberately -- like ssh, a vouched tmux is granted by the hook
# and an unvouched one is an ask, so a rule would change nothing either way.


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
    # git log DOES have one: every diff-machinery subcommand takes --output,
    # so an unreadable "$sha" could be it.
    ("ask",    'git log -1 --format=%s "$sha"'),
    # ...and expansion is exact, so a read-only flag is no longer refused
    ("allow",  "for f in -n; do sed $f 1,5p data.txt; done"),
    ("allow",  "for f in -c; do grep $f pattern data.txt; done"),
    ("allow",  "for f in -i; do grep $f pattern data.txt; done"),
    # a loop that cannot be expanded, but whose word could be a flag, says so
    ("ask",    "for f in -i; do for g in a; do sed $f x; done; done"),
    # A word that splits is expandable too, and expansion is what puts the
    # piece in front of the command it actually reaches -- which decides it
    # either way, where refusing the loop outright was only a guess.
    ("ask",    'for f in "a -i"; do sed $f x; done'),          # -> sed a -i x
    ("allow",  'for f in "data.txt --color"; do grep -i x $f; done'),
    ("allow",  'for f in "a.txt HEAD" "b.txt --color"; do echo "== $f"; grep -i x $f; done'),
    ("ask",    'for f in "data.txt -i"; do sed $f s/a/b/; done'),
    # Quotes are gone by the time the guard sees this, so `"$f"` is modelled as
    # unquoted and this asks where bash would read. Pinned because a
    # quoting-aware expansion could relax it, and should have to say so.
    ("ask",    'for f in "x -i"; do sed "$f" y; done'),
    # a piece may even be the command, which the shell word-splits just the same
    ("allow",  'for c in "grep -c"; do $c pattern data.txt; done'),
    # ...but ONLY the token that received the value splits. Splitting every
    # token shattered quoted arguments that never mentioned the loop variable.
    ("allow",  'for r in "1 2 x"; do echo "a | b"; done'),
    ("allow",  'for r in "1 2"; do echo "left | right"; done'),
    ("allow",  'for r in "1 2 x"; do grep -n "a b" f; done'),
    # ...while ordinary literal word lists keep working
    ("allow",  'for u in https://a.example/ https://b.example/; do echo "$u"; done'),
    ("allow",  "for c in 0fe44dfb28e2:495458 aedc918bcd:1234; do echo $c; done"),
    ("allow",  'for s in WRONG_COUNTS BAD_NODE; do git grep -c "$s" HEAD; done'),
    ("silent", "case $x in a) echo 1;; esac"),

    # -- while / until -------------------------------------------------------
    # The condition and the body are ordinary commands, so no word-list vetting
    # is needed. What `read` assigns is never resolved: the body judges `$line`
    # as it judges any unreadable value.
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
    # -- builtins that run whatever they are handed ------------------------
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

    # -- single-quoted literals cannot expand ------------------------------
    # Bash single quotes suppress expansion absolutely, so a token taken whole
    # from a single-quoted span cannot be one. shlex discards the quotes, so
    # the marking has to be recovered from the raw text.
    ("silent", "awk -F: '$1<4362' f"),
    ("silent", "awk '{print $1}' f"),             # never asked; pinned anyway
    ("silent", "grep -n x f | awk -F: '$1<99'"),
    ("silent", "sed -n '$p' f"),                  # last line, not a variable
    ("silent", "awk '$1 > 5' f"),                 # a COMPARISON, not a redirect
    # Double quotes do expand, so nothing changes for them.
    ("ask",    'awk "$prog" f'),
    ("ask",    'sed -n "$script" f'),
    # A real redirect inside a single-quoted program is still a write, and the
    # literal marking must not stop AWK_WRITE from reading it.
    ("ask",    "awk '{print > \"/etc/x\"}' f"),
    ("ask",    "awk '{system(\"rm -rf x\")}' f"),
    # The same text quoted AND unquoted: the unquoted one could expand to a
    # flag, and they are indistinguishable by text, so the segment still asks.
    ("ask",    "awk '$HOME' $HOME"),

    # -- read-only forms vetted from the tool's own --help -----------------
    ("silent", "orchestrator whoami"),
    ("ask",    "orchestrator whoami --force"),      # an unvetted flag refuses
    ("ask",    "orchestrator submit HEAD~1..HEAD"),
    ("ask",    "orchestrator whoami > /workspace/out"),

    # Read from `-h`, not assumed: every git check-ignore flag (-q -v -n -z
    # --stdin --index/--no-index) only reports. It takes no output file, so it
    # is not flag-sensitive either -- unlike the diff-machinery subcommands,
    # where an unreadable argument could be `--output=`.
    ("silent", "git check-ignore -v .claude/settings.local.json"),
    ("silent", "git check-ignore --stdin -z"),
    ("ask",    "git check-ignore -v f > /workspace/out"),

    # `ps` reads /proc and has no write flag, so only a redirect makes it write.
    # Allowlisted because the write-guard skill names this exact command as the
    # way to tell a resumed session's process age from its transcript's date.
    ("silent", "ps -eo pid,lstart,etimes,args"),
    ("ask",    "ps -eo args > /workspace/out"),

    # -- command runners: ALWAYS_ASK, with a vetted read-only exemption ----
    # ssh reaches a machine where no allow rule and no workspace boundary
    # applies, so the exemption needs the remote command to pass the same
    # read-only AND allowlist test a local one would.
    ("allow",  "ssh -o BatchMode=yes -o ConnectTimeout=8 host 'ls /home'"),
    ("allow",  "ssh -p 22 host 'grep -c VmHWM /proc/self/status'"),
    ("allow",  "ssh -4Cq host 'cat /etc/hostname'"),          # a bool cluster
    # The remote command is judged, not trusted.
    ("ask",    "ssh host 'rm -rf /data'"),
    ("ask",    "ssh host 'echo x > /etc/f'"),                 # remote redirect
    ("ask",    'ssh host "$CMD"'),                            # unreadable
    # Write-free is NOT enough. There is no rule gate on the far side, so an
    # unknown remote program has to ASK rather than fall silent -- silence
    # would let a `Bash(ssh:*)` rule wave the whole class through, which is the
    # very thing listing ssh in ALWAYS_ASK is meant to prevent.
    ("ask",    "ssh host some_unknown_tool --wipe"),
    # ssh's OWN flags act locally, before the remote command is reached.
    ("ask",    "ssh -o ProxyCommand=nc host ls"),             # local exec
    ("ask",    "ssh -o proxycommand=nc host ls"),             # keys are case-insensitive
    ("ask",    "ssh -E /tmp/log host ls"),                    # writes locally
    ("ask",    "ssh -F /tmp/cfg host ls"),                    # config can set ProxyCommand
    ("ask",    "ssh -A host ls"),                             # forwards the agent
    ("ask",    "ssh -L 8080:localhost:80 host ls"),           # tunnel
    ("ask",    "ssh -M -S /tmp/ctl host ls"),                 # control socket
    ("ask",    "ssh host"),                                   # interactive login
    # A scratchpad path names another machine's filesystem over there, so the
    # exemption that makes a local scratchpad write silent must not follow.
    ("ask",    f"ssh host 'sort -o {SANDBOX}/f data'"),

    # tmux is a command runner wearing a listing tool's clothes: `new-session`,
    # `run-shell` and `send-keys` all execute. Same shape as ssh -- ALWAYS_ASK,
    # with an exemption for the subcommands that only report.
    ("allow",  "tmux ls"),
    ("allow",  "tmux list-sessions"),
    ("allow",  "tmux list-panes -a"),
    ("allow",  "tmux -L bench ls"),                           # socket selector
    ("allow",  "tmux capture-pane -p -t bench"),
    ("ask",    "tmux new-session -d 'rm -rf /data'"),
    ("ask",    "tmux run-shell 'curl evil'"),
    ("ask",    "tmux send-keys -t 0 'rm -rf /' Enter"),
    ("ask",    "tmux kill-server"),
    # capture-pane WITHOUT -p writes the pane into a paste buffer instead of
    # printing it, and `save-buffer` then puts that on disk. Only the printing
    # form is a read.
    ("ask",    "tmux capture-pane -t bench"),
    ("ask",    "tmux save-buffer /tmp/out"),
    # A format string is not inert: #(...) runs a shell command, so a read-only
    # subcommand can carry an arbitrary one in its -F argument.
    ("ask",    "tmux ls -F '#(rm -rf /data)'"),
    # `python3 <script>` is a wrapper around a file, and when that file is
    # already allowlisted the interpreter adds nothing the guard cannot see.
    # Unwrapped to the script's own argv and judged as if it had been run
    # directly -- which is what `Bash(<script>:*)` or a grant already covers.
    ("allow",  "python3 /workspace/tool.py --check"),
    ("allow",  "python3 -u -B /workspace/tool.py"),   # flags that only tune I/O
    ("allow",  "python /workspace/tool.py"),
    # The script has to BE allowlisted; the interpreter vouches for nothing.
    ("ask",    "python3 /workspace/unknown.py"),
    # Forms where no file is named, so there is nothing to allowlist.
    ("ask",    "python3 -c 'import shutil; shutil.rmtree(\"/x\")'"),
    ("ask",    "python3 -m http.server"),
    ("ask",    "python3"),                            # a REPL
    ("ask",    "python3 -"),                          # program on stdin
    ("ask",    "python3 -i /workspace/tool.py"),      # REPL after the script
    # A bare name is a PATH lookup for a command word and a relative path for a
    # script, so it resolves here where `./tool.py` already did. Without a cd
    # there is no cwd to resolve against, and the check would be of a path bash
    # is not going to run.
    ("ask",    "python3 tool.py --check"),
    ("allow",  "cd /workspace; python3 tool.py --check"),
    ("allow",  "cd /workspace; python3 -u tool.py"),   # a flag first
    ("ask",    "cd /workspace; python3 unknown.py"),   # resolved, still unruled
    # -c takes code, not a path. Resolving its value against the cwd would
    # invent a path the shell never names.
    ("ask",    "cd /workspace; python3 -c 'import os'"),
    # `env` prints the environment when no COMMAND follows, the same read as
    # printenv. Only boolean flags are vouched: a value-taking one would have
    # to be counted correctly to know where the COMMAND starts, and no read
    # needs them.
    ("allow",  "env"),
    ("allow",  "env | grep -i jira"),
    ("allow",  "env -0 | head -5"),
    ("ask",    "env rm -rf /workspace/d"),
    ("ask",    "env FOO=1 rm -rf /workspace/d"),
    ("ask",    "env -- rm -rf /workspace/d"),
    ("ask",    "env -i sh"),
    # -S splits a string into argv, so it carries a command; -C relocates one.
    ("ask",    "env -S 'sh -c rm'"),
    ("ask",    "env -C /tmp ls"),
    ("ask",    "env -u FOO rm -rf /workspace/d"),
    ("ask",    "env --ignore-signal=INT rm -rf /workspace/d"),
    # Not vouched, but read-only in fact -- the exemption stays narrow rather
    # than growing a value-flag parser for forms nobody types.
    ("ask",    "env -u FOO"),
    ("ask",    "env FOO=1"),
    # `claude` is the worst name to leave unruled: `-p` runs an agent that can
    # do anything, and `mcp add` rewrites config. Only the exact read form is
    # vouched, so a rule naming it is never needed -- and never wanted.
    ("allow",  "claude mcp list"),
    ("allow",  'claude mcp list | grep -i jira'),
    ("ask",    "claude -p 'rm -rf /data'"),
    ("ask",    "claude"),
    ("ask",    "claude mcp add foo bar"),
    ("ask",    "claude mcp remove foo"),
    ("ask",    "claude mcp list --extra"),
    ("ask",    "claude mcp"),
    ("ask",    "claude doctor"),
    # An absolute cd makes the script resolvable, so the interpreter is vouched
    # for the same as a direct run. Only the script position: a value after a
    # code-running flag is resolved too, but -c is not a safe flag letter, so
    # python_script_argv still refuses it.
    ("allow",  "cd /opt/bin; python3 ./tool.py --check"),
    ("allow",  "cd /opt; python3 bin/tool.py"),
    ("ask",    "cd /opt/bin; python3 ./unknown.py"),
    ("ask",    "cd /opt/bin; python3 -c ./tool.py"),
    # The script's own write-capability still applies after unwrapping.
    ("ask",    "python3 /workspace/tool.py > /etc/f"),

    # `perf record` writes its samples to a file -- that is what it is for --
    # and `perf stat -o` does too. Listed in ALWAYS_ASK before any rule names
    # perf, so a later `Bash(perf:*)` cannot make the write silent. Without it
    # the guard found no write reason at all in `perf record -o <file>`.
    ("ask",    "perf record -F 199 -g -p 123 -o /tmp/prof.data -- sleep 20"),
    ("ask",    "perf stat -o /tmp/out -- true"),
    ("ask",    "perf report -i /tmp/prof.data --stdio"),
    ("ask",    "ssh host 'perf record -o /tmp/x -- sleep 1'"),

    # `date [-u] [MMDDhhmm[[CC]YY][.ss]]` sets the system clock, as does -s, so
    # a bare operand refuses. Read flags are allowlisted rather than -s refused
    # because short options cluster: `-Is` is -I with its optional argument.
    ("allow",  "date -Is"),
    ("allow",  "date +%s"),
    ("allow",  "date -u -R"),
    ("allow",  "date -d '2 hours ago' +%H"),
    ("ask",    "date -s '2020-01-01 00:00:00'"),
    ("ask",    "date --set=@0"),
    ("ask",    "date 202001010000"),
    ("ask",    "date --frobnicate"),          # unknown flag may take a value

    # A quoted or escaped operator is an argument, so the segment keeps it and
    # the tool's own check sees it. Splitting there instead built a phantom
    # command out of the first one's arguments.
    ("ask",    "tmux ls ';' new-session -d 'rm -rf /data'"),
    ("ask",    "find . -name '*.pyc' -exec rm {} \\;"),
    ("silent", "echo ';'"),                   # an argument is not a separator
    ("silent", "ls ';' ls"),
    # -f sources a config file, whose contents are tmux commands; -c runs a
    # shell command outright. Both act before any subcommand is reached.
    ("ask",    "tmux -f /tmp/cfg ls"),
    ("ask",    "tmux -c 'rm -rf /data'"),
    # ...and the whole thing again on the far side of an ssh, where the rule
    # gate that would otherwise catch `tmux new-session` does not exist.
    ("allow",  "ssh -o BatchMode=yes host 'tmux ls'"),
    ("ask",    "ssh -o BatchMode=yes host 'tmux new-session -d \"rm -rf /\"'"),

    # docker runs arbitrary code with host access: `-v /:/host` mounts the
    # filesystem in. Flag tables are per subcommand because the same letter
    # differs between them -- `-f` follows for logs, filters for ps.
    ("ask",    "docker run -v /:/host alpine sh -c 'rm -rf /host/etc'"),
    ("ask",    "docker exec -it c bash"),
    ("ask",    "docker cp x c:/y"),
    ("ask",    "docker rm -f c"),
    ("silent", "docker ps -a --no-trunc"),
    ("silent", "docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}'"),
    ("silent", "docker images -q"),
    ("silent", "docker inspect -f '{{.State.Pid}}' c"),
    ("silent", "docker logs -f --tail 20 c"),
    ("silent", "docker top c"),
    ("ask",    "docker ps --frobnicate"),      # unknown flag may take a value
    # A global option reaches a different daemon or other credentials, so none
    # is vouched -- not even the cosmetic ones, which buy nothing.
    ("ask",    "docker -H tcp://evil:2375 ps"),
    ("ask",    "docker --config /tmp/x ps"),
    ("ask",    "docker -c other ps"),
    # `docker top CONTAINER [ps OPTIONS]` hands the rest to ps inside the
    # container, so nothing past the container name was vetted.
    ("ask",    "docker top c -eo pid"),
    # An argument the guard cannot read could BE one of the unvetted flags.
    ("ask",    "docker logs --tail $N c"),

    # mount's own usage line spells the read: `mount [-lhV]`. A source or a
    # target operand means it is mounting, so ANY positional refuses. Vouched
    # rather than ruled, because Bash(mount:*) would admit `mount /dev/sdb1
    # /mnt` -- checked against mount(8) and both listing forms run here.
    ("allow",  "mount"),
    ("allow",  "mount -l"),
    ("allow",  "mount --show-labels"),
    ("allow",  "mount -t ext4"),
    ("allow",  "mount --types=ext4"),
    ("allow",  "mount -V"),
    ("allow",  "mount 2>/dev/null | grep -i tlogs"),
    ("ask",    "mount /dev/sdb1 /mnt"),
    ("ask",    "mount -t ext4 /dev/sdb1 /mnt"),
    ("ask",    "mount -a"),                   # mounts everything in fstab
    ("ask",    "mount -o remount,rw /"),
    ("ask",    "mount --bind /a /b"),
    ("ask",    "mount -M /a /b"),
    ("ask",    "mount --make-rshared /"),
    # -L and -U name a device to mount; they are sources, not filters.
    ("ask",    "mount -L mylabel"),
    ("ask",    "mount -U 1234-5678"),
    ("ask",    "mount --source /dev/sdb1"),
    ("ask",    "mount --target /mnt"),
    ("ask",    "mount -f /dev/sdb1 /mnt"),    # --fake still is not a read
    ("ask",    "mount -T /tmp/fstab -a"),
    ("ask",    "mount -N ns"),
    ("ask",    "mount --frobnicate"),         # unknown flag may take a value
    ("ask",    "mount -t $T"),                # unreadable: could BE a flag
    ("silent", "grep -n mount f"),            # an argument is just an argument

    # man formats a page, but several flags hand the text to a program of the
    # caller's choosing, and two rewrite man's own caches. Vouched rather than
    # ruled for the usual reason: Bash(man:*) would admit every one of them.
    ("allow",  "man mount"),
    ("allow",  "man 8 mount"),
    ("allow",  "man -a mount"),
    ("allow",  "man -k pattern"),
    ("allow",  "man -s 2 open"),
    ("allow",  "man -w mount"),
    ("allow",  "man mount | head -20"),
    ("ask",    "man -P 'sh -c \"rm -rf /\"' mount"),   # -P runs the pager
    ("ask",    "man -H firefox mount"),                # -H runs a browser
    ("ask",    "man -C /tmp/cfg mount"),        # a config file sets PAGER
    ("ask",    "man -c mount"),                 # catman rewrites cat pages
    ("ask",    "man -u"),                       # updates the man cache
    ("ask",    "man -t mount"),                 # hands the page to groff
    ("ask",    "man --frobnicate mount"),       # unknown flag may take a value
    ("ask",    "man -s $S open"),               # unreadable: could BE a flag

    # `command -v` resolves a name and runs nothing -- `which` as a builtin. It
    # was in REFUSED_WORDS *and* ALWAYS_ASK, so a `command -v ruff` beside six
    # allowlisted segments made the whole line ask.
    ("silent", "command -v ruff"),                 # rule-matched, nothing to add
    ("silent", 'echo "PATH=$PATH"; command -v ruff; ruff --version'),
    ("silent", "command -V ruff"),
    ("silent", "command -pv ruff"),                # clustered with -p
    ("allow",  "command -v ruff; echo $(ruff --version)"),   # grant survives it
    # Every other form runs its argument, which is what the builtin is for.
    ("ask",    "command rm -rf x"),
    ("ask",    "command -p rm -rf x"),
    ("ask",    "command -- rm -rf x"),             # -- ends the flags, no -v
    ("ask",    "command ls"),                      # allowlisted, still hidden
    ("ask",    "command -x ruff"),                 # unrecognized flag
    ("ask",    "command"),                         # resolves nothing
    ("ask",    "command -v ruff > /tmp/f"),        # the redirect still counts

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
    # -- how the command word itself arrives -------------------------------
    # -- orchestrator: the read subcommands, and what must stay refused ----
    # Every spelling below must still reach argv0_of, or the ALWAYS_ASK entry
    # is bypassed by how the command word was written.
    ("ask",    "orchestrator submit --branch users/me/x"),
    ("ask",    "/opt/local/bin/orchestrator submit HEAD"),
    ("ask",    "timeout 60 orchestrator submit HEAD"),
    ("ask",    'echo "$(orchestrator submit HEAD)"'),
    ("ask",    "A=1 orchestrator submit HEAD"),
    ("ask",    "ls -la && orchestrator submit HEAD"),
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
    # request_list is the third: one GET, one log line, and --num-completed is
    # its only flag. Same optional to_branch as queue_status.
    ("silent", "orchestrator request_list"),
    ("silent", "orchestrator request_list feature/some_queue"),
    ("silent", "orchestrator request_list --num-completed 5 x"),
    ("silent", "orchestrator request_list feature/some_queue 2>&1 | tail -6"),
    ("ask",    "orchestrator request_list $BRANCH"),
    ("ask",    "orchestrator request_list --commits x"),
    # job_status is the fourth. get_job_data, get_tpe_data and get_queue_data
    # are each one http_session.get -- the POST sitting next to them in
    # common.py belongs to get_session_data, the auth check every subcommand
    # makes -- and its flags are the shared status booleans.
    ("silent", "orchestrator job_status 279384"),
    ("silent", "orchestrator job_status 279384 2>&1 | head -40"),
    ("silent", "orchestrator job_status --color --sort-by-name 279384"),
    ("ask",    "orchestrator job_status"),          # argparse requires the id
    ("ask",    "orchestrator job_status --newflag 1"),
    ("ask",    "orchestrator job_status $JOB"),
    # argparse prints usage and exits before any subcommand dispatches, but
    # only vouched when help LEADS: a global value flag can swallow it, and
    # `orchestrator --token --help submit` then runs submit.
    ("silent", "orchestrator --help"),
    ("silent", "orchestrator -h"),
    ("silent", "orchestrator --help 2>&1 | grep -iE job"),
    ("ask",    "orchestrator submit --help"),
    ("ask",    "orchestrator --token --help submit"),
    # submit is vouched ONLY as a dry run, and only with --dry-run leading.
    # --description, --feature-name and --request take values, so a later
    # --dry-run can become one: `submit --description --dry-run a b br` is a
    # real push to a shared branch with --dry-run sitting in argv where a
    # naive check would find it. No value flag is vetted, for the same reason.
    ("silent", "orchestrator submit --dry-run aa bb feature/some_queue"),
    ("silent", "orchestrator submit --dry-run --details aa bb feature/x"),
    ("silent", "orchestrator submit --dry-run --commits --color aa bb x"),
    ("ask",    "orchestrator submit --description --dry-run aa bb x"),
    ("ask",    "orchestrator submit aa bb feature/some_queue --dry-run"),
    ("ask",    "orchestrator submit --dry-run --description x aa bb y"),
    ("ask",    "orchestrator submit --dry-run --reset-branch aa bb x"),
    ("ask",    "orchestrator submit --dry-run --skip-presubmission-checks a b"),
    ("ask",    "orchestrator submit --dry-run $RANGE feature/some_queue"),
    ("ask",    "orchestrator submit --dry-run=1 aa bb x"),
    ("ask",    "orchestrator --token t submit --dry-run aa bb x"),
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
    # -- OWN_TOOLS: this repo's own scripts, by resolved path --------------
    # An interpreter asks unless the script it runs is vouched for; OWN_TOOLS
    # vouches for these, run directly or through python3.
    ("allow",  "python3 ~/.claude/tools/why-prompt.py ls"),
    ("allow",  "~/.claude/tools/why-prompt.py ls"),

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

    # -- redirections are not arguments ------------------------------------
    # Any check that counts positionals saw `2>&1` as two of them, so these
    # ordinary reads reported writes.
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

    # -- the session scratchpad exemption ----------------------------------
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
    # -- flags that name an output file ------------------------------------
    # Every tool that names an output file goes through one extractor, so the
    # same destination gets the same answer whichever tool writes it.
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

    # Path printers: they transform a string and write nothing, which is why a
    # missing `realpath` rule was able to withdraw the grant from a 30-segment
    # loop whose every other command was allowlisted.
    ("silent", "realpath /workspace/ui"),
    ("silent", "basename /workspace/a/b"),
    ("silent", "dirname /workspace/a/b"),
    ("silent", "readlink -f /workspace/ui"),
    ("allow",  'echo "$(realpath /workspace/ui)"'),
    ("allow",  'if [ -d /workspace/ui ]; then echo "$(basename /tmp/x)"; fi'),
    # `file` reads magic bytes, except -C, which compiles a magic.mgc.
    ("silent", "file /workspace/a.bin"),
    ("silent", "file -b --mime-type /workspace/a.bin"),
    ("silent", "file -c -m /workspace/magic"),        # lowercase c only prints
    ("ask",    "file -C -m /workspace/magic"),
    ("ask",    "file --compile -m /workspace/magic"),
    ("ask",    "file -bC -m /workspace/magic"),       # bundled with -b
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
    # -- builtins and grouping no rule can name ----------------------------
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
    # ...but quoted it is inert, exactly as `<(` is. A C++ template closing
    # onto a call -- `foo<T>()` -- puts `>(` in an ordinary grep pattern.
    ("silent", 'echo ">(rm -rf x)"'),
    ("silent", "echo '>(rm -rf x)'"),
    ("silent", 'grep -rn "failpoint<[^>]*>()" --include=*.cpp .'),
    ("ask",    "diff `git show a` f"),            # backticks still refused
    ("ask",    'echo "`tee /tmp/f`"'),            # and inside "" they DO expand

    # -- heredocs: the body is stdin data, not a command list --------------
    # Verified against bash before these were written, because the whole fix
    # turns on one distinction: a QUOTED delimiter makes the body literal,
    # while an UNQUOTED one still expands $(...) inside it. Skipping every
    # body would therefore hide a real command.
    ("silent", "cat <<'EOF'\nls -la\nEOF"),
    ("silent", "cat <<'EOF'\nrm -rf /\nEOF"),     # data: the shell never runs it
    ("silent", "cat <<EOF\nrm -rf /\nEOF"),       # no expansion here either
    ("silent", "cat << 'CMDEOF'\ngit fetch origin 2>&1 | tail -2\nCMDEOF"),
    ("silent", "cat <<'EOF'\nEOFX\nEOF"),         # only an exact line ends it
    ("silent", "cat <<-EOF\n\ttabbed\n\tEOF"),    # <<- strips leading TABS
    ("silent", "cat <<- EOF\n\ttabbed\n\tEOF"),   # blanks may follow the operator
    ("silent", "cat <<'EOF' | grep -c x\nbody\nEOF"),
    # The expansion cases -- the reason the body cannot simply be skipped.
    ("ask",    "cat <<EOF\n$(rm -rf /tmp/x)\nEOF"),
    ("silent", "cat <<'EOF'\n$(rm -rf /tmp/x)\nEOF"),
    # Any quoting of the DELIMITER suppresses expansion, not just '': both of
    # these were checked against bash, having first been written the wrong way
    # round here on the assumption that only '' counted.
    ("silent", 'cat <<"EOF"\n$(rm -rf /tmp/x)\nEOF'),
    ("silent", "cat <<\\EOF\n$(rm -rf /tmp/x)\nEOF"),
    # An unquoted body's substitution is inspected, not refused outright --
    # a read-only one must still come back clean.
    ("allow",  "cat <<EOF\n$(cat /workspace/f)\nEOF"),
    ("silent", "cat <<'A' <<'B'\nx\nA\ny\nB"),   # bodies consumed in order
    # Nothing around the heredoc stops being inspected.
    ("ask",    "cat <<'EOF' > /tmp/f\nbody\nEOF"),
    ("ask",    "cat <<'EOF'\nbody\nEOF\nrm -rf /tmp/y"),
    ("ask",    "rm -rf /tmp/y\ncat <<'EOF'\nbody\nEOF"),
    # A receiver that executes its stdin is ALWAYS_ASK on its own name, which
    # is what makes skipping bodies safe at all.
    ("ask",    "bash <<'EOF'\nls\nEOF"),
    ("ask",    "python3 - <<'PY'\nprint(1)\nPY"),
    # Shapes whose body cannot be bounded: a missing terminator, and one that
    # bash rejects for trailing whitespace, so the body swallows the rest.
    ("ask",    "cat <<'EOF'\nbody"),
    ("ask",    "cat <<'EOF'\nbody\nEOF \nrm -rf /tmp/y"),
    # `<<<` is a herestring, a different operator, and it expands.
    ("silent", "cat <<<hello"),
    ("ask",    'cat <<<"$(rm -rf /tmp/x)"'),

    # -- git: locating the subcommand, and the diff machinery's --output ---
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
    # Safe today only because none are allowlisted: a `Bash(timeout:*)` rule
    # would let `timeout 30 rm -rf x` through with no prompt at all.
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
    # commands on two lines collapse into one whose argv0 is the FIRST.
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
    # An assignment and a loop word both reach INSIDE a substitution now, so
    # these agree with the same commands written one level out.
    ("allow",  'F=/tmp/x.log; echo "$(wc -l \"$F\")"'),
    ("allow",  'F=/tmp/x.log; echo "$(sed -n 1,5p \"$F\")"'),
    ("allow",  'for j in A B; do printf "%s" "$(git shortlog A)"; done'),
    ("allow",  'for j in A B; do printf "%s" "$(git shortlog $j)"; done'),
    # Every value is checked, so one bad word in the list refuses the lot --
    # it must not pass on the strength of the first.
    ("ask",    'for f in a.txt -i; do echo "$(sed $f /workspace/x)"; done'),
    # A binding written AFTER the substitution has not run yet.
    ("ask",    'echo "$(sed -n 1,5p \"$F\")"; F=/tmp/x.log'),

    # Arithmetic read as a substitution closing at the first `)` left the parse
    # broken, so the guard fell silent and a write placed AFTER it ran
    # unprompted. The same write BEFORE it was caught, which hid this.
    ("ask",    "echo $((1+1)); sed -i s/a/b/ /workspace/f"),
    ("ask",    "echo $((1+1)); tee /workspace/f"),
    ("ask",    "echo $((1+1)); rm -rf /workspace/d"),
    ("ask",    "sed -i s/a/b/ /workspace/f; echo $((1+1))"),
    # Arithmetic itself is inert: it yields an integer, so it can never produce
    # a write flag, and bash does not fall back to a subshell -- `$((echo hi))`
    # is a syntax error, not a command. Reading a range through it is read-only.
    ("silent", 'sed -n "1905,$((1905+8))p" /workspace/f'),
    ("allow",  "wc -l /tmp/f; echo $((1+1))"),
    ("allow",  'for l in 1905 2003; do sed -n "${l},+8p" /workspace/f; done'),
    # A body that can RUN something still refuses: $( ) inside arithmetic is
    # evaluated, and a `[` subscript is evaluated as an expression too.
    ("ask",    "echo $(( $(id -u) + 1 ))"),
    ("ask",    "echo $((x[1]+1))"),
    # `$( (cmd) )` needs the space to be a subshell, so it stays a real
    # substitution and its commands are still read.
    ("ask",    "echo $( (tee /workspace/f) )"),
    # A name asks even here: arithmetic is read before the loop is unrolled, so
    # `l` is still a name. `,+8p` needs no arithmetic and allows.
    ("ask",    'for l in 1905 2003; do sed -n "${l},$((l+8))p" /workspace/f; done'),
    # Single quotes do not expand arithmetic, so it stays literal text.
    ("silent", "grep -c '$((1+1))' /workspace/f"),

    # An absolute `cd` makes a following relative COMMAND word resolvable, so
    # an allowlisted script invoked as ./x is recognised as the same script.
    ("allow",  "cd /opt/bin; ./tool.py --test"),
    ("allow",  "cd /opt/bin; ./tool.py --test 2>&1 | tail -12"),
    ("allow",  "cd /opt; ./bin/tool.py --test"),
    ("allow",  "cd /opt/bin/../bin; ./tool.py --test"),
    # Nothing to resolve against: no cd at all, or one the guard cannot read.
    # Each leaves the cwd unknown rather than guessing, so ./tool.py stays
    # unrecognised and the rules decide alone.
    ("silent", "./tool.py --test"),
    ("silent", "cd /opt/bin; cd sub; ./tool.py --test"),
    ("silent", "cd sub; ./tool.py --test"),
    ("silent", "cd; ./tool.py --test"),
    ("silent", "cd ~; ./tool.py --test"),
    ("silent", "cd -; ./tool.py --test"),
    ("silent", 'D=/opt/bin; cd "$D/x"; ./tool.py --test'),
    # A cd in a pipeline runs in a subshell, so it never moved the parent and
    # must not be honoured -- on either side of the pipe.
    ("silent", "cd /opt/bin | true; ./tool.py --test"),
    ("silent", "true | cd /opt/bin; ./tool.py --test"),
    # But a pipe ELSEWHERE in the line changes no directory, so it must not
    # discard a cwd already established. Clearing on every `|` cost exactly
    # this shape: the first command piped into tail, and every later relative
    # word -- including inside a loop -- stopped resolving.
    ("allow",  "cd /opt/bin; ./tool.py --test 2>&1 | tail -6; ./tool.py --test"),
    ("allow",  'cd /opt/bin; ./tool.py -t 2>&1 | tail -6; echo "=="; '
               'for h in tool tool; do printf "%-4s " "$h"; '
               './$h.py -t 2>&1 | tail -1; done'),
    # A cd inside a pipeline is DISCARDED at the statement end rather than
    # poisoning what follows: the subshell moved, the parent did not, so the
    # earlier cwd is still the right answer for ./tool.py.
    ("allow",  "cd /opt/bin; false | cd /tmp; ./tool.py --test"),
    ("allow",  "cd /opt/bin; true | tail -1; ./tool.py --test"),
    # Backgrounding is a subshell too, so its cd is discarded the same way.
    ("silent", "cd /opt/bin & ./tool.py --test"),
    ("allow",  "cd /opt/bin; true & ./tool.py --test"),

    # The guard's own tooling, granted from the published table rather than
    # from local_grants.py. These paths ship with this repo, so the grant is
    # portable -- and being in the guard proper is what makes it testable here,
    # since local grants are disabled for these cases.
    ("allow",  "~/.claude/hooks/bash-write-guard.py --test"),
    ("allow",  "~/.claude/hooks/comment-ratio-gate.py --test"),
    ("allow",  "~/.claude/hooks/commit-message-gate.py --test"),
    ("allow",  "~/.claude/hooks/review-text-gate.py --test"),
    ("allow",  "~/.claude/tools/guard-verdict.py --expect ask"),
    ("allow",  "~/.claude/tools/check-settings.py"),
    # A neighbour in the same directory is not covered by the set. The grant is
    # per file, never per directory.
    ("silent", "~/.claude/hooks/not-a-real-gate.py --test"),
    ("silent", "~/.claude/tools/not-a-real-tool.py"),
    # A write still asks: being our own tool says the file is read-only when
    # run as intended, not that any command naming it is.
    ("ask",    "sed -i s/a/b/ ~/.claude/hooks/review-text-gate.py"),
    # A bare name is a PATH lookup, not a relative path -- rewriting it would
    # invent a file that bash never looks for.
    ("silent", "cd /opt/bin; tool.py --test"),
    # An assignment prefix holds the command position without being the
    # command. It is also a `/`-bearing word, so resolving it rewrote the
    # assignment itself into a path and broke the segment.
    ("allow",  "cd /opt/bin; F=/tmp/x.log ./tool.py --test"),
    # cd cannot launder a write: resolving the cwd says where the write lands,
    # never that it is allowed.
    ("ask",    "cd /opt/bin; sed -i s/a/b/ f"),
    ("ask",    "cd /opt/bin; ./tool.py --out f > g"),
]

# Known gaps, asserted at their CURRENT behavior so they are written down
# rather than rediscovered. Each is a shape where a write-capable flag reaches
# an allowlisted tool through data the guard cannot read. Closing one makes the
# assertion below fail -- that is the reminder to move it into CASES.
GAPS = [
]

# Known OVER-asks, asserted at their current behavior. Nothing here is unsafe --
# each prompts for something read-only -- but they are pinned for the same
# reason as GAPS: so the shape is written down rather than rediagnosed, and so
# closing one is a visible event rather than a silent loosening.
#
# Kept apart from GAPS deliberately. A gap is a hole and wants closing; an
# over-ask is a nuisance, and the tempting "fix" is to relax the check that
# produced it. Reading them as one list invites trading the first for the
# second.
OVER_ASKS = [
    # Refused with toolDenialKind=permission-rule while `echo "$HOME"` runs, so
    # the braces alone decide it -- and a guard allow does not override this.
    ("silent", 'echo "${HOME}"'),
]


# why-prompt.py's cases: (label, segment, env, expected paths outside TEST_ROOTS).
#
# The workspace gate is checked against the RESOLVED path, so a token that is
# only a path after a variable expands still has to be reported. Reading argv
# alone finds nothing there, and why-prompt.py answered "no prompt expected" for
# a command that prompted every time -- which got blamed on a stale session
# twice before the env block was consulted.
#
# The guard is deliberately NOT changed to match. Expanding these there would
# make it vouch for the path and emit "allow", which BYPASSES the very gate that
# is doing its job. Diagnosis wants the wider view; the grant does not.
WHY_PROMPT_CASES = [
    ("literal path outside",
     ["ls", "-l", "/elsewhere/f"], {}, ["/elsewhere/f"]),
    ("literal path inside",
     ["ls", "-l", "/workspace/f"], {}, []),
    ("env var resolving outside",
     ["ls", "-l", "$SOCK"], {"SOCK": "/elsewhere/.ssh/sock"},
     ["/elsewhere/.ssh/sock"]),
    ("env var in braces",
     ["ls", "-l", "${SOCK}"], {"SOCK": "/elsewhere/.ssh/sock"},
     ["/elsewhere/.ssh/sock"]),
    ("env var resolving inside",
     ["ls", "-l", "$SOCK"], {"SOCK": "/workspace/sock"}, []),
    # An unknown name stays as written: reporting a path the command does not
    # touch is worse than reporting none.
    ("unknown var is not guessed at",
     ["ls", "-l", "$MYSTERY"], {}, []),
]


# why-prompted.py's cases: (label, transcript lines, needle, expected records).
# Each expected record is (decision, reason, waited); `waited` is the
# tool_use -> tool_result gap in seconds.
_WP_USE = ('{"type":"assistant","timestamp":"%s","message":{"content":'
           '[{"type":"tool_use","id":"%s","name":"Bash",'
           '"input":{"command":%s}}]}}')
_WP_RESULT = ('{"type":"user","timestamp":"%s","message":{"content":'
              '[{"type":"tool_result","tool_use_id":"%s"}]}}')
# The same record when the call was refused. toolDenialKind sits beside the
# message, not inside it, and it is the ONLY place the outcome is written down.
_WP_DENIED = ('{"type":"user","timestamp":"%s","toolDenialKind":"%s",'
              '"message":{"content":'
              '[{"type":"tool_result","tool_use_id":"%s"}]}}')
_WP_HOOK = ('{"type":"attachment","timestamp":"%s","attachment":'
            '{"hookName":"PreToolUse:Bash","toolUseID":"%s",'
            '"stdout":"{\\"hookSpecificOutput\\": {\\"permissionDecision\\": '
            '\\"%s\\", \\"permissionDecisionReason\\": \\"%s\\"}}"}}')

WHY_PROMPTED_CASES = [
    # The case the tool exists for: the hook recorded WHY it asked.
    ("hook ask is reported with its reason",
     [_WP_USE % ("2026-01-01T00:00:00.000Z", "t1", '"ls /tmp"'),
      _WP_HOOK % ("2026-01-01T00:00:00.100Z", "t1", "ask", "guard says no"),
      _WP_RESULT % ("2026-01-01T00:02:00.000Z", "t1")],
     "ls /tmp", [("ask", "guard says no", 120.0, None)]),
    # No hook line at all is NOT the same as an allow, and saying "allowed"
    # there would invent a record. Older transcripts simply do not carry one.
    ("missing hook record is reported as unknown",
     [_WP_USE % ("2026-01-01T00:00:00.000Z", "t2", '"ls /tmp"'),
      _WP_RESULT % ("2026-01-01T00:00:00.500Z", "t2")],
     "ls /tmp", [(None, None, 0.5, None)]),
    # A command that never finished has no result line, so there is no elapsed
    # time to report -- distinct from an elapsed time of zero.
    ("no result line leaves the wait unknown",
     [_WP_USE % ("2026-01-01T00:00:00.000Z", "t3", '"ls /tmp"'),
      _WP_HOOK % ("2026-01-01T00:00:00.100Z", "t3", "ask", "guard says no")],
     "ls /tmp", [("ask", "guard says no", None, None)]),
    # Matching is on the command text, so a fragment finds the whole command.
    # Anything else would need the caller to retype a multi-line command
    # exactly, which is the transcription trap this tool is meant to end.
    ("a fragment matches",
     [_WP_USE % ("2026-01-01T00:00:00.000Z", "t4", '"grep -rn foo bar | head"'),
      _WP_HOOK % ("2026-01-01T00:00:00.100Z", "t4", "allow", "fine")],
     "grep -rn foo", [("allow", "fine", None, None)]),
    ("a non-match finds nothing",
     [_WP_USE % ("2026-01-01T00:00:00.000Z", "t5", '"ls /tmp"'),
      _WP_HOOK % ("2026-01-01T00:00:00.100Z", "t5", "allow", "fine")],
     "something else", []),
    # The hook's decision is not the outcome. Reading only the hook reported a
    # refused command as allowed, which is the wrong answer to the one question
    # this tool exists to settle.
    ("a hook allow that was refused anyway is reported as denied",
     [_WP_USE % ("2026-01-01T00:00:00.000Z", "t7", '"ls /tmp"'),
      _WP_HOOK % ("2026-01-01T00:00:00.100Z", "t7", "allow", "cleared"),
      _WP_DENIED % ("2026-01-01T00:00:04.000Z", "permission-rule", "t7")],
     "ls /tmp", [("allow", "cleared", 4.0, "permission-rule")]),
    # A malformed line must not take the scan down with it: transcripts are
    # appended to live, so the last line can be a partial write.
    ("a truncated line is skipped",
     ['{"type":"assistant","timestamp":"2026-01-01T00:00',
      _WP_USE % ("2026-01-01T00:00:00.000Z", "t6", '"ls /tmp"'),
      _WP_HOOK % ("2026-01-01T00:00:00.100Z", "t6", "ask", "guard says no")],
     "ls /tmp", [("ask", "guard says no", None, None)]),
]
