# Claude Code configuration

Portable half of `~/.claude`. Everything here is safe for a public repo; the
machine- and workplace-specific half stays local and is listed under
[What is deliberately absent](#what-is-deliberately-absent).

```sh
python3 claude/install.py            # repo  -> ~/.claude   (merges, backs up)
python3 claude/sync.py               # ~/.claude -> repo    (strips local bits)
python3 claude/sync.py --check       # report drift, write nothing
~/.claude/hooks/bash-write-guard.py --test
```

`settings.json` is read **at startup only** — restart Claude Code after
installing. Hook files are re-read on every command and need no restart.

## Why a prompt happens

Two independent gates. Both must pass, or you get a prompt:

1. **The command** matches an allow rule. In a compound command *every* segment
   must match — one uncovered segment prompts the whole line.
2. **Every path it touches** is inside the workspace: the project directory or
   `permissions.additionalDirectories`.

One exception, and it is the write guard's whole leverage: a hook returning
`allow` bypasses **both** gates, which is how a verified read-only compound can
read a path outside the workspace. Nothing else overrides gate 2.

Gate 2 is the one that wastes time, because it looks identical to a missing
rule. `ls -la ~/.bashrc` prompts even with `Bash(ls:*)` allowed, because it
resolves outside the workspace. `ls -la ~/work/thing/.gitignore` is fine — the
tilde is irrelevant, only where it resolves matters.

When something prompts unexpectedly, ask rather than guess:

```sh
~/.claude/tools/why-prompt.py 'cd /some/dir && grep -n foo bar | head'
```

It reports the per-segment rule match, out-of-workspace paths, command
substitution, the write-guard verdict, and warns if `settings.json` was modified
after the running process started.

To check a batch of commands instead of one, or to assert what they should
produce:

```sh
~/.claude/tools/guard-verdict.py 'sed -i s/a/b/ /tmp/x' 'echo hi | tee /etc/x'
~/.claude/tools/guard-verdict.py --quiet --expect ask 'rm -rf /tmp/x' 'mv a b'
```

It runs each command through the guard the way Claude Code does — a JSON
`tool_input` on stdin — so it reports what the hook really emits rather than
what importing the module suggests. Commands are only ever *judged*, never run.
`--expect` exits non-zero on any mismatch, so it can gate a check.

## The write guard

`hooks/bash-write-guard.py` is a `PreToolUse` hook doing two narrow jobs, both
of which exist because allow rules are literal prefix matches:

- **Downgrade writes to a prompt.** `Bash(sed:*)` cannot tell `sed -n` from
  `sed -i`, nor `cat f` from `cat f > g`. The guard inspects redirect targets
  (so `2>/dev/null` and `2>&1` stay silent), in-place flags, `find -delete`,
  `sort -o`, awk programs that redirect or `system()`, `git branch -D`,
  `git --output`, and a list of unconditional writers.
- **Clear read-only compounds.** Shell control flow has no command name to
  allowlist, so `for f in a b; do grep -c x "$f"; done` always prompted however
  read-only it was. When every command position is verified read-only *and*
  already allowlisted, the guard returns `allow`.

It emits one of three verdicts. Only `allow` bypasses a prompt, so silence can
never itself be a leak:

| verdict | output | effect |
|---|---|---|
| `ask` | `permissionDecision: ask` | prompts even if the rules would have cleared it |
| `allow` | `permissionDecision: allow` | **bypasses** the prompt |
| `silent` | nothing | the rules decide |

The guard never guesses toward `allow`. Backticks, `>(cmd)`, unbalanced quotes
and nesting past the depth cap resolve to `ask` — they can hide commands it
cannot read, and for an allowlisted command silence would let them through.

`$(...)` and unquoted `<(...)` are read rather than refused: both substitute
data (output, or a `/dev/fd` path) rather than syntax, so their only new risk is
the commands inside the parens, and those are checked like any others. That is
what lets `diff <(git show a) <(git show b)` clear while `diff <(rm -rf x) f`
still asks.

### Tests

The cases live in the file itself and print their own count:
`bash-write-guard.py --test`. Every fix adds the command that was mishandled, so
the suite is a list of real defects rather than invented inputs. Among them: a
nested `"` inside `$(...)` making `img->$f` parse as a redirect; `shlex` treating
`#` as a comment anywhere, so `for c in a; do echo hi#; rm -rf x; done` verified
as safe while bash still ran the `rm`; an unquoted newline collapsing a compound
so that a trailing `rm -rf` was never examined; and a raised exception exiting
non-zero with no stdout, which a `PreToolUse` hook treats as non-blocking — the
guard was fail-*open* until `_decide()` and `_fail_closed_ok()` closed it.

Gaps that cannot be closed yet go in `_GAPS`, asserted at their *current*
behaviour rather than hidden, so closing one fails the suite as a reminder. The
list is empty at present; the mechanism stays because the next gap wants writing
down, not discovering twice.

`skills/write-guard/SKILL.md` carries the rules for changing any of this — the
`ask`/`allow`/`silent` contract, what a new check must obey, and what "done"
means.

## What is deliberately absent

`sync.py` drops these on the way out and prints what it dropped. It also runs a
keyword scan over everything about to be written and **aborts** on a hit — that
check is the point of the script, since a rule or comment naming an internal
project would otherwise be published by whoever next runs the sync.

| Not published | Why |
|---|---|
| `permissions.additionalDirectories` | local absolute paths, per machine |
| `hooks/local_grants.py` | site-specific grants; see `local_grants.example.py` |
| `hooks/allowed-blueprints` | internal test names |
| `~/.claude/CLAUDE.md` | workplace build and branch conventions |
| `.credentials.json`, `history.jsonl`, `projects/` | secrets, command history, transcripts |

After `install.py`, add back locally:

- `permissions.additionalDirectories` for any tree outside the project you need
  to read. The installer preserves these across runs.
- `hooks/local_grants.py`, if you want grants for local tooling.

Note `~/.gitignore_global` here ignores `CLAUDE.md` and `.claude/` globally, so
those names cannot be committed to *any* repo by accident. This directory is
`claude/` without the dot for exactly that reason.
