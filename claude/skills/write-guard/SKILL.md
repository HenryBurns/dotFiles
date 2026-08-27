---
name: write-guard
description: Rules for changing the Bash permission guard at ~/.claude/hooks/bash-write-guard.py. Use when editing that hook, adding or loosening a check in it, diagnosing why a Bash command did or did not prompt, adding a Bash(...) allow rule or additionalDirectories entry to ~/.claude/settings.json, or publishing any of it via the dotfiles sync. Covers the ask/allow/silent contract, the design rules a new check must obey, and what "done" means.
---

# Changing the Bash write guard

This skill is the judgment and the procedure. It deliberately does **not** describe what the
guard checks — that lives in the code, where it cannot drift:

| Question | Read |
|---|---|
| What does it check, and why this flag? | `~/.claude/hooks/bash-write-guard.py` — the tables carry their own rationale |
| What are the two jobs? | its module docstring |
| Why did *this* command prompt? | `~/.claude/tools/why-prompt.py '<the exact command>'` |
| How does a prompt get decided at all? | `claude/README.md` in the dotfiles repo (not installed into `~/.claude`) |
| Site-specific grants | `~/.claude/hooks/local_grants.py`, untracked — never put a local path or an internal name in the guard itself |

## Threat model

**Reads should flow without interruption; writes should prompt.** That asymmetry is the entire
point — it is not a bug that a read-only command needs no approval, and it is not a win to
prompt more often in general.

So the two error directions are not equals:

- **Over-asking** is a papercut, fixable later, and acceptable. Falling back to a prompt for an
  operation that is read-only under all but a couple of flags is fine.
- **Under-asking** is the failure that matters. A write that runs with no prompt cannot be
  undone by iterating.

When a change trades one for the other, take the over-ask.

## The verdict contract

Three outcomes. Only `allow` can leak, because only `allow` bypasses the prompt:

| verdict | meaning |
|---|---|
| `ask` | "I understand this construct, and it is write-capable." |
| `allow` | "I understand *every* command position here, and all are read-only and already allowlisted." |
| `silent` | "I do not understand this construct." The rules decide alone. |

`silent` is for genuine incomprehension — a backtick, a process substitution, `case/esac`,
nesting past the depth cap. Deferring is honest there.

**Never downgrade a positive identification to `silent`.** If the guard worked out that a
construct is write-capable, it must say `ask`. Throwing away something it actually knows is
the one move it must not make.

A hook `allow` also overrides the workspace-path gate, not just the command-rule gate. That is
intended — it is what lets a verified read-only compound touch a readable path outside the
workspace — but it means an `allow` is the only decision with real blast radius. Weigh it
accordingly.

## Design rules for a new check

**Expand before checking.** Resolve what a command actually *is* — variable assignments,
literal loop words, wrapper prefixes — in the one shared `expand()` pass, then let both the
write check and the permission check consume the result. A fix placed there lands everywhere;
a fix placed at one call site cures a symptom and leaves its siblings broken. Several
"separate" bugs here turned out to be one missing expansion.

**Opaque, not forbidden.** A value the guard cannot read (a `$(...)` result) should become a
placeholder that later checks treat as unknown — not a hard refusal. Refusing what you cannot
read makes ordinary commands prompt; tracking it as unknown keeps the information.

**Prefix rules cannot express "read-only forms only."** A write flag can appear anywhere after
the command name, so `Bash(sed:*)` covers `sed -i` and `Bash(find:*)` covers `find -delete`.
For those tools the guard is the *only* layer, not a second line of defence — an allow rule and
a guard check are not redundant with each other.

**Naming a subcommand in a rule still admits every flag it takes.** `Bash(git branch:*)` reads
as narrow but permits `git branch -f`, which resets an existing branch and discards where it
pointed. Two live bugs had this shape. When allowlisting a subcommand, enumerate its write
flags in the guard in the same change.

**Unknown flag → treat as a write** wherever the check counts positional arguments, since one
unconsumed value-taking flag corrupts the count.

**Wrappers earn their unwrapping.** Only unwrap a prefix when the wrapper cannot itself write,
takes its command as real argv (not a shell string), and does not change identity. The
`WRAPPERS` table records why each candidate was accepted or rejected — extend it rather than
special-casing a name in code.

**Fail closed.** A crash must still emit `ask`. The guard was once fail-*open*: a raised
exception exited non-zero with no stdout, which a `PreToolUse` hook treats as a non-blocking
error, leaving the rules to decide alone. `_decide()` plus the top-level `except` is what
prevents that, and `_fail_closed_ok()` proves it. Do not add an early `return`/`sys.exit` path
around it.

## Definition of done

1. `~/.claude/hooks/bash-write-guard.py --test` — all cases, 0 unexpected.
2. **Every fix earns a case.** Add the command that was mishandled, not a paraphrase of it.
3. A gap you cannot close goes in `_GAPS`, asserted at its *current* behaviour, so closing it
   later fails the suite as a reminder. Never leave a known hole undocumented.
4. Verify through the real interface, not just the unit under test: feed the hook a JSON
   `tool_input` on stdin and read the verdict. Several fixes looked right in isolation and did
   nothing end to end.
5. Publishing: `python3 claude/sync.py --check`, then `sync.py`. Its keyword scan **aborts** on
   workplace-specific content — including in test cases, which is how a real path once got
   caught on its way out. Use a neutral placeholder path in cases.
6. `settings.json` is read **at startup only** — a new rule or directory needs a Claude Code
   restart before it is live. Hook files are re-read per command and need no restart.
   `why-prompt.py` warns when settings are newer than the running process; believe it.

## Traps

**The test fixture is not the real rule set.** `_TEST_RULES` is a small stand-in. A case
prompting there may only mean the fixture lacks the rule — this produced three wrong diagnoses
in a row. Check `settings.json` before concluding the guard is at fault.

**Do not trust a reduced repro that drops a segment.** Shortening a failing compound can remove
the very ingredient that caused it (a leading `cd` changes which paths are in-workspace).
Reproduce with the command exactly as it was run, then reduce.

**Prompts are the bug report.** Nearly every real defect here was found by asking "why did this
mundane command prompt?", not by auditing. Take the question seriously: an unexpected prompt on
a read-only command usually means the guard misread the command, and the same misreading can
run the other way.
