---
name: code-comments
description: Write code comments that explain why rather than what, at the density of the code they land in. Use when adding, editing or reviewing a comment in any language, when a reviewer says a comment is too long, restates the code or explains what instead of why, or when trimming a change's comments before review. Covers the why-not-what test, what earns a comment, measuring density with comment-ratio.py, and what to cut first.
---

# Code comments

Language- and tool-independent. Which comments a language requires by convention (Go doc comments
on exported names, a license header) is a local rule and always stays.

## A comment says why, not what

> Documenting _what_ is not useful, it's obvious what the if case does. What's interesting, if you
> do want a comment, is to document _why_.
> (a reviewer, on a `// if X, do Y` comment above `if X: Y`)

Code already says what it does, so a "what" comment is a second copy that drifts from the first as
soon as someone edits the code. The reason a line is the way it is is the one thing the code cannot
say. That is what a comment is for.

Check every sentence:

| Sentence | Verdict |
|---|---|
| Restates the next line, the condition, or the function's name | **delete** |
| "X, so Y" | keep only **so Y**. X is the code |
| States an invariant (`filled once, never cleared`) | keep it **with** what relies on it: `..., so readers need no lock` |
| Explains something that looks like a bug but isn't (a retry, an odd ordering) | **keep**: this is the best kind |
| Says the same reason twice (header and implementation, two call sites) | keep the copy next to the code that would break |

**If nothing is left after the cuts, there is no comment.** That is a good outcome, not a gap.

Worked examples, before and after:

```
// Register the handler on the admin port too, so admin calls get their own worker pool.
// Admin calls get their own worker pool on this port.

// Returns false if the buffer is not one of ours.   <- on `bool TryRelease(Buffer*)`
(deleted: the name and the bool say it)

// Only borrowed buffers have an owner set. They didn't come from the pool and must not be returned to it.
// Borrowed buffers didn't come from the pool, so they must not go back to it.
```

## State the conclusion, never the derivation

A comment carries **what the reader must not break**, not the argument for why that's true. One
"because" is the limit, so stop after the first link of causation. A second derivation isn't what's
wrong; the first one already was, and the second just makes it visible.

The test isn't "is this true and relevant?", since every cut sentence passes that. The test is
**would a reader do anything differently if this sentence were deleted?**

The investigation behind a change (why the bug existed, what else was tried, how some other function
behaves today) belongs in the commit message or the ticket. A comment outlives both, and a paragraph
about another function's current behaviour goes stale as soon as that function changes.

**Intricate code doesn't earn extra lines.** The subtler the mechanism, the more a derivation feels
justified, and that's exactly when to distrust it. What a hard problem earns is *a comment where
none seemed necessary*: one sentence stating a conclusion the reader couldn't have inferred.

## Carry only what isn't obvious

- **Delete before rewording.** A well-named constant or function needs no comment.
- **Don't classify a list the reader can see.** Keep only the consequence: what breaks if someone
  adds or removes a member.
- **Generalize, don't enumerate.** One sentence naming the shared property beats two worked
  examples.
- **Don't restate an adjacent log or error string.** Read it first, then write only what it doesn't
  already say.
- **A comment goes before what it describes.** One trailing a definition, or attached to nothing,
  is misplaced, not just too long.

## Match the local density, and measure it

Write at the density of the code around the change. A change that comments at twice its file's rate
reads as foreign code, and reviewers say "too many comments" before they read any of them.

Measure instead of guessing. `comment-ratio.py` (shipped alongside this skill under `tools/`)
classifies added lines with real per-language scanners and compares them with the file they land
in:

```bash
comment-ratio.py --worktree                 # before committing
comment-ratio.py --staged --amend           # what an amend would produce
comment-ratio.py --max-multiple 1.5         # exit 1 past 1.5x the local density
comment-ratio.py --max-block                # exit 1 on any comment longer than the code it introduces
```

**Run `--max-block` as well as the ratio.** The ratio is an aggregate, so one long function dilutes
it: a six-line comment over a two-line guard can pass a compliant ratio. `--max-block` catches that
shape.

Passing the gate isn't the same as being right. A measure catches density; it can't catch a short
comment that only says what.

## Related

- The same discipline for commit messages: `commit-messages`.
- Applying a reviewer's comment feedback across a whole change, not just the flagged line:
  `code-review-practice`.
