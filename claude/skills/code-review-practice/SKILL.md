---
name: code-review-practice
description: How code review works regardless of which review tool is in front of it - what a review contains, how to reply to reviewer comments, and how to apply feedback to a commit in the middle of a stack. Use when writing or trimming a reply to review feedback, splitting a change into one review per commit, amending a mid-stack commit to address a comment, or judging whether a review is ready to send out. Covers the reply discipline, assembling a review before sending it, and the reset/amend/replay recipe.
---

# Code review practice

Tool-independent. Everything here outlives whichever review system is in front of it, so the
mechanics — how to post, which API, how to escape a field — belong in a skill about that tool.

## One review per commit

Each review shows one commit's change, not everything beneath it. A stack of six commits is six
reviews, and each reviewer sees only the commit they were asked about.

This is why commit splitting and review structure are the same decision: a commit that does two
things produces a review nobody can approve cleanly.

## Assemble the whole review before any of it goes out

**Answer every comment, then send once.** Not because sending twice is untidy: because one
comment's resolution routinely changes another's. A reviewer's objection to an interface can make a
separate comment about its callers moot, and a suggestion you accept in one place often has to be
applied in three. Answering serially means the earlier answers are stale by the time the last one
is written, and the reviewer reads a set that contradicts itself.

So the unit of work is the whole set of replies, not each reply. Read them back together before
sending — that pass is where the contradictions show up.

Sending is the irreversible half. A draft can be abandoned; a notification cannot be recalled, and
a half-answered review has already reached everyone on it. If the tool separates drafting from
sending, that separation is the safety net and is worth using deliberately.

**Check who will be notified before sending.** Reviewer groups expand — two named groups became
four once path-based owners were added, and everyone in all four was mailed. Read the resolved
recipient list rather than assuming the blast radius from the names you typed.

## Always hand back a clickable link

Any time a review is touched — created, updated, a field changed, a reply drafted — end with the
**full URL as a markdown link**, not a bare id. The next step is always to open it, and an id means
reconstructing a URL by hand. Link every review touched, not just the last one.

## Evidence goes in the review, not the commit message

The commit message names what ran; the review carries the proof. Test output, counts, artifact
paths and run ids belong in the review's evidence field, where a reader can act on them, and not in
a commit message that will be read for years in `git log`.

One entry per suite, and a newer or wider run **replaces** the older one rather than being appended
below it. An evidence field that accumulates every run ever made stops being evidence and becomes a
changelog nobody reads to the bottom of.

## Replying to reviewer comments

Every comment gets answered **as a reply on that comment**. Not in the review description, not in
the commit message, not verbally — the reply belongs on the thread that raised it, where the next
reader finds it next to the code.

Answer every comment, including the ones you are not acting on — "not changing this, because X" is
an answer. A comment left with no reply reads as unseen.

**No standalone `--` (or `—`) in anything posted.** A dash pair standing in for an em dash reads as
machine-written, and a reply goes out under a person's name. Use a comma, a colon, a semicolon, or
two sentences. A flag inside quoted text (`grep --count`) is fine; it is the em-dash use that is
not.

### A reply to an accepted comment is "Done." — nothing more

**If the suggestion was taken as written, the entire reply is `Done.`** No restating the change, no
quoting the new code, no explaining what was wrong with the old code. The reviewer can read the
diff; they asked for it.

Three things that keep creeping in and must not:

- **Justifying the original.** "The six lines it replaced were derivation rather than contract..."
  The reviewer did not ask why it was written that way, and re-arguing a point already conceded
  reads as defensiveness.
- **Local tooling.** Which script measured it, which check now gates it, what got written down
  afterwards — **all of it is invisible to the reviewer and irrelevant to them.**
- **Counts and mechanics.** "renamed at 14 sites", "removed 5 lines" — the diff says so.

The exception is a **partial** accept, which needs exactly one sentence saying what was not done and
why, because the reviewer would otherwise have to find the inconsistency themselves:

```
Done -- switched both argument checks to the shared error code. Left the parse failure on its
own code, since it reports a different condition.
```

A comment you are declining, or one raising a design question, earns real prose. An accepted one
does not.

### Check who has already replied

Someone else, or an earlier session, may have answered some of the comments in between. "This review
has replies" is not "this review is answered" — match existing replies to individual comment ids
before drafting, or the reviewer gets the same answer twice.

Survey the **whole stack**, not just the reviews you expect feedback on. A new review can arrive on
any of them.

### Make the change first, then reply

**Do the work before writing the reply — always, unless explicitly told otherwise.** Not "here is
what I would do", not a menu of options, not a reply that promises a change. Apply it, verify it,
then answer.

A reply written ahead of the change is a promise the reviewer has to track, and it puts the review
in a state where the comment says one thing and the diff says another. Doing it first also collapses
the reply to `Done.` — which is the right length anyway.

This holds even when the change looks large. If the work turns out to be genuinely too big, or the
suggestion turns out to be wrong once attempted, *that* is what the reply says — and it is worth
far more than a guess, because it is now backed by having tried.

### Applying feedback is not finishing it

A reviewer flags an instance; the instance is rarely alone. Before replying "done" and re-sending,
check whether the same pattern occurs elsewhere in the change — otherwise the next round produces
the same comment on the next occurrence, and each round costs a full review cycle.

Measure where a measure exists — `comment-ratio.py --max-block` for comment bloat. Applying three
comments that moved the metric from 2.8x to 2.7x is a signal the reply is premature, not that the
work is done. A measure catches density; it does not catch a comment that is merely wrong, so it
does not replace reading the diff.

## Applying feedback to a mid-stack commit

Feedback almost always lands on a commit that is not the tip, and `git rebase -i` is unavailable in
this environment (interactive flags are not supported). Reset, amend, replay:

```bash
git branch backup/<topic> HEAD                       # cheap, and the only real safety net
git rev-list --reverse <target>..HEAD                # the commits to replay, in order

git reset --hard <target>
#   ... edit ...
git add -A && git commit --amend --no-edit
git cherry-pick <each sha from that list, in order>
```

**Verify with a diff against the backup, not by reading the cherry-pick output.** The tip should
differ from the backup by exactly the intended change and nothing else — this catches a cherry-pick
that resolved differently as well as an edit that reached further than intended:

```bash
git diff backup/<topic> HEAD --stat
```

A conflict here is real information, not just an obstacle: it means a later commit **depends on** the
one being amended. Confirm with `git log -S '<symbol>'` before concluding two commits are
independent — checking a single symbol is not enough, since the dependency is usually a shared
helper rather than the API under discussion.

Scoped edits need scoped tools. A rename confined to one function is a `sed` over that function's
line range, not a file-wide replace; check the count inside and outside the range before and after,
and the arithmetic should account for every occurrence.

Afterwards, re-post only the amended commit and confirm HEAD was not rewritten and the tree is clean.
