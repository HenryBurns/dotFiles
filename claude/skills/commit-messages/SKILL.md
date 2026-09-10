---
name: commit-messages
description: Write a commit message sized to the change rather than to the analysis behind it. Use when writing, amending, rewording or reviewing a commit message, when splitting or reordering a commit series, or when creating a revert or fixup commit. Covers the subject line, what the description must contain, how long it should be and why, what to cut first, and the rules for revert and fixup messages.
---

# Commit messages

Tool-independent. Which trailers are mandatory, which ticket id belongs in the subject, and what
enforces them are local conventions and belong in a skill about that repo.

Messages matter beyond tidiness: reviewers use them for context, and whoever decides whether a
change is safe to backport judges scope and risk from the message alone, often months later.

## Subject

- A headline-style summary, ideally **under 72 characters**.
- **The second line must be blank** — otherwise git folds the body into the subject.
- Make it expressive: many contexts show only this line (`git log --oneline`, `git rebase -i`,
  review notifications).

## Description

Address three things:

1. What problem is this solving, or what functionality is it adding — and what happens if we don't?
2. What changes does it make, and how do they address that?
3. What alternatives were considered, and why this one?

These are **prompts, not a template**. Answer them in clauses. Three paragraphs because there are
three questions is how a trivial change acquires an essay — and drop question 3 entirely unless a
reader would otherwise object to the approach.

## Size the description to the change, not to the analysis

This is the rule that fails most often, so it is worth stating as a number rather than a feeling.

Measured over 250 commits of real history, the median body is **3–6 lines at every change size** —
the local norm barely grows with the diff. `commit-message-gate.py` in this repo enforces a ceiling
near that history's 90th percentile:

| Lines changed | Aim for | Refused above |
|---|---|---|
| ≤ 20 | ≤ 5 | 10 |
| 21–100 | ~5 | 14 |
| 101–500 | ~10 | 18 |
| 501+ | ~15 | 28 |

Body means content lines after the subject: blanks and trailers do not count, since their length is
not a choice. Calibrate against your own history rather than adopting these numbers on faith — the
point is that a measured norm exists and is much shorter than instinct suggests.

**Complete means covering everything the change does — not everything you learned getting there.**
Those pull in opposite directions, and the second wins by default unless you budget first. A
one-line fix drew a 38-line description before being cut to 12, with nothing a reviewer needed lost.

Completeness itself is not the thing to trim. It has a safety rationale: reviewers rely on it to
notice something in the diff that the message never claimed, so the inventory of *effects* is
inviolable. It is the narrative of how you got there that is optional.

What to cut, in order:

- **Test output or evidence.** It belongs in the review, where a reader can act on it.
- **Derivation.** State the fact, do not prove it: "the expected model disagrees with the parser",
  not three paragraphs deriving why it does.
- **True and interesting but decision-irrelevant.** The hard one, because accuracy feels like
  justification. Ask which reader decision each sentence changes. Backport scope, risk and "why now"
  earn their place, because people act on them.

**Do not cut on the grounds that it is already in the ticket.** Some duplication is worth it: a
concise summary of the final change is hard to mine out of a ticket or a design doc, and the commit
outlives both. Restate the **conclusion** in the message; leave the **investigation** in the ticket.

## Trailers

Trailers go last, as a block, with a single blank line between the description and the first one.
Which ones are required is a local convention; `Signed-off-by` and `Co-Authored-By` are the
portable ones.

Whatever the local set, the same rule applies to all of them: a trailer names something, it does
not narrate it. A `Testing`-style trailer says what was run, not what the run printed — counts, ids
and artifact paths are evidence, and evidence belongs in the review.

## Reverts and fixups

- They **must** be created with `git revert` or `git commit --fixup`. The generated message has a
  format that tooling later parses to recombine a fixup with its original.
- **Never edit the generated part of the message.**
- **Do** append your own explanation: `git commit --amend`, blank line at the end, then write why
  the revert or fixup exists.

## What a checker can and cannot enforce

A gate can refuse a body past a ceiling, or a missing trailer. Nothing checks that the description
answers the three questions, or that a `Testing`-style trailer is *true* — only that it is present.
Those stay a matter of judgement, which is why a passing gate is not the same as a good message.
