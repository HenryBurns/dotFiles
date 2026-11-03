---
name: slack-messages
description: How Henry wants Slack messages shaped when Claude sends one on his behalf - a short top-level message with the details in a thread reply under it. Use whenever sending, drafting or scheduling a Slack message or DM with the Slack MCP tools (slack_send_message, slack_send_message_draft, slack_schedule_message), alongside the plugin's slack:slack-messaging skill, which covers formatting syntax.
---

# Slack messages: brief on top, detail in the thread

Messages go out under Henry's name, and most readers see only the notification or the first line.
**Every message is two parts:**

1. **The top-level message is one or two sentences**: what this is and where to find it. A link,
   an ask, or a status, enough to act on without opening anything.
2. **Everything else goes in a thread reply to that message**: the code, the reasoning,
   corrections, caveats, and how to reproduce. It should be there for whoever wants to dig in, never
   required reading.

Send the top-level message first, then post the detail with `thread_ts` set to the `message_ts` it
returned. Never put both in one message.

## Example

Henry's own rewrite of a message Claude sent as a single block, handing a colleague a fix to compare
with their draft. The top level became one line:

> Here's the experiment I mentioned, pushed so you can compare it with your draft:
> `<branch>` (`<sha>`, one file, `<file>`).

and the code snippet, a second class that needed the same change, a correction to the ticket, the
untested caveat with its reproduce command, and "it's yours to take" all moved into one reply under
it.

## What stays in the top-level message

- the link, branch, review or ticket the message is about
- the one thing being asked or offered
- a status that changes what the reader does ("untested", "merged", "blocked on X") **only if it
  changes what they do next**; otherwise it goes in the thread too

Anything with a code block, a list, or a second paragraph belongs in the thread.

## Related

- Formatting syntax for the MCP message tools (bold, code blocks, links): `slack:slack-messaging`.
- Messages go out under Henry's name: confirm before sending unless he asked for it to be sent.
