#!/usr/bin/env python3
"""Approximate token cost of a Claude Code session, broken down by tool.

Answers "where did the context go?" -- which tools consumed the most payload,
which individual results were largest, and how much was the assistant's own
prose rather than tool output.

    transcript_cost.py                       # latest session for $PWD
    transcript_cost.py --top 25
    transcript_cost.py path/to/session.jsonl

Counts are chars/4, so treat them as +/-10%.  `thinking` blocks are not stored
in the transcript, so the real total is higher than the one reported here.
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

CHARS_PER_TOKEN = 4

# Tools whose first argument is a subcommand worth keeping in the family name,
# so `git log` and `git diff` are counted apart instead of lumped under `git`.
#
# Site-specific tools go in the untracked sidecar rather than here, one name per
# line: this file is published, and a list of internal tool names is itself a
# disclosure. Same reasoning, and same shape, as sync.py's sync-deny.local.
# The sidecar is read at import, so those tools break down exactly as the ones
# below do -- nothing is lost by moving a name out of this file.
SUBCOMMAND_TOOLS = ("git", "gh", "jj", "cargo", "npm", "docker", "kubectl")
LOCAL_TOOL_LIST = Path(__file__).with_name("subcommand-tools.local")


def subcommand_tools():
    """Known subcommand-taking tools, plus whatever the sidecar adds."""
    try:
        lines = LOCAL_TOOL_LIST.read_text().splitlines()
    except OSError:
        lines = []                     # no sidecar: the defaults stand alone
    # Per LINE, not per word: splitting the whole file on whitespace drops the
    # `#` and keeps every word of the comment after it as a tool name.
    extra = [line.strip() for line in lines]
    return set(SUBCOMMAND_TOOLS) | {n for n in extra if n and not n.startswith("#")}


# Read once: family() runs per transcript record.
KNOWN_SUBCOMMAND_TOOLS = subcommand_tools()


def config_dirs():
    """Candidate Claude config roots, most specific first."""
    seen, out = set(), []
    for cand in (os.environ.get("CLAUDE_CONFIG_DIR"),
                 Path.home() / ".claude",
                 Path("/u") / os.environ.get("USER", "") / ".claude"):
        if not cand:
            continue
        p = Path(cand)
        if p not in seen and p.is_dir():
            seen.add(p)
            out.append(p)
    return out


def latest_session(cwd=None):
    """Newest transcript for the given working directory, or None."""
    slug = str(Path(cwd or Path.cwd())).replace("/", "-")
    best = None
    for root in config_dirs():
        proj = root / "projects" / slug
        if not proj.is_dir():
            continue
        for f in proj.glob("*.jsonl"):
            if best is None or f.stat().st_mtime > best.stat().st_mtime:
                best = f
    return best


def family(cmd):
    """Name the command family a Bash invocation belongs to.

    Strips leading `cd ...&&` hops and VAR=x prefixes so the real executable is
    what gets counted, and keeps the subcommand for multiplexers like git.
    """
    s = re.sub(r'^(cd\s+\S+\s*(&&|;)\s*)+', '', cmd.strip())
    s = re.sub(r'^\w+=\S+\s+', '', s)
    m = re.match(r'([\w./-]+)', s)
    if not m:
        return "?"
    head = m.group(1).split('/')[-1]
    sub = re.match(r'([a-z_-]+)', s[m.end():].strip())
    if head in KNOWN_SUBCOMMAND_TOOLS and sub:
        return f"{head} {sub.group(1)}"
    return head


def result_text(block):
    """Flatten a tool_result content block to a string."""
    c = block.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "".join(p.get("text", "") for p in c if isinstance(p, dict))
    return ""


def analyse(path):
    uses = {}
    res = defaultdict(int)
    calls = defaultdict(int)
    inp_sz = defaultdict(int)
    biggest = []
    text_out = thinking_out = 0
    # Bash-only breakdown, gathered in the same pass.
    bash = {"fam_res": defaultdict(int), "fam_n": defaultdict(int),
            "exact": defaultdict(lambda: [0, 0]), "capped": [0, 0], "uncapped": [0, 0]}

    with open(path, errors="replace") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            msg = rec.get("message")
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for b in content:
                if not isinstance(b, dict):
                    continue
                t = b.get("type")
                if t == "tool_use":
                    name = b.get("name", "?")
                    inp = b.get("input", {})
                    blob = json.dumps(inp)
                    cmd = inp.get("command", "") if name == "Bash" else ""
                    uses[b.get("id")] = (name, blob[:160], cmd)
                    calls[name] += 1
                    inp_sz[name] += len(blob)
                elif t == "tool_result":
                    name, blob, cmd = uses.get(b.get("tool_use_id"), ("<unmatched>", "", ""))
                    n = len(result_text(b))
                    res[name] += n
                    biggest.append((n, name, blob))
                    if name == "Bash" and cmd:
                        f = family(cmd)
                        bash["fam_res"][f] += n
                        bash["fam_n"][f] += 1
                        e = bash["exact"][" ".join(cmd.split())[:200]]
                        e[0] += 1
                        e[1] += n
                        if "grep" in cmd:
                            slot = "capped" if re.search(r'\|\s*(head|tail|wc)\b', cmd) else "uncapped"
                            bash[slot][0] += 1
                            bash[slot][1] += n
                elif t == "text":
                    text_out += len(b.get("text", ""))
                elif t == "thinking":
                    thinking_out += len(b.get("thinking", ""))

    return res, calls, inp_sz, biggest, text_out, thinking_out, bash


def print_bash(bash, top, tok):
    """Command-family breakdown: where Bash time actually goes."""
    fam_res, fam_n = bash["fam_res"], bash["fam_n"]
    if not fam_res:
        print("\nNo Bash calls in this transcript.")
        return

    print(f"\n{'command family':<28} {'calls':>6} {'result~tok':>11} {'avg':>7}")
    print("-" * 56)
    for f in sorted(fam_res, key=lambda k: -fam_res[k])[:top]:
        print(f"{f:<28} {fam_n[f]:>6} {tok(fam_res[f]):>11,} {tok(fam_res[f] // fam_n[f]):>7,}")

    repeats = [(c, n, cmd) for cmd, (c, n) in bash["exact"].items() if c >= 3]
    if repeats:
        print("\nMost-repeated identical commands:")
        for c, n, cmd in sorted(repeats, reverse=True)[:top]:
            print(f"  {c:>3}x {tok(n):>8,} tok  {cmd[:96]}")

    cn, cc = bash["capped"]
    un, uc = bash["uncapped"]
    if cn or un:
        total = cn + un
        print(f"\ngrep hygiene: {cn}/{total} capped with head/tail/wc "
              f"({100.0 * cn / total:.0f}%)")
        print(f"  capped   {cn:>5} calls  {tok(cc):>9,} tok  "
              f"{tok(cc // max(cn, 1)):>6,}/call")
        print(f"  uncapped {un:>5} calls  {tok(uc):>9,} tok  "
              f"{tok(uc // max(un, 1)):>6,}/call")


def main():
    ap = argparse.ArgumentParser(
        description="Approximate token cost of a Claude Code session, by tool.")
    ap.add_argument("session", nargs="?",
                    help="path to a session .jsonl (default: latest for $PWD)")
    ap.add_argument("--top", type=int, default=15,
                    help="rows to show in each table (default 15)")
    ap.add_argument("--bash", action="store_true",
                    help="add a Bash breakdown: command families, repeated "
                         "commands, and grep capping rate")
    args = ap.parse_args()

    path = Path(args.session) if args.session else latest_session()
    if path is None:
        sys.exit("no transcript found for this directory; pass one explicitly")
    if not path.is_file():
        sys.exit(f"not a file: {path}")

    res, calls, inp_sz, biggest, text_out, thinking_out, bash = analyse(path)
    if not res and not text_out:
        sys.exit(f"no tool activity parsed from {path}")

    tok = lambda n: n // CHARS_PER_TOKEN
    total_res = sum(res.values())
    total_inp = sum(inp_sz.values())
    grand = total_res + total_inp + text_out + thinking_out

    print(f"{path}  ({path.stat().st_size / 1e6:.1f} MB)\n")
    print(f"{'tool':<46} {'calls':>6} {'result~tok':>11} {'input~tok':>10} {'avg/call':>9}")
    print("-" * 86)
    for name in sorted(res, key=lambda k: -res[k])[:args.top]:
        c = calls.get(name, 0)
        print(f"{name:<46} {c:>6} {tok(res[name]):>11,} "
              f"{tok(inp_sz.get(name, 0)):>10,} {tok(res[name] // max(c, 1)):>9,}")

    if args.bash:
        print_bash(bash, args.top, tok)

    print("\nLargest single tool results:")
    for n, name, blob in sorted(biggest, reverse=True)[:args.top]:
        print(f"  {tok(n):>9,} tok  {name:<38} {blob[:90]}")

    def pct(n):
        return f"{100.0 * n / grand:4.1f}%" if grand else "   -"

    print("\nTotals (~tokens, 4 chars/tok):")
    for label, n in (("tool results", total_res), ("tool inputs", total_inp),
                     ("assistant text", text_out), ("thinking", thinking_out)):
        print(f"  {label:<15}{tok(n):>10,}  {pct(n)}")
    print(f"  {'GRAND':<15}{tok(grand):>10,}")
    if not thinking_out:
        print("\n  note: thinking blocks are not stored in transcripts; true total is higher.")


if __name__ == "__main__":
    main()
