#!/usr/bin/env python3
"""Explain why a Bash command would trigger a permission prompt.

    why-prompt.py 'cd /some/dir && grep -n foo bar | head'
    echo '<command>' | why-prompt.py

Claude Code splits a compound command on shell operators and requires EVERY
segment to match an allow rule, so one uncovered segment prompts the whole
line. This prints the per-segment verdict, then checks whether the local
write-guard hook would force a prompt on top of that.

Reuses bash-write-guard.py for the write detection so there is one source of
truth rather than two copies that drift.
"""

import importlib.util
import json
import os
import shlex
import sys

HOME = os.path.expanduser("~")
GUARD = os.path.join(HOME, ".claude", "hooks", "bash-write-guard.py")

OPERATORS = {"&&", "||", "|", ";", "&", "|&", "(", ")"}


def load_guard():
    """Import the hook by path; its filename isn't a valid module name."""
    try:
        spec = importlib.util.spec_from_file_location("bash_write_guard", GUARD)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def process_start(pid):
    """Epoch seconds when `pid` started, or None. Linux /proc only."""
    try:
        with open("/proc/stat") as handle:
            boot = next(int(l.split()[1]) for l in handle if l.startswith("btime"))
        with open(f"/proc/{pid}/stat") as handle:
            # comm can contain spaces and parens; fields resume after the last ')'
            fields = handle.read().rsplit(")", 1)[1].split()
        return boot + int(fields[19]) / os.sysconf("SC_CLK_TCK")
    except (OSError, StopIteration, IndexError, ValueError):
        return None


def claude_start_time():
    """Start time of the ancestor `claude` process, walking up from our parent."""
    pid = os.getppid()
    for _ in range(12):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                cmdline = handle.read().decode("utf-8", "replace")
            with open(f"/proc/{pid}/stat") as handle:
                ppid = int(handle.read().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            return None
        if "claude" in cmdline and "why-prompt" not in cmdline:
            return process_start(pid)
        if ppid <= 1:
            return None
        pid = ppid
    return None


def staleness_warning(cwd):
    """Warn if settings.json is newer than the running Claude process."""
    started = claude_start_time()
    if started is None:
        return None
    newest = None
    for label, path in settings_sources(cwd):
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if newest is None or mtime > newest[0]:
            newest = (mtime, label, path)
    if newest and newest[0] > started:
        age = int((newest[0] - started) / 60)
        return (f"STALE: {newest[2]} was modified {age} min AFTER Claude "
                f"started.\n  Rules added since then are NOT live. Restart to "
                f"apply them.")
    return None


def settings_sources(cwd):
    """Settings files that contribute rules, in load order."""
    return [
        ("user", os.path.join(HOME, ".claude", "settings.json")),
        ("project", os.path.join(cwd, ".claude", "settings.json")),
        ("local", os.path.join(cwd, ".claude", "settings.local.json")),
    ]


def collect_rules(cwd):
    """(prefix_rules, exact_rules, deny_rules), each as (pattern, source)."""
    prefix, exact, deny = [], [], []
    for label, path in settings_sources(cwd):
        try:
            with open(path) as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        perms = data.get("permissions") or {}
        for rule in perms.get("allow") or []:
            if not rule.startswith("Bash(") or not rule.endswith(")"):
                continue
            body = rule[5:-1]
            if body.endswith(":*"):
                prefix.append((body[:-2], label))
            else:
                exact.append((body, label))
        for rule in perms.get("deny") or []:
            if rule.startswith("Bash(") and rule.endswith(")"):
                body = rule[5:-1]
                deny.append((body[:-2] if body.endswith(":*") else body, label))
    return prefix, exact, deny


def split_segments(command, guard):
    """Segments as the guard sees them, not as the raw text reads.

    Substitutions are replaced by a placeholder and literal `for` loops and
    assignments are expanded first, exactly as bash-write-guard.py does. Doing
    it any other way prints segments the guard never judged -- a nested quote
    inside $(...) used to surface here as a bogus `>` redirect.
    """
    spans = guard.substitution_spans(command)
    text = command if spans is None else guard.strip_substitutions(command, spans)
    try:
        tokens, _ = guard.expand(guard.tokenize(text))
    except ValueError as exc:
        raise SystemExit(f"could not parse command: {exc}")
    segments, current = [], []
    for token in tokens:
        if token in OPERATORS:
            if current:
                segments.append(current)
            current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return [" ".join(seg) for seg in segments]


def match(text, rules):
    for pattern, source in rules:
        if text == pattern or text.startswith(pattern + " "):
            return pattern, source
    return None, None


def main():
    command = " ".join(sys.argv[1:]).strip() or sys.stdin.read().strip()
    if not command:
        raise SystemExit("usage: why-prompt.py '<bash command>'")

    cwd = os.getcwd()
    guard = load_guard()
    if guard is None:
        raise SystemExit(f"could not load guard hook at {GUARD}")
    prefix, exact, deny = guard.collect_rules(cwd)

    print(f"cwd: {cwd}")
    print(f"rules: {len(prefix)} prefix, {len(exact)} exact, {len(deny)} deny")
    stale = staleness_warning(cwd)
    print(f"\n{stale}\n" if stale else "")

    blockers = []

    spans = guard.substitution_spans(command)
    if spans is None:
        print("command substitution: a form the guard will not read -- a "
              "backtick,\n  <(...), or an unbalanced quote. That always asks.\n")
        blockers.append("opaque substitution")
    elif spans:
        print(f"command substitution: {len(spans)} x $(...)")
        print("  -> no prefix rule can ever match one. The write-guard hook")
        print("     grants it when every command inside is read-only and")
        print("     allowlisted; otherwise this prompts.\n")
        blockers.append("command substitution")

    for pattern, source in exact:
        if command == pattern:
            print(f"whole-command exact rule matches ({source}) -> allowed")
            break

    roots = guard.workspace_roots(cwd)
    segments = split_segments(command, guard)
    width = min(max((len(s) for s in segments), default=10), 52)
    print(f"{'segment':<{width}}  verdict")
    print("-" * (width + 26))
    for segment in segments:
        shown = segment if len(segment) <= width else segment[:width - 2] + ".."
        denied, dsource = match(segment, deny)
        if denied:
            verdict = f"DENIED by Bash({denied}) [{dsource}]"
            blockers.append(f"{segment.split()[0]}: denied")
        else:
            hit, source = match(segment, prefix)
            if hit:
                verdict = f"ok   Bash({hit}:*) [{source}]"
            else:
                verdict = "NO RULE MATCHES"
                blockers.append(f"{segment.split()[0]}: no rule")
        print(f"{shown:<{width}}  {verdict}")

        stray = guard.outside_workspace(segment.split(), roots)
        if stray:
            print(f"{'':<{width}}  ^ OUTSIDE WORKSPACE: {', '.join(stray)}")
            blockers.append(f"path outside workspace: {stray[0]}")

    print()
    if guard.guard_disabled():
        print("write-guard: standing down (allowlisted worktree)")
    else:
        reasons = guard.find_reasons(command)
        if reasons:
            print(f"write-guard: WOULD ASK -- {'; '.join(reasons)}")
            blockers.append("write-guard")
        elif guard.grant_verdict(command, cwd):
            print("write-guard: ALLOWS (control flow, $(...) substitution, "
                  "and/or a local grant; every command cleared)")
            # An active grant overrides the rule-level blockers above: the hook
            # runs before the permission check and its allow is authoritative.
            # Out-of-workspace paths are NOT cleared -- that gate is separate.
            blockers = [b for b in blockers if b.startswith("path outside")]
        else:
            print("write-guard: silent")

    print()
    if blockers:
        print(f"VERDICT: prompts -- {'; '.join(blockers)}")
    else:
        print("VERDICT: no prompt expected (if the running session has this "
              "config loaded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
