#!/usr/bin/env python3
"""Report what fraction of a change is comments, against the code it lands in.

    comment-ratio.py                      # the HEAD commit
    comment-ratio.py origin/main..HEAD    # a range
    comment-ratio.py a7a1a28              # one commit
    comment-ratio.py --staged             # what is about to be committed
    comment-ratio.py --worktree -v        # uncommitted, listing the comments

A raw comment percentage means nothing on its own: a filesystem checker's
internals and an integration test have very different natural densities. So
every added line is classified (comment / code / blank) and compared with the
same measurement of the file as it was *before* the change -- for a new file,
of its siblings in the same directory. The verdict is about the delta, not the
absolute number.

Classification is a real scanner, not a regex: it tracks block comments, raw
strings and char literals for C/C++ and Go, and uses tokenize for Python, so a
"//" inside a string or a "#" inside a docstring is not miscounted. A line with
a trailing comment counts as code; those are reported separately.

The ratio is an aggregate, and a long function dilutes it -- a six-line comment
over a two-line guard sails through a compliant ratio. So blocks longer than the
code they introduce are reported separately, and --max-block gates on them.

Exit status is 1 only when an explicit --max-ratio, --max-multiple or
--max-block is given and exceeded, so the script is usable both as a gate and as
a look-at-it tool.
"""

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tokenize

CPP_EXTS = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx",
            ".h++", ".inl", ".ipp", ".cu", ".cuh"}
GO_EXTS = {".go"}
PY_EXTS = {".py", ".pyi"}

# A change is only interesting once it has enough comment lines to argue about.
MIN_COMMENTS_FOR_VERDICT = 3
# How far above the surrounding density we start calling it heavy.
HEAVY_MULTIPLE = 1.5


def language_of(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in CPP_EXTS:
        return "cpp"
    if ext in GO_EXTS:
        return "go"
    if ext in PY_EXTS:
        return "python"
    return None


def git(args, cwd=None, allow_fail=False):
    """Run git and return stdout, or None when allow_fail and it errors."""
    proc = subprocess.run(["git", "-c", "core.quotepath=false"] + args,
                          cwd=cwd, capture_output=True)
    if proc.returncode != 0:
        if allow_fail:
            return None
        sys.exit("git %s failed: %s" % (" ".join(args),
                                        proc.stderr.decode(errors="replace").strip()))
    return proc.stdout.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Scanners.  Each returns a list of (has_code, has_comment) per line, so a line
# is a comment line only when it holds a comment and nothing else.
# --------------------------------------------------------------------------

def scan_c_like(text, go=False):
    """Character scanner for C, C++ and Go.

    Handles // and /* */, string and char literals, C++ raw strings and Go
    backtick strings, all of which can otherwise swallow or fake a comment.
    """
    marks = []
    in_block = False        # inside /* */
    raw_end = None          # closing delimiter of a raw string, if inside one
    for line in text.split("\n"):
        has_code = has_comment = False
        i, n = 0, len(line)
        while i < n:
            if raw_end is not None:
                idx = line.find(raw_end, i)
                has_code = True
                if idx < 0:
                    break
                i, raw_end = idx + len(raw_end), None
                continue
            if in_block:
                idx = line.find("*/", i)
                if line[i:(idx if idx >= 0 else n)].strip() or idx >= 0:
                    has_comment = True
                if idx < 0:
                    break
                i, in_block = idx + 2, False
                continue
            c = line[i]
            nxt = line[i + 1] if i + 1 < n else ""
            if c == "/" and nxt == "/":
                has_comment = True
                break                      # rest of the line is comment
            if c == "/" and nxt == "*":
                has_comment, in_block, i = True, True, i + 2
                continue
            if c == '"':
                has_code = True
                # C++ raw string: R"delim( ... )delim"
                if not go and i > 0 and line[i - 1] == "R":
                    m = re.match(r'([^()\\ ]*)\(', line[i + 1:])
                    if m:
                        raw_end = ")%s\"" % m.group(1)
                        i += 1 + m.end()
                        continue
                i = skip_quoted(line, i, '"')
                continue
            if c == "`" and go:
                has_code = True
                idx = line.find("`", i + 1)
                if idx < 0:
                    raw_end = "`"
                    break
                i = idx + 1
                continue
            if c == "'":
                has_code = True
                # In C++ a quote between digits is a separator: 1'000'000.
                if not go and i > 0 and (line[i - 1].isalnum() or line[i - 1] == "_"):
                    i += 1
                    continue
                i = skip_quoted(line, i, "'")
                continue
            if not c.isspace():
                has_code = True
            i += 1
        marks.append((has_code, has_comment))
    return marks


def skip_quoted(line, i, quote):
    """Return the index just past the literal opening at line[i]."""
    i += 1
    while i < len(line):
        if line[i] == "\\":
            i += 2
            continue
        if line[i] == quote:
            return i + 1
        i += 1
    return i        # unterminated; the newline ends it for our purposes


def scan_python(text, docstrings_are_comments=True):
    """Tokenize Python, treating a bare string statement as documentation."""
    lines = text.split("\n")
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return scan_python_fallback(text, docstrings_are_comments)

    code = set()
    comment = set()
    meaningful = []
    for t in toks:
        if t.type == tokenize.COMMENT:
            comment.add(t.start[0])
        elif t.type != tokenize.NL:
            meaningful.append(t)

    skip = {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
            tokenize.ENCODING, tokenize.ENDMARKER}
    starters = {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
                tokenize.ENCODING}
    for idx, t in enumerate(meaningful):
        if t.type in skip:
            continue
        docstring = False
        if t.type == tokenize.STRING and docstrings_are_comments:
            prev = meaningful[idx - 1].type if idx else tokenize.ENCODING
            nxt = (meaningful[idx + 1].type if idx + 1 < len(meaningful)
                   else tokenize.NEWLINE)
            docstring = (prev in starters
                         and nxt in (tokenize.NEWLINE, tokenize.ENDMARKER))
        target = comment if docstring else code
        for ln in range(t.start[0], t.end[0] + 1):
            if lines[ln - 1].strip():       # blanks inside a docstring stay blank
                target.add(ln)

    marks = []
    for n, line in enumerate(lines, 1):
        has_code, has_comment = n in code, n in comment
        # Anything non-blank that no token claimed (a bare "\" continuation) is code.
        if line.strip() and not has_code and not has_comment:
            has_code = True
        marks.append((has_code, has_comment))
    return marks


def scan_python_fallback(text, docstrings_are_comments=True):
    """Used when a file does not tokenize (a partial or broken source file)."""
    marks = []
    fence = None            # (delimiter, is_documentation) of an open triple quote
    for line in text.split("\n"):
        has_code = has_comment = False
        i, n = 0, len(line)
        while i < n:
            if fence:
                delim, is_doc = fence
                idx = line.find(delim, i)
                if line[i:(idx if idx >= 0 else n)].strip() or idx >= 0:
                    if is_doc:
                        has_comment = True
                    else:
                        has_code = True
                if idx < 0:
                    break
                i, fence = idx + 3, None
                continue
            c = line[i]
            if c == "#":
                has_comment = True
                break
            if c in "\"'":
                if line[i:i + 3] in ('"""', "'''"):
                    delim = line[i:i + 3]
                    # A triple quote opening its own statement is documentation;
                    # one on the right of an "=" is just a string.
                    is_doc = (docstrings_are_comments and not has_code
                              and not line[:i].strip())
                    if is_doc:
                        has_comment = True
                    else:
                        has_code = True
                    idx = line.find(delim, i + 3)
                    if idx < 0:
                        fence = (delim, is_doc)
                        break
                    i = idx + 3
                    continue
                has_code = True
                i = skip_quoted(line, i, c)
                continue
            if not c.isspace():
                has_code = True
            i += 1
        marks.append((has_code, has_comment))
    return marks


def classify(text, lang, docstrings_are_comments=True):
    if lang == "python":
        return scan_python(text, docstrings_are_comments)
    return scan_c_like(text, go=(lang == "go"))


# --------------------------------------------------------------------------
# Diff parsing
# --------------------------------------------------------------------------

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def added_lines_by_file(diff_args):
    """Map path -> sorted list of line numbers added, from a -U0 diff."""
    out = git(["diff", "-U0", "-M", "--no-color",
               "--diff-filter=ACMR"] + diff_args)
    files, path = {}, None
    for line in out.split("\n"):
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                path = None
            else:
                path = target[2:] if target.startswith("b/") else target
                if path.startswith('"') and path.endswith('"'):
                    path = path[1:-1].encode().decode("unicode_escape")
                files.setdefault(path, [])
            continue
        m = HUNK_RE.match(line)
        if m and path:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            files[path].extend(range(start, start + count))
    return files


def read_new(path, new_rev, root):
    if new_rev is None:                       # worktree
        full = os.path.join(root, path)
        try:
            with open(full, "r", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None
    if new_rev == ":":                        # index
        return git(["show", ":" + path], cwd=root, allow_fail=True)
    return git(["show", "%s:%s" % (new_rev, path)], cwd=root, allow_fail=True)


def ratio(code, comment):
    total = code + comment
    return (comment / total) if total else None


# A block this short is not worth reporting however lopsided it looks: two lines
# over a one-line statement is ordinary.
MIN_BLOCK_LINES = 3


def top_heavy_blocks(marks, added, lines, min_block=MIN_BLOCK_LINES):
    """Added comment blocks longer than the code they introduce.

    The ratio is an aggregate and a big function dilutes it, so a comment block
    several times the length of its statement passes unnoticed.  This is the
    local check: it reads each run of comment-only added lines against the code
    run that follows it.
    """
    out, n, i = [], len(marks), 0
    while i < n:
        if (i + 1) not in added or marks[i][0] or not marks[i][1]:
            i += 1
            continue
        start = i
        while i < n and (i + 1) in added and not marks[i][0] and marks[i][1]:
            i += 1
        block = i - start

        code, blanks, j = 0, 0, i
        while j < n:
            has_code, has_comment = marks[j]
            if has_code:
                code, blanks = code + 1, 0
            elif has_comment:
                break                     # the next block starts here
            else:
                blanks += 1
                if blanks >= 2:           # a gap ends the statement it introduces
                    break
            j += 1

        if block >= min_block and block > code:
            out.append(dict(line=start + 1, comment=block, code=code,
                            text=lines[start].strip()))
    return out


def baseline_for(path, lang, base_rev, root, docstrings, cache):
    """Comment ratio of the code this change is landing in.

    The file as it was before the change, or -- for a new file -- up to a dozen
    of its neighbours, which is the density a reviewer would compare against.
    """
    text = git(["show", "%s:%s" % (base_rev, path)], cwd=root, allow_fail=True)
    if text is not None:
        marks = classify(text, lang, docstrings)
        code = sum(1 for c, m in marks if c)
        comment = sum(1 for c, m in marks if m and not c)
        return ratio(code, comment), "prior version"

    directory = os.path.dirname(path)
    key = (directory, lang)
    if key not in cache:
        listing = git(["ls-files", "--", directory or "."],
                      cwd=root, allow_fail=True) or ""
        siblings = [p for p in listing.split("\n")
                    if p and os.path.dirname(p) == directory
                    and language_of(p) == lang and p != path][:12]
        code = comment = 0
        for sib in siblings:
            text = git(["show", "%s:%s" % (base_rev, sib)],
                       cwd=root, allow_fail=True)
            if text is None:
                continue
            marks = classify(text, lang, docstrings)
            code += sum(1 for c, m in marks if c)
            comment += sum(1 for c, m in marks if m and not c)
        cache[key] = (ratio(code, comment),
                      "%d sibling file%s" % (len(siblings),
                                             "" if len(siblings) == 1 else "s"))
    return cache[key]


# --------------------------------------------------------------------------

def resolve_range(args):
    """Return (diff_args, base_rev, new_rev, label). new_rev None = worktree."""
    if args.staged:
        return ["--cached"], "HEAD", ":", "staged changes"
    if args.worktree:
        return ["HEAD"], "HEAD", None, "working tree vs HEAD"
    rev = args.revision or "HEAD"
    if ".." in rev:
        base, _, new = rev.partition("..")
        new = new.lstrip(".") or "HEAD"
        base = base or "HEAD"
        return [rev], base, new, rev
    return ["%s^" % rev, rev], "%s^" % rev, rev, rev


def analyze(args):
    root = (git(["rev-parse", "--show-toplevel"]) or "").strip()
    diff_args, base_rev, new_rev, label = resolve_range(args)
    docstrings = not args.docstrings_as_code

    files, skipped, cache = [], [], {}
    for path, lines in sorted(added_lines_by_file(diff_args).items()):
        if not lines:
            continue
        lang = language_of(path)
        if lang is None:
            skipped.append((path, len(lines)))
            continue
        text = read_new(path, new_rev, root)
        if text is None:
            skipped.append((path, len(lines)))
            continue
        marks = classify(text, lang, docstrings)
        text_lines = text.split("\n")
        blocks = top_heavy_blocks(marks, set(lines), text_lines)
        code = comment = blank = trailing = 0
        samples = []
        for ln in lines:
            if ln > len(marks):
                continue
            has_code, has_comment = marks[ln - 1]
            if has_code:
                code += 1
                if has_comment:
                    trailing += 1
            elif has_comment:
                comment += 1
                samples.append((ln, text_lines[ln - 1].strip()))
            else:
                blank += 1
        base_ratio, base_kind = (None, "")
        if not args.no_baseline:
            base_ratio, base_kind = baseline_for(path, lang, base_rev, root,
                                                 docstrings, cache)
        files.append(dict(path=path, lang=lang, added=len(lines), code=code,
                          comment=comment, blank=blank, trailing=trailing,
                          ratio=ratio(code, comment), baseline=base_ratio,
                          baseline_kind=base_kind, comment_lines=samples,
                          heavy_blocks=blocks))
    return files, skipped, label


def pct(value):
    return "  --  " if value is None else "%5.1f%%" % (value * 100)


def report(files, skipped, label, args):
    code = sum(f["code"] for f in files)
    comment = sum(f["comment"] for f in files)
    trailing = sum(f["trailing"] for f in files)
    overall = ratio(code, comment)

    # Weight each file's baseline by how much of the change landed in it.
    weight = sum(f["code"] + f["comment"] for f in files if f["baseline"] is not None)
    base = None
    if weight:
        base = sum(f["baseline"] * (f["code"] + f["comment"])
                   for f in files if f["baseline"] is not None) / weight

    if args.json:
        print(json.dumps(dict(range=label, files=files, skipped=skipped,
                              total=dict(code=code, comment=comment,
                                         trailing=trailing, ratio=overall,
                                         baseline=base)), indent=2))
        return verdict_code(overall, base, comment, args, files)

    width = max([28] + [min(len(f["path"]), 56) for f in files]) if files else 28
    print("comment-ratio: %s\n" % label)
    print("%-*s  %5s %5s %5s  %6s  %8s" %
          (width, "FILE", "ADDED", "CODE", "CMNT", "RATIO", "BASELINE"))
    for f in files:
        name = f["path"]
        if len(name) > width:
            name = "..." + name[-(width - 3):]
        print("%-*s  %5d %5d %5d  %s  %s" %
              (width, name, f["added"], f["code"], f["comment"],
               pct(f["ratio"]), pct(f["baseline"])))
    if files:
        print("%-*s  %5d %5d %5d  %s  %s" %
              (width, "TOTAL", sum(f["added"] for f in files), code, comment,
               pct(overall), pct(base)))
    else:
        print("(no C/C++, Go or Python lines added)")
    if trailing:
        print("\n%d added code line%s a trailing comment."
              % (trailing, " also carries" if trailing == 1 else "s also carry"))
    if skipped:
        print("\nNot analyzed (unknown language): "
              + ", ".join("%s (+%d)" % (p, n) for p, n in skipped))

    heavy = [(f["path"], b) for f in files for b in f["heavy_blocks"]]
    if heavy:
        heavy.sort(key=lambda pb: pb[1]["comment"] - pb[1]["code"], reverse=True)
        shown = heavy if args.verbose else heavy[:5]
        print("\nComment blocks longer than the code they introduce (%d):" % len(heavy))
        for path, b in shown:
            print("  %s:%d  %d comment line%s over %d of code"
                  % (path, b["line"], b["comment"],
                     "" if b["comment"] == 1 else "s", b["code"]))
            print("      %s" % b["text"][:96])
        if len(shown) < len(heavy):
            print("  ... %d more (-v to list)" % (len(heavy) - len(shown)))

    if args.verbose:
        for f in files:
            if not f["comment_lines"]:
                continue
            print("\n%s" % f["path"])
            for ln, textline in f["comment_lines"]:
                print("  %6d  %s" % (ln, textline))

    print()
    print(verdict_text(overall, base, comment, files))
    return verdict_code(overall, base, comment, args, files)


def verdict_text(overall, base, comment, files):
    if overall is None:
        return "Verdict: nothing to judge."
    if base is None or base == 0:
        return ("Verdict: %.1f%% of added lines are comments; no baseline to "
                "compare against." % (overall * 100))
    multiple = overall / base
    kinds = sorted({f["baseline_kind"] for f in files if f["baseline_kind"]})
    against = " (baseline: %s)" % ", ".join(kinds) if kinds else ""
    if comment < MIN_COMMENTS_FOR_VERDICT:
        return ("Verdict: %d comment line%s added -- too few to be heavy."
                % (comment, "" if comment == 1 else "s"))
    if multiple >= HEAVY_MULTIPLE:
        return ("Verdict: HEAVY -- %.1f%% comments vs %.1f%% in the surrounding "
                "code, %.1fx the local density%s."
                % (overall * 100, base * 100, multiple, against))
    return ("Verdict: in line -- %.1f%% comments vs %.1f%% locally, %.1fx%s."
            % (overall * 100, base * 100, multiple, against))


def verdict_code(overall, base, comment, args, files=()):
    # The block gate stands on its own: a top-heavy block is worth failing on
    # even when the aggregate ratio is comfortably in line, which is exactly the
    # case the ratio cannot see.
    if args.max_block is not None:
        for f in files:
            for b in f["heavy_blocks"]:
                if b["comment"] > max(b["code"] * args.max_block, MIN_BLOCK_LINES):
                    return 1
    if overall is None or comment < MIN_COMMENTS_FOR_VERDICT:
        return 0
    if args.max_ratio is not None and overall > args.max_ratio:
        return 1
    if args.max_multiple is not None and base:
        if overall / base > args.max_multiple:
            return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        epilog="Ratio is comment lines / non-blank added lines; a line with a "
               "trailing comment counts as code.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("revision", nargs="?", metavar="REV|RANGE",
                        help="commit or range to analyze (default: HEAD)")
    parser.add_argument("--staged", "--cached", action="store_true",
                        dest="staged", help="analyze the staged changes")
    parser.add_argument("--worktree", action="store_true",
                        help="analyze uncommitted changes against HEAD")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="list every added comment line")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--no-baseline", action="store_true",
                        help="skip measuring the surrounding code")
    parser.add_argument("--docstrings-as-code", action="store_true",
                        help="count Python docstrings as code, not comments")
    parser.add_argument("--max-ratio", type=float, metavar="F",
                        help="exit 1 if the comment ratio exceeds F (0-1)")
    parser.add_argument("--max-multiple", type=float, metavar="F",
                        help="exit 1 if the ratio exceeds F times the baseline")
    parser.add_argument("--max-block", type=float, nargs="?", const=1.0,
                        metavar="F",
                        help="exit 1 if any comment block is longer than F times "
                             "the code it introduces (default F=1)")
    args = parser.parse_args()
    if args.staged and args.worktree:
        parser.error("--staged and --worktree are mutually exclusive")

    files, skipped, label = analyze(args)
    return report(files, skipped, label, args)


if __name__ == "__main__":
    sys.exit(main())
