"""Template for hooks/local_grants.py -- copy, rename, edit. NEVER commit it.

bash-write-guard.py is deliberately generic. Grants tied to a machine, an
employer, or an internal toolchain go here instead, so the guard itself stays
publishable. If this file is absent the guard simply has no extra grants.

Contract
--------
    extra_grant(segment, guard) -> bool

`segment` is one simple command as a token list, e.g. ["make", "-j8", "test"].
`guard` is a view of the guard module, for its helpers (guard.REDIRECTS,
guard.read_list, guard.matches, ...).

Returning True BYPASSES the permission prompt for that command. It is checked
only after the allow rules fail to match, and only for commands the guard has
already verified are not write-capable.

Grant only what you would approve every single time without reading it, and
prefer narrow shapes over whole commands. `make` is not a safe grant; `make
--dry-run` is. If a flag's arity is unknown, refuse -- a value-taking flag can
swallow the next token and hide what is really being run.

Any exception raised here is swallowed and treated as "no grant", so a bug means
silent loss of the grant rather than a crash. `bash-write-guard.py --test` calls
this function once for real to catch exactly that.
"""


# Example: allow a dry-run build, and nothing else.
DRY_RUN_FLAGS = {"-n", "--dry-run", "--just-print"}


def extra_grant(segment, guard):
    if segment[:1] == ["make"]:
        return any(token in DRY_RUN_FLAGS for token in segment[1:])
    return False
