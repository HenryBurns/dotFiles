# Sourced by non-interactive bash via $BASH_ENV (set in ~/.claude/settings.json).
#
# IMPORTANT -- measured, not assumed: the Bash tool's OWN top-level shell does
# NOT source this file, even though BASH_ENV is in its environment at exec time
# and it is a plain non-interactive `/bin/bash -c` (not POSIX mode, where bash
# would consult $ENV instead). A nested `bash -c` from inside a command, with
# the identical environment, DOES source it. Why the top-level shell skips it
# is unexplained; do not rely on anything set here reaching a command directly.
#
# Two consequences:
#   * Anything a command genuinely needs goes in settings.json's `env` block,
#     which is applied at exec and does arrive -- that is how SSH_AUTH_SOCK is
#     set, and it is why BASH_ENV itself is visible at all.
#   * PATH cannot be fixed anywhere: the Bash tool sources a generated shell
#     snapshot whose LAST line is an unconditional `export PATH=...`, which
#     clobbers any earlier value. Call ~/.local/bin tools by absolute path.
#
# What remains useful here is the nested-shell case.
#
# Keep it cheap and SILENT -- it runs before every command, and anything printed
# here lands in that command's stdout and corrupts the output. No subshells, no
# sudo, no echo.

# Probe: proves whether this file was sourced. Silent, and the first thing to
# check when something set here fails to appear -- `printenv` it from a command.
export CLAUDE_BASH_ENV_SOURCED=1

case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) PATH="$HOME/.local/bin:$PATH" ;;
esac

case ":$PATH:" in
    *":$HOME/bin:"*) ;;
    *) PATH="$HOME/bin:$PATH" ;;
esac

export PATH

# The Bash tool's environment carries no SSH_AUTH_SOCK, so anything reaching the
# network over ssh cannot authenticate unless the command sets it itself. An
# inline `SSH_AUTH_SOCK=... cmd` prefix is the obvious workaround and a bad one:
# the write guard refuses variables that reroute authentication, so every such
# command prompts, and the variable is repeated on each line where it is easy to
# get wrong. Setting it once here is both safer and quieter.
#
# Guarded on both sides: an inherited value wins, and a missing or dead socket
# leaves the variable unset rather than pointing ssh at nothing.
if [ -z "$SSH_AUTH_SOCK" ] && [ -S "$HOME/.ssh/ssh_auth_sock" ]; then
    SSH_AUTH_SOCK="$HOME/.ssh/ssh_auth_sock"
    export SSH_AUTH_SOCK
fi
