# Sourced by every non-interactive bash via $BASH_ENV (set in ~/.claude/settings.json).
#
# Claude Code's Bash tool spawns `bash -c ...`, which reads no startup file at
# all: .bash_profile is login-shells-only and .bashrc is interactive-only. This
# is the one hook bash offers for that case.
#
# Keep it cheap and SILENT -- it runs before every command, and anything printed
# here lands in that command's stdout and corrupts the output. No subshells, no
# sudo, no echo.

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
