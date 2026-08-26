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
