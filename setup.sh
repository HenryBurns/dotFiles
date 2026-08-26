#!/usr/bin/env bash
# Install the portable dotfiles into $HOME.
#
#   ./setup.sh              copy the config files (safe, backs up on change)
#   ./setup.sh --full       also install zsh/oh-my-zsh, tpm, vim-plug, badwolf
#
# Deliberately bash: the work here is package installs, clones and file copies.
# The one part with a real data structure -- merging settings.json while keeping
# local-only keys -- is claude/install.py, which bash would do badly.
#
# Everything tracked in this repo is portable. Machine- and work-specific
# settings live in untracked siblings that the tracked files source:
#
#   ~/.gitconfig.local      identity, work aliases   (via git [include])
#   ~/.vimrc.local          linter executables, per-host settings
#   ~/.zshrc.local          work paths, tool wrappers
#   ~/.bash_aliases.local   work aliases
#
# Create those FIRST on a machine whose settings are worth keeping. In
# particular your name and email now come from ~/.gitconfig.local, so
# installing .gitconfig without it leaves you with no git identity.

set -u
cd "$(dirname "$0")" || exit 1

FULL=0
[ "${1:-}" = "--full" ] && FULL=1

# Copy into $HOME, keeping a timestamped backup if the target differs. Never
# silently discards an existing file -- that is the whole point.
install_file() {
    src="$1"
    dst="$HOME/$1"
    if [ ! -e "$dst" ]; then
        cp "$src" "$dst" && echo "  created  $dst"
    elif cmp -s "$src" "$dst"; then
        echo "  current  $dst"
    else
        cp "$dst" "$dst.bak-$(date +%Y%m%d-%H%M%S)" \
            && echo "  backed up $dst"
        cp "$src" "$dst" && echo "  updated  $dst"
    fi
}

echo "config files:"
install_file .gitignore_global
install_file .gitconfig
install_file .bash_aliases
install_file .tmux.conf
install_file .vimrc
install_file .zshrc

if [ -z "${SKIP_CLAUDE:-}" ] && command -v python3 >/dev/null 2>&1; then
    echo "claude code:"
    # Merges into ~/.claude, preserving local additionalDirectories, extra allow
    # rules and hooks/local_grants.py; backs up the previous settings.json.
    # See claude/README.md. Restart Claude Code afterwards.
    python3 claude/install.py
fi

# Apply the new shell config immediately. Only possible when this script was
# SOURCED from zsh -- run as ./setup.sh it is a bash process, and sourcing a
# zshrc from bash produces a screenful of syntax errors rather than a new shell.
apply_zshrc() {
    if [ -n "${ZSH_VERSION:-}" ]; then
        # shellcheck disable=SC1090
        source "$HOME/.zshrc"
        echo "  reloaded ~/.zshrc"
    else
        echo "  run 'source ~/.zshrc' (or open a new shell) to pick up changes"
    fi
}

if [ "$FULL" -eq 0 ]; then
    echo
    echo "Skipped package installs and plugin managers. Re-run with --full for:"
    echo "  zsh + oh-my-zsh, tpm (tmux), vim-plug, badwolf colorscheme"
    apply_zshrc
    return 0 2>/dev/null || exit 0
fi

#######
# ZSH #
#######
# oh-my-zsh's installer moves any existing .zshrc to .zshrc.pre-oh-my-zsh, so
# it runs BEFORE .zshrc is put back in place.
if [ ! -d "$HOME/.oh-my-zsh" ]; then
    sudo apt-get install -y zsh
    chsh -s "$(which zsh)"
    sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    install_file .zshrc
fi

########
# TMUX #
########
# .tmux.conf manages plugins with tpm and expects it at this exact path.
# Afterwards press prefix + I inside tmux to install the plugins it lists.
[ -d "$HOME/.tmux/plugins/tpm" ] \
    || git clone https://github.com/tmux-plugins/tpm "$HOME/.tmux/plugins/tpm"

#######
# VIM #
#######
mkdir -p "$HOME/.vim/colors"
[ -f "$HOME/.vim/colors/badwolf.vim" ] \
    || wget -q https://raw.githubusercontent.com/sjl/badwolf/refs/heads/master/colors/badwolf.vim \
            -O "$HOME/.vim/colors/badwolf.vim"
# .vimrc uses vim-plug; install it, then run :PlugInstall inside vim.
[ -f "$HOME/.vim/autoload/plug.vim" ] \
    || curl -fLo "$HOME/.vim/autoload/plug.vim" --create-dirs \
            https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim

apply_zshrc
