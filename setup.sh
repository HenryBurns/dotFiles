# Move over general dotfile configs.

# Copy all the relevant dotfiles to our home directory.
cp -t ~/ .gitignore_global .gitconfig .zshrc .tmux.conf .vimrc

#######
# ZSH #
#######
# Install Oh-my-zsh. This will move any .zshrc file to .zshrc.pre-oh-my-zsh.
sudo apt-get install zsh
chsh -s $(which zsh)
sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

#######
# VIM #
#######
mkdir -p ~/.vim/colors/
wget https://raw.githubusercontent.com/sjl/badwolf/refs/heads/master/colors/badwolf.vim -O ~/.vim/colors/badwolf.vim
curl -fLo ~/.vim/autoload/plug.vim --create-dirs \
    https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim

source ~/.zshrc
