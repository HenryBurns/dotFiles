# Move over general dotfile configs.

#######
# GIT #
#######
cp .gitignore_global ~/

#######
# ZSH #
#######
# Install Oh-my-zsh. This will move any .zshrc file to .zshrc.pre-oh-my-zsh.
sudo apt-get install zsh
chsh -s $(which zsh)
sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
# cp -t ~/ .zshrc .zshrc.pre-oh-my-zsh 


#######
# VIM #
#######
cp .vimrc ~/
mkdir -p ~/.vim/colors/
wget https://raw.githubusercontent.com/sjl/badwolf/refs/heads/master/colors/badwolf.vim -O ~/.vim/colors/badwolf.vim

source ~/.zshrc
