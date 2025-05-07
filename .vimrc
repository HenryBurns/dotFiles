colorscheme badwolf " awesome colorscheme
set background=dark " sets dark mode
syntax enable           " enable syntax processing
"set tabstop=4       " number of visual spaces per TAB
set softtabstop=4   " number of spaces in tab when editing
set shiftwidth=4    " this should fix my double tabbing problem
set expandtab       " tabs are spaces
set number              " show line numbers
set showcmd             " show command in bottom bar
set cursorline          " highlight current line
filetype indent on      " load filetype-specific indent files
set wildmenu            " visual autocomplete for command menu
set lazyredraw          " redraw only when we need to.
set showmatch           " highlight matching [{()}]
set incsearch           " search as characters are entered
set hlsearch            " highlight matches
set cc=120              " highlight column 120
set textwidth=120       " wrap text at 120

" turn off search highlight
nnoremap <leader><space> :nohlsearch<CR>
set foldenable          " enable folding
set foldlevelstart=10   " open most folds by default
set foldnestmax=10      " 10 nested fold max
" space open/closes folds
nnoremap <space> za
set foldmethod=indent   " fold based on indent level
" move vertically by visual line
nnoremap j gj
nnoremap k gk
let mapleader=","       " leader is comma
" allows cursor change in tmux mode
if exists('$TMUX')
    let &t_SI = "\<Esc>Ptmux;\<Esc>\<Esc>]50;CursorShape=1\x7\<Esc>\\"
    let &t_EI = "\<Esc>Ptmux;\<Esc>\<Esc>]50;CursorShape=0\x7\<Esc>\\"
else
    let &t_SI = "\<Esc>]50;CursorShape=1\x7"
    let &t_EI = "\<Esc>]50;CursorShape=0\x7"
endif

call plug#begin('~/.vim/plugged')
    Plug 'wfxr/protobuf.vim' " Proto file indentation.
    Plug 'scrooloose/nerdtree'
call plug#end()

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""
" Extension Configs
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""

" Nerdtree
map <leader>n :NERDTreeToggle<CR>
