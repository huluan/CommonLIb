set autoindent
set shiftwidth=4
set autoindent
set cursorline
set number
set expandtab
set tabstop=4
set t_Co=256
set fileencodings=utf-8,ucs-bom,gb18030,gbk,gb2312,cp936
set termencoding=utf-8
set encoding=utf-8

set nocompatible              " be iMproved, required
filetype off                  " required

"set the runtime path to include Vundle and initialize
set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()
" alternatively, pass a path where Vundle should install plugins
"call vundle#begin('~/some/path/here')
"
"" let Vundle manage Vundle, required
Plugin 'gmarik/Vundle.vim'

" The following are examples of different formats supported.
" Keep Plugin commands between vundle#begin/end.
" plugin on GitHub repo
"
Plugin 'Mizuchi/STL-Syntax'
Plugin 'vim-scripts/a.vim'
Plugin 'kien/ctrlp.vim'
Plugin 'Valloric/YouCompleteMe'
Plugin 'Lokaltog/vim-powerline'
Plugin 'vim-scripts/delimitMate.vim'
Plugin 'tpope/vim-surround'

" All of your Plugins must be added before the following line
call vundle#end()            " required
filetype plugin indent on    " required

let g:ycm_global_ycm_extra_conf = '~/.vim/bundle/YouCompleteMe/ycm_extra_conf.py' 
let g:ycm_collect_identifiers_from_tag_files = 1 "使用ctags生成的tags文件
let g:syntastic_cpp_compiler = 'g++'  "change the compiler to g++ to support c++11 
let g:syntastic_cpp_compiler_options = '-std=c++11 -stdlib=libc++' "set the options of g++ to suport
let mapleader = ","  " 这个leader就映射为逗号“，”
nnoremap <leader>jd:YcmCompleter GoToDefinitionElseDeclaration<CR>   "按,jd 会跳转到定义

" for powerline
set laststatus=2   " Always show the statusline

"let g:molokai_original = 1
"let g:rehash256 = 1
