import os, sys

from pyfiglet import Figlet

# Modules directory to path
cwd = os.path.abspath(os.getcwd()) # current working directory
modules_dirpath = os.path.join(cwd, 'modules')
sys.path.insert(0, modules_dirpath)

# My modules
from consts import *

def display_splash():
    f = Figlet(font='slant')
    print(f.renderText("PYPASS"))
    print(SPLASH_WELCOME)
    print(SPLASH_TIP, end="\n\n")

display_splash()
user_input = input(PROMPT_CMD)
print(user_input)