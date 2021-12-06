import os, sys, sqlite3

from cryptography.fernet import Fernet
from pyfiglet import Figlet

from consts import *

def display_splash():
    f = Figlet(font='slant')
    print(f.renderText("PYPASS"), end="\n\n")
    print(SPLASH_WELCOME)
    print()

def runner():
    pass