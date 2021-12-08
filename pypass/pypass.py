# Python standard libraries
import os, sys, sqlite3
from typing import Tuple
from hashlib import blake2b

# 3rd parties
from cryptography.fernet import Fernet, InvalidToken
from pyfiglet import Figlet

# Local
from consts import *
from params import *
from helpers import *
import masterauth
from commands import run_commands

def display_splash(username):
    f = Figlet(font='slant')
    print(f.renderText("PYPASS"), end="\n\n")
    print(SPLASH_WELCOME.format(username))
    print()

def init()->Tuple[Fernet, sqlite3.Connection]:
    init_success = False

    print("Loading PyPass...", end=" ")
    try:
        # Master Authentication
        user_auth = masterauth.authenticate()
        
        if type(user_auth) == masterauth.UserAuth:
            init_success = True
    except sqlite3.DatabaseError:
        init_success = False
    except KeyboardInterrupt:
        handle_keyboard_interrupt()
    finally:
        if init_success:
            print("\r")
        else:
            print(ERROR_INIT_FAIL)
            sys.exit(1)
    return user_auth

def cleanup(user_auth):
    del user_auth

def main():
    user_auth = init()
    display_splash(user_auth.username)
    try:
        command = ''
        while command != 'Quit':
            command = run_commands()
    except KeyboardInterrupt:
        print("Quiting PyPass...")
    finally:
        print("Clearing sensitive information...", end=" ", flush=True)
        cleanup(user_auth)
        print("Done")

if __name__ == "__main__":
    main()
