# Python standard libraries
import sys, sqlite3
from typing import Tuple

# 3rd parties
from cryptography.fernet import Fernet
from pyfiglet import Figlet

# Local
if __name__ == "__main__":
    from consts import *
    from params import *
    from helpers import *
    import masterauth
    from commands import run_commands
else:
    from pypass.consts import *
    from pypass.params import *
    from pypass.helpers import *
    from pypass import masterauth
    from pypass.commands import run_commands

def display_splash(username):
    f = Figlet(font='slant')
    print(f.renderText("PYPASS"), end="\n\n")
    print(SPLASH_WELCOME.format(username))
    print()

def init()->Tuple[Fernet, sqlite3.Connection]:
    init_success = False

    print("Loading PyPass...")
    try:
        # Master Authentication
        user_auth = masterauth.authenticate()
    except sqlite3.DatabaseError:
        user_auth = None
    except KeyboardInterrupt:
        user_auth = None
        handle_keyboard_interrupt()
    finally:
        if user_auth == None:
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
        while not(command == 'Quit'):
            command = run_commands(user_auth)
            print()
    except KeyboardInterrupt:
        print("Quiting PyPass...")
    finally:
        print("Clearing sensitive information...", end=" ", flush=True)
        cleanup(user_auth)
        print("Done")

if __name__ == "__main__":
    main()
