import sqlite3
import os, sys
from cryptography.fernet import Fernet, InvalidToken
import getpass
import string
import datetime
import hashlib
import base64

# STRINGS
PROMPT_CMD=">>"
PROMPT_MASTER_PW = "Enter master password: "
PROMPT_CURRENT_MASTER_PW = "Enter old master password: "
PROMPT_NEW_MASTER_PW = "Enter new master password: "
PROMPT_CONFIRM_PW = "Re-enter password: "
PROMPT_USERNAME = "Enter username: "

WELCOME_USER = "Welcome, {}"

SUCCESS_NEW_MASTER_PW = "New master password successfully set."

ERROR_PW_CONFIRM = "Passwords do not match. Please try again."
ERROR_PW_TOO_SHORT = "A password needs to be at least 6 characters long. Please try again."
ERROR_PW_UNSUPPORTED_CHARS = "Your password contains unsupported character(s). Please try again."
ERROR_PW_EXCEED_MAX_ATTEMPTS = "You got the password wrong too many times. Exiting..."
ERROR_MASTER_PW_WRONG = "Incorrect master password."
ERROR_USERNAME_EMPTY = "A username cannot be empty."
ERROR_USERNAME_TOO_SHORT = "A username must be at least 3 characters long."
ERROR_USERNAME_UNSUPPORTED_CHARS = "Your username contains unsupported character(s). Please try again."

PATH_DATADIR = 'data'

NAME_KEYFILE = 'master.key'
NAME_SALTFILE = 'master.salt'
NAME_DBFILE = 'credentials.db'
NAME_DBFILE_ENC = 'credentials.db.enc'
NAME_USERNAMEFILE = 'uname'
NAME_USERNAMEFILE_ENC = 'uname.enc'

PATH_KEYFILE = os.path.join(PATH_DATADIR, NAME_KEYFILE)
PATH_SALTFILE = os.path.join(PATH_DATADIR, NAME_SALTFILE)
PATH_DBFILE = os.path.join(PATH_DATADIR, NAME_DBFILE)
PATH_DBFILE_ENC = os.path.join(PATH_DATADIR, NAME_DBFILE_ENC)
PATH_USERNAMEFILE = os.path.join(PATH_DATADIR, NAME_USERNAMEFILE)
PATH_USERNAMEFILE_ENC = os.path.join(PATH_DATADIR, NAME_USERNAMEFILE_ENC)

# PARAMETERS
SCRYPT_R = 8
SCRYPT_N = 2 ** 15
SCRYPT_P = 1
SCRYPT_MAX_MEM = 64 * 2 ** 20
SCRYPT_DKLEN = 32

MASTER_PW_MAX_ATTEMPTS = 5

# COMMANDS (and their aliases)
CMD_NEW = ['new', 'n']
CMD_VIEW = ['view', 'v', 'find']
CMD_EDIT = ['edit', 'update', 'e']
CMD_DEL = ['delete', 'del', 'd', 'remove']
CMD_LS = ['list', 'ls']
CMD_LOCK = ['lock']
CMD_EXIT = ['exit', 'quit']

# Generate key from plaintext password
def generate_key(pw:str, salt=None)->tuple[bytes, bytes]:
    pw_bytes = pw.encode()
    pw_salt = salt
    if not pw_salt:
        pw_salt = os.urandom(16) # Generate random new salt
    pw_hashed = hashlib.scrypt(pw_bytes, salt=pw_salt, n=SCRYPT_N, \
        r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAX_MEM, dklen=SCRYPT_DKLEN)
    key = base64.urlsafe_b64encode(pw_hashed)
    return key, pw_salt

def decrypt_file(frn:Fernet, filepath:str, write_to_file:bool=False)->bool:
    try:
        with open(filepath, "rb") as encrypted_file:
            encrypted = encrypted_file.read()
            try:
                decrypted = frn.decrypt(encrypted)
                if write_to_file:
                    decrypted_filename = ''
                    if filepath.index(".enc") >= 0:
                        decrypted_filename = os.path.basename(filepath).split(".enc")[0]
                    else:
                        decrypted_filename = os.path.basename(filepath) + ".dec"
                    decrypted_filepath = os.path.join(PATH_DATADIR, decrypted_filename)
                    with open(decrypted_filepath, "wb") as decrypted_file:
                        decrypted_file.write(decrypted)
            except InvalidToken:
                print(ERROR_MASTER_PW_WRONG)
                return False
    except FileNotFoundError:
        print(f"File not found: '{filepath}'")
        return False
    return decrypted

# ######## MASTER PASSWORD ########

# Validate master password
def validate_master_pw(pw:str, pw_confirm:str)->bool:
    if pw != pw_confirm:
        print(ERROR_PW_CONFIRM)
        return False
    if len(pw) < 6:
        print(ERROR_PW_TOO_SHORT)
        return False
    for ch in pw:
        if ch not in string.printable:
            print(ERROR_PW_UNSUPPORTED_CHARS)
            return False
    return True

# Create or change master password
def update_master_pw()->tuple[bytes, bytes]:
    pw = ''
    validated = False
    while not validated:
        pw = getpass.getpass(PROMPT_NEW_MASTER_PW)
        pw_confirm = getpass.getpass(PROMPT_CONFIRM_PW)
        validated = validate_master_pw(pw, pw_confirm)
    key, salt = generate_key(pw)
    return key, salt

# Prompt user for master password
def prompt_master_pw()->str:
    entered_pw = ''
    while not entered_pw:
        entered_pw = getpass.getpass(PROMPT_MASTER_PW)
    return entered_pw

# Load salt for master password generation from file
def load_master_salt()->bytes:
    master_salt = b''
    with open(PATH_SALTFILE, "rb") as saltfile:
        master_salt = saltfile.read()
    return master_salt

# Store salt for master password generation to file
def store_master_salt(salt:bytes):
    with open(PATH_SALTFILE, "wb") as saltfile:
        saltfile.write(salt)

# Load master password generated key from file
def load_master_key()->bytes:
    master_key = b''
    with open(PATH_KEYFILE, "rb") as keyfile:
        master_key = keyfile.read()
    return master_key

# Store salt for master password generation to file
def store_master_key(key:bytes):
    with open(PATH_KEYFILE, "wb") as keyfile:
        keyfile.write(key)

# ######## USERNAME ########

# validate username
def validate_username(username:str)->bool:
    if not username:
        print(ERROR_USERNAME_EMPTY)
        return False
    if len(username) < 3:
        print(ERROR_USERNAME_TOO_SHORT)
        return False
    for ch in username:
        if ch not in string.printable:
            print(ERROR_USERNAME_UNSUPPORTED_CHARS)
            return False
    return True

# Prompt user for username
def prompt_username()->str:
    entered = ''
    validated = False
    while not validated:
        entered = input(PROMPT_USERNAME)
        validated = validate_username(entered)
    return entered

# Encrypt username and write to file
def store_username(frn:Fernet, username:str):
    username_enc = frn.encrypt(username.encode())
    with open(PATH_USERNAMEFILE_ENC, "wb") as username_file:
        username_file.write(username_enc)

# ######## INIT ########

# Initialize program on launch
def init()->tuple[bytes, bytes, Fernet, sqlite3.Connection]:
    # init variables
    username = ''
    is_first_run = False
    master_key = b''
    master_salt = b''
    frn = None
    conn = None

    # Make data dir if not exists
    dirs = os.listdir(".")
    if PATH_DATADIR not in dirs:
        os.mkdir(PATH_DATADIR)
    
    # Generate key file if not exists
    dirs = os.listdir(PATH_DATADIR)
    if NAME_KEYFILE not in dirs:
        if NAME_SALTFILE in dirs:
            # just generate key from pre-existing salt
            master_key, master_salt = generate_key(prompt_master_pw(), load_master_salt())
            store_master_key(master_key)
        else:
            # first run. generate key and salt
            username = prompt_username()
            master_key, master_salt = update_master_pw()
            store_master_key(master_key)
            store_master_salt(master_salt)
            is_first_run = True
    else:
        master_key = load_master_key()
        master_salt = load_master_salt()
    
    # Initialize Fernet
    frn = Fernet(master_key)
    
    # Attempt to load username
    if NAME_USERNAMEFILE_ENC in dirs:
        attempts = 0
        decrypt_result = False
        while attempts < MASTER_PW_MAX_ATTEMPTS and not decrypt_result:
            decrypt_result = decrypt_file(frn, PATH_USERNAMEFILE_ENC)
            attempts += 1
            if not decrypt_result:
                # If decryption was not successful, wrong master password
                master_key, master_salt = generate_key(getpass.getpass(PROMPT_MASTER_PW), master_salt)
                # Re-initialize Fernet
                frn = Fernet(master_key)
        if attempts >= MASTER_PW_MAX_ATTEMPTS or not decrypt_result:
            # Decrypt failed. Quit program
            print(ERROR_MASTER_PW_WRONG)
            sys.exit(1)
        else:
            # Decrypt success. Load from decrypted file
            username = decrypt_result
    else:
        username = prompt_username()
        store_username(frn, username)
    
    # Store encrypted username if first run
    if is_first_run:
        if not username:
            username = prompt_username()
            store_username(frn, username)
    
    # Print welcome message
    print(WELCOME_USER.format(username))

    # Decrypt database file
    if NAME_DBFILE_ENC in dirs:
        attempts = 0
        decrypt_successful = False
        while attempts < MASTER_PW_MAX_ATTEMPTS and not decrypt_successful:
            decrypt_successful = decrypt_file(frn, PATH_DBFILE_ENC, write_to_file=True)
            attempts += 1
            if not decrypt_successful:
                # If decryption was not successful, wrong master password
                master_key, master_salt = generate_key(getpass.getpass(PROMPT_MASTER_PW), master_salt)
                # Re-initialize Fernet
                frn = Fernet(master_key)
        if attempts >= MASTER_PW_MAX_ATTEMPTS or not decrypt_successful:
            # Decrypt failed. Quit program
            print(ERROR_MASTER_PW_WRONG)
            sys.exit(1)
        conn.sqlite3.connect(PATH_DBFILE)
    else:
        # Create database if not exists
        conn = sqlite3.connect(PATH_DBFILE)
        conn.execute('CREATE TABLE IF NOT EXISTS credentials(id INTEGER, \
            name TEXT, user_id TEXT, user_pw BLOB, date_created TEXT, date_modified TEXT)')

    return master_key, master_salt, frn, conn

# ######## COMMANDS ########

def get_cmd():
    # init
    cmd = ''
    args = []

    # Get user input
    user_input = input(PROMPT_CMD).strip()
    while not user_input:
        user_input = input(PROMPT_CMD).strip()
    user_input = user_input.split(" ")

    # Correctly parse quotation marks
    if len(user_input) > 1:
        cmd = user_input[0]
        long_args = ''
        for arg in user_input[1:]:
            if arg[0] == '"' or arg[0] == "'":
                long_args += arg[1:]
            elif long_args:
                long_args += arg
            elif arg[-1] == '"' or arg[-1] == "'":
                long_args += arg[:-1]
                args.append(long_args)
                long_args = ''
            else:
                args.append(arg)

    return cmd, args

def run_new():
    pass

def run_view(args):
    pass

def run_edit(args):
    pass

def run_del(args):
    pass

def run_lock():
    pass

def run_cmd(cmd, args):
    if cmd in CMD_NEW:
        run_new()
    elif cmd in CMD_VIEW:
        run_view(args)
    elif cmd in CMD_EDIT:
        run_edit(args)
    elif cmd in CMD_DEL:
        run_del(args)
    elif cmd in CMD_LOCK:
        run_lock()

# ######## CLEANUP ########

def before_exit(frn:Fernet):
    # Delete master key file
    if os.path.exists(PATH_KEYFILE):
        os.remove(PATH_KEYFILE)
    # Encrypt database
    with open(PATH_DBFILE, "rb") as db_file:
        decrypted = db_file.read()
        encrypted = frn.encrypt(decrypted)
        with open(PATH_DBFILE_ENC, "wb") as db_file_enc:
            db_file_enc.write(encrypted)
    # Delete decrypted database
    if os.path.exists(PATH_DBFILE):
        os.remove(PATH_DBFILE)

def main():
    master_key, master_salt, frn, conn = init()
    try:
        cmd, args = get_cmd()
        while cmd not in CMD_EXIT:
            print(cmd, args)
            cmd, args = get_cmd()
    finally:
        if type(conn) == sqlite3.Connection:
            conn.close()
        before_exit(frn)
        master_key = None
        master_salt = None


if __name__ == "__main__":
    main()