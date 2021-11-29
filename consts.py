import os

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