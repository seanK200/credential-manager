import os

# USER PROMPTS
PROMPT_CMD=">>"
PROMPT_MASTER_PW = "Enter master password: "
PROMPT_CURRENT_MASTER_PW = "Enter old master password: "
PROMPT_NEW_MASTER_PW = "Enter new master password: "
PROMPT_CONFIRM_PW = "Re-enter password: "
PROMPT_USERNAME = "Enter username: "

PROMPT_NEW_ENTRY_TITLE = "===== Adding new credential entry =====\n"
PROPMT_NEW_ENTRY_NAME = "[1/3] Enter service/domain name: "
PROPMT_NEW_ENTRY_ID = "[2/3] Enter your user ID/email (leave blank if there is none): "
PROMPT_NEW_ENTRY_EMPTY_ID_CONFIRM = "You have not entered anything. Are you sure (y/n)? "
PROMPT_NEW_ENTRY_PASSWORD_1 = "[3/3] Password\n"
PROMPT_NEW_ENTRY_PASSWORD_2 = """<Options>
1. Generate new secure password (recommended)
2. Enter a pasword yourself\n
Choose option (Enter 1 or 2): """
PROMPT_NEW_ENTRY_PASSWORD_USER = "Enter a password for this service: "

# RESPONSE MESSAGES
WELCOME_USER = "Welcome, {}"

# SUCCESS MESSAGES
SUCCESS_NEW_MASTER_PW = "New master password successfully set."

# ERROR MESSAGES
ERROR_PW_CONFIRM = "Passwords do not match. Please try again."
ERROR_PW_TOO_SHORT = "A password needs to be at least {} characters long. Please try again."
ERROR_PW_UNSUPPORTED_CHARS = "Your password contains unsupported character(s). Please try again."
ERROR_PW_EXCEED_MAX_ATTEMPTS = "You got the password wrong too many times. Exiting..."
ERROR_MASTER_PW_WRONG = "Incorrect master password."

ERROR_USERNAME_EMPTY = "A username cannot be empty."
ERROR_USERNAME_TOO_SHORT = "A username must be at least 3 characters long."
ERROR_USERNAME_UNSUPPORTED_CHARS = "Your username contains unsupported character(s). Please try again."

ERROR_NEW_ENTRY_NAME_EMPTY = "You must enter a non-empty service/domain name."
ERROR_NEW_ENTRY_NAME_TOO_LONG = "A service/domain name must be shorter than 512 characters. Please try again."
ERROR_NEW_ENTRY_PW_INVALID_OPTIONS = "Enter either 1 or 2 to select an option. Please try again."

# PATHS TO DIRECTORIES, FILES
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
MASTER_PW_MIN_LEN = 6

USERNAME_MIN_LEN = 3

USER_PW_MIN_LEN = 6

# COMMANDS (and their aliases)
CMD_NEW = ['new', 'n']
CMD_VIEW = ['view', 'v', 'find']
CMD_EDIT = ['edit', 'update', 'e']
CMD_DEL = ['delete', 'del', 'd', 'remove']
CMD_LS = ['list', 'ls']
CMD_LOCK = ['lock']
CMD_EXIT = ['exit', 'quit']

# RESPONSES (Answer to y/n prompts)
RESPONSE_YES = ['yes', 'y']
RESPONSE_NO = ['no', 'n']

# MISC
PRINTABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ\
    abcdefghijklmnopqrstuvwxyz0123456789\
        !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'