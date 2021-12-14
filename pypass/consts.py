VERSION = 1.0
SPLASH_WELCOME = "PyPass - An interactive password manager. Welcome, {}"

# USER PROMPTS
PROMPT_MASTER_PW = "Enter master password: "
PROMPT_NEW_MASTER_PW = "Enter new master password: "
PROMPT_CONFIRM_PW = "Re-enter password: "
PROMPT_MASTER_USERNAME = "Enter PyPass username: "
PROMPT_MASTER_USER_CREATE = "Create a new PyPass user?"

PROMPT_SEARCH_QUERY = "Search database by service name: "

PROMPT_PASSWORD_COPIED = 'The password was copied to your clipboard!'

PROMPT_LOGIN_WIZARD_1_URL = "Hit ENTER after reaching the login page. Opening URL..."
PROMPT_LOGIN_WIZARD_2_ID = "Place your cursor in the ID field of the login page and press the 'tab' key."

# SUCCESS MESSAGES

# ERROR MESSAGES
ERROR_INIT_FAIL = "Failed to load PyPass. Exiting..."

ERROR_PW_CONFIRM = "Passwords do not match. Please try again."
ERROR_PW_TOO_SHORT = "A password needs to be at least {} characters long. Please try again."
ERROR_PW_TOO_LONG = "A password needs to be shorter than {} characters long. Please try again."
ERROR_ID_UNSUPPORTED_CHARS = "Your ID contains unsupported character({}). Please try again."
ERROR_PW_UNSUPPORTED_CHARS = "Your password contains unsupported character({}). Please try again."

ERROR_MASTER_USERNAME_EMPTY = "A username cannot be empty."
ERROR_MASTER_USERNAME_ALREADY_EXISTS = "The username '{}' already exists. Please choose another one."
ERROR_MASTER_USERNAME_TOO_LONG = "Username must be shorter than {} characters. Please choose another one."
ERROR_MASTER_USERNAME_UNSUPPORTED_CHARS = "Your username contains unsupported character('{}'). Please try again."
ERROR_MASTER_USERNAME_DOES_NOT_EXIST = "We could not find a user with the username '{}'."
ERROR_CREATE_PYPASS_USER_DATABASEERROR = "A DatabaseError occured while trying to create a new PyPass user."
ERROR_CREATE_PYPASS_USER_FAIL = "Failed to create a new PyPass user due to an error."
ERROR_MASTER_AUTH_KEYBOARD_INTERRUPT = "Master authentication aborted by user. Exit program."
ERROR_WRONG_MASTER_PASSWORD = "Wrong master password. Please re-launch the program to try again."

ERROR_NEW_ENTRY_NAME_EMPTY = "You must enter a non-empty service/domain name."
ERROR_NEW_ENTRY_NAME_TOO_LONG = "A service/domain name must be shorter than 512 characters. Please try again."
ERROR_NEW_ID_TOO_LONG = "A user ID/email must be shorter than {} characters. Please try again."

ERROR_VIEW_QUERY_TOO_SHORT = "Search query is too short. Search with at least {} characters as your search query."

ERROR_DATABASE_ERROR = "A database error occured while carrying out the operation."

ERROR_USER_ABORT = "Command execution was cancelled by user. Aborting..."

ERROR_INVALID_SIGNATURE = """WARNING: Entry signature is invalid.\n
The database has been corrputed, or someone with malicious intent \
    may have tampered with the database.
The information in this database entry may be incorrect, \
    or may contain malicious information. 
It is STRONGLY recommended to delete this credential entry from the database.
View and use the data in this entry at your own risk.\n
"""

# MISC
PRINTABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ\
    abcdefghijklmnopqrstuvwxyz0123456789\
        !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'