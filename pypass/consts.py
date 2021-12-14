VERSION = 1.0
SPLASH_WELCOME = "PyPass - An interactive password manager. Welcome, {}"
SPLASH_COPYRIGHT = "Copyright 2021 Youngwoo Kim."


# USER PROMPTS
PROMPT_CMD=">> "
PROMPT_VALUE="> "
PROMPT_MASTER_PW = "Enter master password: "
PROMPT_CURRENT_MASTER_PW = "Enter old master password: "
PROMPT_NEW_MASTER_PW = "Enter new master password: "
PROMPT_CONFIRM_PW = "Re-enter password: "
PROMPT_MASTER_USERNAME = "Enter PyPass username: "
PROMPT_DEFAULT_YN = "Continue (y/n)? "
PROMPT_MASTER_USER_CREATE = "Create a new PyPass user?"

PROMPT_NEW_ENTRY_TITLE = "===== Adding new credential entry =====\n"
PROPMT_NEW_ENTRY_NAME = "[1/3] Enter service/domain name: "
PROMPT_NEW_ENTRY_NAME_SAME_CONFIRM = "Are you sure you want to use this name (y/n)? "
PROPMT_NEW_ENTRY_ID = "[2/3] Enter your user ID: "
PROMPT_NEW_ENTRY_EMPTY_ID_CONFIRM = "You have not entered anything. Are you sure (y/n)? "
PROMPT_NEW_ENTRY_PASSWORD_1 = "[3/3] Password\n"
PROMPT_NEW_ENTRY_PASSWORD_2 = """<Options>
1. Generate new secure password (recommended)
2. Enter a pasword yourself\n
Choose option (Enter 1 or 2): """
PROMPT_NEW_ENTRY_PASSWORD_USER = "Enter a password for this service: "
PROMPT_NEW_ENTRY_CONFIRM_ENTRY = """The following entry will be created.
Please confirm your input.

================ NEW ENTRY ================
* service/domain name: {}
* ID: {}
* Password: {}
===========================================

Is the information above correct (y/n)? """

PROMPT_SEARCH_QUERY = "Search database by service name: "

PROMPT_PASSWORD_COPIED = 'The password was copied to your clipboard!'

PROMPT_EDIT_CONFIRM_CHOICE = "Do you wish to edit this entry (y/n)? "
PROMPT_EDIT_CHOOSE_ONE = "Enter the entry ID of the item to edit: "
TIP_KEEP_ORIGINAL = " (Leave it blank to keep original)"
PROMPT_EDIT_ENTRY_NAME = "[1/3] Edit service name" + TIP_KEEP_ORIGINAL
PROMPT_EDIT_ENTRY_ID = "[2/3] Edit ID" + TIP_KEEP_ORIGINAL
PROMPT_EDIT_ENTRY_PW = "[3/3] Edit password" + TIP_KEEP_ORIGINAL
PROMPT_EDIT_ENTRY_PW_2 = """<Options>
1. Generate new secure password (recommended)
2. Enter a pasword yourself
3. No change. Keep original.\n
Choose option (Enter 1 ~ 3): """
PROMPT_EDIT_ENTRY_PW_CONFIRM = "Enter same value again to confirm, leave blank to try again."
PROMPT_EDIT_CONFIRM_CHANGE_1 = "CONFIRM CHANGE"
PROMPT_EDIT_CONFIRM_CHANGE_2 = "{} >> {}"
PROMPT_EDIT_CONFIRM_CHANGE_3 = "Confirm (y/n) ? "
PROMPT_EDIT_IN_PROGRESS = "Saving changes... "

PROMPT_DELETE_CONFIRM = "Are you sure you want to delete the above entry (y/n)? "
PROMPT_DELETE_CONFIRM_2 = "This action cannot be undone. Are you sure (y/n)? "

PROMPT_LOGIN_WIZARD_1_URL = "Hit ENTER after reaching the login page. Opening URL..."
PROMPT_LOGIN_WIZARD_2_ID = "Place your cursor in the ID field of the login page and press the 'tab' key."

# RESPONSE MESSAGES
WELCOME_USER = "Welcome, {}"
VIEW_SEARCH_RESULT = "Found {} entries for search '{}'."
EDIT_NO_CHANGES = "No changes. Keep original value: '{}'."
EDIT_NO_CHANGES_AT_ALL = "No changes made to entry. Keeping all original data."
EDIT_DB_UPDATE_IN_PROGRES = "Saving changes to database..."

# SUCCESS MESSAGES
SUCCESS_NEW_MASTER_PW = "New master password successfully set."
SUCCESS_EDIT = "All changes saved successfully."
SUCCESS_DELETE = "Deleted credential entry from the database."

# ERROR MESSAGES
ERROR_INIT_MISSING_SALT = 'Cannot unlock database due to missing key file. Stopping...'
ERROR_INIT_FAIL = "Failed to load PyPass. Exiting..."

ERROR_MODULES_NOT_FOUND = "Dependencies not found. Please install dependencies with './install.sh' and try again."

ERROR_PW_CONFIRM = "Passwords do not match. Please try again."
ERROR_PW_TOO_SHORT = "A password needs to be at least {} characters long. Please try again."
ERROR_PW_TOO_LONG = "A password needs to be shorter than {} characters long. Please try again."
ERROR_ID_UNSUPPORTED_CHARS = "Your ID contains unsupported character({}). Please try again."
ERROR_PW_UNSUPPORTED_CHARS = "Your password contains unsupported character({}). Please try again."
ERROR_PW_EXCEED_MAX_ATTEMPTS = "You got the password wrong too many times. Exiting..."
ERROR_MASTER_PW_WRONG = "Incorrect master password."

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
ERROR_NEW_ID_TOO_SHORT = "A user ID/email must be longer than {} characters. Please try again."
ERROR_NEW_ID_TOO_LONG = "A user ID/email must be shorter than {} characters. Please try again."
ERROR_NEW_ENTRY_ALREADY_EXISTS = "You already have an entry for the service '{}' in the database."
ERROR_NEW_ENTRY_PW_INVALID_OPTIONS = "Enter either 1 or 2 to select an option. Please try again."
ERROR_NEW_ENTRY_PW_EMPTY = "A password field cannot be left empty. Please try again."

ERROR_VIEW_QUERY_TOO_SHORT = "Search query is too short. Search with at least {} characters as your search query."
ERROR_VIEW_QUERY_TOO_LONG = "Search query is too long. Search with less than {} characters as your search query."
ERROR_VIEW_NO_SEARCH_RESULTS = "No credentials were found for search '{}'."

ERROR_DATABASE_ERROR = "A database error occured while carrying out the operation."

ERROR_EDIT_ENTRY_ID_NOT_NUMBER = "Enter a valid entry ID. An entry ID is a number. Please try again."

ERROR_DELETE_NOT_INIT = "Failed to access the database. Forgot to decrypt?"
ERROR_DELETE_FAILED = "Failed to delete credential from database."

ERROR_YN_RESPONSE_INVALID = "Error: Invalid response. Enter either 'y' or 'n' as a reponse. Please try again."

ERROR_USER_ABORT = "Command execution was cancelled by user. Aborting..."

ERROR_INVALID_SIGNATURE = """WARNING: Entry signature is invalid.\n
The database has been corrputed, or someone with malicious intent \
    may have tampered with the database.
The information in this database entry may be incorrect, \
    or may contain malicious information. 
It is STRONGLY recommended to delete this credential entry from the database.
View and use the data in this entry at your own risk.\n
"""

# TIPS
SHOW_PW_FLAG = "(Use the '-p' or '--show-password' flag to view your password)"

# COMMANDS (and their aliases)
CMD_NEW = ['new', 'n']
CMD_VIEW = ['view', 'v', 'find']
CMD_EDIT = ['edit', 'update', 'e']
CMD_DEL = ['delete', 'del', 'd', 'remove']
CMD_LS = ['list', 'ls']
CMD_LOCK = ['lock']
CMD_EXIT = ['exit', 'quit']
CMD_PASSWD = ['passwd'] # change master password

# FLAGS
FLAG_SHOW_PW = ['-p', '--show-password']
FLAG_ALL = ['-a', '--all']

# RESPONSES (Answer to y/n prompts)
RESPONSE_YES = ['yes', 'y']
RESPONSE_NO = ['no', 'n']

# MISC
PRINTABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ\
    abcdefghijklmnopqrstuvwxyz0123456789\
        !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

QUOTATION_MARK = ['\'', '"']