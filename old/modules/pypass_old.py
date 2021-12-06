# Imports: Python Standard Library
import os, sys, sqlite3, base64, datetime
import hashlib, getpass
from typing import Iterable

# Modules directory to path
cwd = os.path.abspath(os.getcwd()) # current working directory
modules_dirpath = os.path.join(cwd, 'modules')
sys.path.insert(0, modules_dirpath)

# My modules
from consts_old import *
from pwgenerator import *
from sqlite_queries import *
from params_old import *

# 3rd-party dependencies
try:
    from cryptography.fernet import Fernet, InvalidToken
    import pandas
    from pyfiglet import Figlet
except ModuleNotFoundError:
    print(ERROR_MODULES_NOT_FOUND)
    sys.exit(1)

# Globals
master_key:bytes = b''
master_salt:bytes = b''
frn:Fernet = None
conn:sqlite3.Connection = None

# ######## UTILITIES ########

# Generate key from plaintext password
def generate_key(pw:str, salt=None)->tuple[bytes, bytes]:
    """
    Generate a key to initialize Fernet
    If the optional salt argument is provided, use the provided salt.
    If not, generate a random salt.
    """
    pw_bytes = pw.encode()
    pw_salt = salt
    if not pw_salt:
        pw_salt = os.urandom(16) # Generate random new salt
    pw_hashed = hashlib.scrypt(pw_bytes, salt=pw_salt, n=SCRYPT_N, \
        r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAX_MEM, dklen=SCRYPT_DKLEN)
    key = base64.urlsafe_b64encode(pw_hashed)
    return key, pw_salt

def decrypt_file(frn:Fernet, filepath:str, write_to_file:bool=False)->bool:
    """
    Decrypt a file at a given 'filepath' using given Fernet object 'frn'.
    If the optional 'write_to_file' argument is set to True, 
    write the decrypted data to a new file.
    """
    try:
        with open(filepath, "rb") as encrypted_file:
            encrypted = encrypted_file.read()
            try:
                decrypted = frn.decrypt(encrypted)
                if write_to_file:
                    decrypted_filename = ''
                    # Change the file extension
                    # If it already has the encrypted extension,
                    if filepath.index(".enc") >= 0:
                        # Remove the extension.
                        decrypted_filename = os.path.basename(filepath).split(".enc")[0]
                    else:
                        # If it doesn't, just add a decrypted extension
                        decrypted_filename = os.path.basename(filepath) + ".dec"
                    decrypted_filepath = os.path.join(PATH_DATADIR, decrypted_filename)
                    with open(decrypted_filepath, "wb") as decrypted_file:
                        decrypted_file.write(decrypted)
            except InvalidToken:
                # Master password wrong
                print(ERROR_MASTER_PW_WRONG)
                return False
    except FileNotFoundError:
        print(f"File not found: '{filepath}'")
        return False
    return decrypted

def ask_yn(prompt:str=PROMPT_DEFAULT_YN)->bool:
    """
    Ask a yes/no question to user with the given prompt and get response.
    Returns True if the user answered yes, False otherwise.
    """
    response = ''
    while not response:
        response = input(prompt).lower()
        if response in RESPONSE_YES:
            return True
        elif response in RESPONSE_NO:
            return False
        else:
            print(ERROR_YN_RESPONSE_INVALID)
            response = ''

def get_current_ts()->int:
    """
    Returns current timestamp
    """
    return int(datetime.datetime.now().timestamp())

def format_date_from_ts(ts:int)->str:
    if type(ts) == str:
        ts = int(ts)
    date_format = '%Y-%m-%d %H:%M:%S'
    dt = datetime.datetime.fromtimestamp(ts)
    return dt.strftime(date_format)

def handle_keyboardinterrupt():
    print()
    print(ERROR_USER_ABORT)
    print()

# ######## CLEANUP ########

def before_exit(frn:Fernet, conn:sqlite3.Connection):
    """
    Code to execute before termination of application. 
    Encrypt the database and delete decrypted file.
    """
    # Close database
    if type(conn) == sqlite3.Connection:
        conn.close()

    # Encrypt database
    if type(frn) == Fernet:
        with open(PATH_DBFILE, "rb") as db_file:
            decrypted = db_file.read()
            encrypted = frn.encrypt(decrypted)
            with open(PATH_DBFILE_ENC, "wb") as db_file_enc:
                db_file_enc.write(encrypted)
        # Delete decrypted database
        if os.path.exists(PATH_DBFILE):
            os.remove(PATH_DBFILE)
    else:
        print("FATAL ERROR: Could not encrypt database.")

# ######## DATABASE UTILITIES ########

def get_entries_with_name(name:str)->list[sqlite3.Row]:
    """
    Check if name already exists in DB
    """
    global conn
    cur = conn.cursor()
    cur.execute('SELECT name, user_id FROM credentials WHERE name=?', [name])
    rows = cur.fetchall()
    cur.close()
    return rows

def print_one_entry(row:sqlite3.Row, *, verbose=False, show_password=False):
    entry_id, name, user_id, user_pw_enc, date_created_ts, date_modified_ts = row
    print("<<", name, sep=" ", end=" ")
    
    if verbose:
        print(f"({entry_id})", end=" ")
    
    print(">>")
    print(f"ID: {user_id}")
    
    if show_password:
        global frn
        user_pw = frn.decrypt(user_pw_enc).decode()
        print(f"PW: {user_pw}")
    else:
        print("PW: ****")
    
    if verbose:
        print(f"Date Created : {format_date_from_ts(date_created_ts)}")
        print(f"Date Modified : {format_date_from_ts(date_modified_ts)}")
    
    if not show_password:
        print(SHOW_PW_FLAG)

def print_many_entry(cur:sqlite3.Cursor, *, show_password=False, raw_rows=None):
    if not raw_rows:
        raw_rows = cur.fetchall()
    if len(raw_rows) == 0: return
    global frn
    cols = ['ENTRY ID', 'SERVICE NAME', 'ID', 'DATE CREATED', 'LAST MODIFIED']
    if show_password:
        cols.insert(3, 'PASSWORD')
    rows = []
    for raw_row in raw_rows:
        entry_id, name, user_id, user_pw_enc, date_created_ts, date_modified_ts = raw_row
        row = []
        row.append(entry_id)
        row.append(name)
        row.append(user_id)
        if show_password:
            decrypted_pw = frn.decrypt(user_pw_enc).decode()
            row.append(decrypted_pw)
        row.append(format_date_from_ts(date_created_ts))
        row.append(format_date_from_ts(date_modified_ts))
        
        rows.append(row)
    data_df = pandas.DataFrame.from_records(data=rows, columns=cols)
    print(data_df)

    if not show_password:
        print(SHOW_PW_FLAG)

def get_one_entry(show_password:bool=False, query:str='')->sqlite3.Row:
    # Ask user for search query
    if not query:
        query = prompt_search_query()

    # Search database for entry
    global conn
    chosen_row = None
    with conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM credentials WHERE name LIKE ?', [f"%{query}%"])
        rows = cur.fetchall()
        if len(rows) > 1:
            # Multiple results. Choose.
            print(VIEW_SEARCH_RESULT.format(len(rows), query), end="\n\n")
            print_many_entry(cur, show_password=show_password, raw_rows=rows)
            
            # Make user pick one from the list by entry ID
            valid_entry_ids = [row[0] for row in rows]
            entry_id = prompt_entry_id(valid_entry_ids)
            cur.execute('SELECT * FROM credentials WHERE entry_id=?', [entry_id])
            chosen_row = cur.fetchone()
            
            # Print the user's choice
            print()
            print_one_entry(chosen_row, show_password=show_password)
        elif len(rows) > 0:
            # Only one result. Proceed
            print(VIEW_SEARCH_RESULT.format(len(rows), query), end="\n\n")
            chosen_row = rows[0]
            print_one_entry(chosen_row, show_password=show_password)
        else:
            # Nothing found. Stop.
            print(ERROR_VIEW_NO_SEARCH_RESULTS.format(query))
            chosen_row = None
    
    return chosen_row
        
# ######## MASTER PASSWORD ########

# Validate master password
def validate_master_pw(pw:str, pw_confirm:str)->bool:
    if pw != pw_confirm:
        print(ERROR_PW_CONFIRM)
        return False
    if len(pw) < MASTER_PW_MIN_LEN:
        print(ERROR_PW_TOO_SHORT.format(MASTER_PW_MIN_LEN))
        return False
    for ch in pw:
        if ch not in PRINTABLE:
            print(ERROR_PW_UNSUPPORTED_CHARS)
            return False
    return True

# Create or change master password
def prompt_new_master_pw()->tuple[bytes, bytes]:
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

# ######## INIT ########

# Initialize program on launch
def init()->tuple[bytes, bytes, Fernet, sqlite3.Connection]:
    # init variables
    master_key = b''
    master_salt = b''
    frn = None
    conn = None

    # Make data dir if not exists
    dirs = os.listdir(".")
    if PATH_DATADIR not in dirs:
        os.mkdir(PATH_DATADIR)
    
    # list data directory
    dirs = os.listdir(PATH_DATADIR)
    
    # Decrypt and connect to existing DB
    if NAME_DBFILE_ENC in dirs:
        if NAME_SALTFILE not in dirs:
            # If there is encrypted DB, but no salt, cannot decrypt.
            print(ERROR_INIT_MISSING_SALT)
            sys.exit(1)
        
        # Decrypt DB
        attempts = 0
        decrypt_successful = False
        while attempts < MASTER_PW_MAX_ATTEMPTS and not decrypt_successful:
            master_key, master_salt = generate_key(prompt_master_pw(), load_master_salt())
            frn = Fernet(master_key)
            decrypt_successful = decrypt_file(frn, PATH_DBFILE_ENC, write_to_file=True)
            attempts += 1
        
        # Decryption failed. Quit program
        if not decrypt_successful:
            sys.exit(1)
        
        # Connect to decrypted DB
        conn = sqlite3.connect(PATH_DBFILE)
    
    # First run.
    else:
        # Generate new key
        master_key, master_salt = prompt_new_master_pw()
        store_master_salt(master_salt)
        conn = sqlite3.connect(PATH_DBFILE)
        frn = Fernet(master_key)
        
        # Create table
        with conn:
            conn.execute(SQL_CREATE_TABLE)

    return master_key, master_salt, frn, conn

# ######## PROMPT ########

def prompt_entry_name(override_prompt:str=""):
    """
    Prompt user for service/domain name of a credential entry
    """
    if override_prompt:
        prompt = override_prompt
    else:
        prompt = PROPMT_NEW_ENTRY_NAME
    user_name = ''
    while not user_name:
        user_name = input(prompt).strip()
        if not user_name:
            print(ERROR_NEW_ENTRY_NAME_EMPTY)
        elif len(user_name) > SERVICE_NAME_MAX_LEN:
            print(ERROR_NEW_ENTRY_NAME_TOO_LONG)
            user_name = ''
        else:
            # check if entry with same name exists
            entries_with_name = get_entries_with_name(user_name)
            # If the entry already exists,
            if entries_with_name and len(entries_with_name) > 0:
                # notify user, and
                print(ERROR_NEW_ENTRY_ALREADY_EXISTS.format(user_name))
                # ask user for confirmation.
                if not ask_yn(PROMPT_NEW_ENTRY_NAME_SAME_CONFIRM):
                    # If user aborts, ask for a new name
                    user_name = ''
    return user_name

def prompt_entry_userid(override_prompt:str=""):
    """
    Prompt user for the user ID of a credential entry
    """
    user_id = ''
    if override_prompt:
        prompt = override_prompt
    else:
        prompt = PROPMT_NEW_ENTRY_ID
    while not user_id:
        user_id = input(prompt)
        if not user_id:
            empty_id_confirmed = ask_yn(PROMPT_NEW_ENTRY_EMPTY_ID_CONFIRM)
            if empty_id_confirmed:
                break
        elif len(user_id) > USER_ID_MAX_LEN:
            print(ERROR_NEW_ID_TOO_LONG.format(USER_ID_MAX_LEN))
            user_id = ''
    return user_id

def validate_entry_password(pw, pw_conf):
    """
    Validate user's password
    """
    # Password and confirm match
    if pw != pw_conf:
        print(ERROR_PW_CONFIRM)
        return False
    # Too short
    if len(pw) < USER_PW_MIN_LEN:
        print(ERROR_PW_TOO_SHORT.format(USER_PW_MIN_LEN))
        return False
    # Supported characters
    for ch in pw:
        if ch not in PRINTABLE:
            print(ERROR_PW_UNSUPPORTED_CHARS)
            return False
    return True

def prompt_entry_password():
    """
    Prompt user for the user password for a credential entry
    """
    options = ''
    user_pw = ''
    print(PROMPT_NEW_ENTRY_PASSWORD_1)
    while not options:
        options = input(PROMPT_NEW_ENTRY_PASSWORD_2).strip()
        if not (options == '1' or options == '2'):
            options = ''
            print(ERROR_NEW_ENTRY_PW_INVALID_OPTIONS)
    if options == '1':
        # Generate password
        print("Generating a strong password...", end=" ", flush=True)
        user_pw = generate_strong_random_pw()
        print("Done")
    else:
        user_pw_confirm = ''
        validated = False
        while not validated:
            while not user_pw:
                user_pw = getpass.getpass(PROMPT_NEW_ENTRY_PASSWORD_USER)
            while not user_pw_confirm:
                user_pw_confirm = getpass.getpass(PROMPT_CONFIRM_PW)
            validated = validate_entry_password(user_pw, user_pw_confirm)
            if not validated:
                user_pw = ''
                user_pw_confirm = ''
    return user_pw

def prompt_search_query():
    """
    Prompt user for a search query
    """
    query = ''
    while not query:
        query = input(PROMPT_SEARCH_QUERY).strip()
        # Query too short
        if len(query) < SEARCH_QUERY_MIN_LEN:
            print(ERROR_VIEW_QUERY_TOO_SHORT.format(SEARCH_QUERY_MIN_LEN))
            query = ''
        elif len(query) > SEARCH_QUERY_MAX_LEN:
            print(ERROR_VIEW_QUERY_TOO_SHORT.format(SEARCH_QUERY_MAX_LEN))
            query = ''
    return query

def prompt_entry_id(valid_ids:Iterable[int]=[])->int:
    entry_id = 0
    while not entry_id:
        entry_id = input(PROMPT_EDIT_CHOOSE_ONE).strip()
        # Attempt to parse int
        try:
            entry_id = int(entry_id)
        except ValueError:
            print(ERROR_EDIT_ENTRY_ID_NOT_NUMBER)
            entry_id = 0
        # Is the entry ID one of the available choices
        if valid_ids and len(valid_ids) > 0:
            if entry_id not in valid_ids:
                print()
                entry_id = 0
    return entry_id

def prompt_edit_name(original_name:str=''):
    print(PROMPT_EDIT_ENTRY_NAME)
    new_name = ''
    while not new_name:
        new_name = input(PROMPT_VALUE)
        if new_name == '':
            # Left blank. No changes
            print(EDIT_NO_CHANGES.format(original_name))
            break
        elif len(new_name) > SERVICE_NAME_MAX_LEN:
            print(ERROR_NEW_ENTRY_NAME_TOO_LONG)
            new_name = ''
        # TODO check if name already exists
        
        # Confirm change
        print(PROMPT_EDIT_CONFIRM_CHANGE_1)
        print(PROMPT_EDIT_CONFIRM_CHANGE_2.format(original_name, new_name))
        confirm = ask_yn(PROMPT_EDIT_CONFIRM_CHANGE_3)
        if not confirm:
            # If user says no, try again
            new_name = ''
            print()
    print()
    return new_name

def prompt_edit_userid(original_id:str=''):
    print(PROMPT_EDIT_ENTRY_ID)
    user_id = ''
    while not user_id:
        user_id = input(PROMPT_VALUE)
        if user_id == '':
            # Left blank. No changes.
            print(EDIT_NO_CHANGES.format(original_id))
            break
        elif len(user_id) > USER_ID_MAX_LEN:
            print(ERROR_NEW_ID_TOO_LONG)
            user_id = ''
        
        # Confirm change
        print(PROMPT_EDIT_CONFIRM_CHANGE_1)
        print(PROMPT_EDIT_CONFIRM_CHANGE_2.format(original_id, user_id))
        confirm = ask_yn(PROMPT_EDIT_CONFIRM_CHANGE_3)
        if not confirm:
            # If user says no, try again
            user_id = ''
            print()
    print()
    return user_id

def prompt_edit_password(ori_user_pw_bytes:bytes):
    ori_user_pw = ''
    global frn
    if ori_user_pw_bytes:
        ori_user_pw = frn.decrypt(ori_user_pw_bytes).decode()
    else:
        ori_user_pw = '****'
        
    print(PROMPT_EDIT_ENTRY_PW)
    option = ''
    while not option:
        option = input(PROMPT_EDIT_ENTRY_PW_2).strip()
        if option == '':
            option = '3'
        if not (option == '1' or option == '2' or option == '3'):
            print(ERROR_NEW_ENTRY_PW_INVALID_OPTIONS)
            option = ''
    
    user_pw = ''
    if option == '1':   # Random generation
        print("Generating a strong password...", end=" ", flush=True)
        user_pw = generate_strong_random_pw()
        print("Done")
    elif option == '2': # Custom password
        user_pw_confirm = ''
        validated = False
        while not validated:
            # Ask user for new password
            user_pw = getpass.getpass(PROMPT_VALUE)
            if not user_pw:
                # Left blank. No changes
                print(EDIT_NO_CHANGES.format(ori_user_pw))
                break
            # Confirm password
            print(PROMPT_EDIT_ENTRY_PW_CONFIRM)
            user_pw_confirm = getpass.getpass(PROMPT_VALUE)
            if not user_pw_confirm:
                # Left blank. No changes
                print(EDIT_NO_CHANGES.format(ori_user_pw))
                break
            validated = validate_entry_password(user_pw, user_pw_confirm)
    elif option == '3':
        user_pw = ''
        print(EDIT_NO_CHANGES.format(ori_user_pw))
    else: # Invalid option
        print(ERROR_NEW_ENTRY_PW_INVALID_OPTIONS)
    print()
    return user_pw


# ######## COMMANDS ########

def run_new():
    """
    Runs the command "new" to add a new credential entry into the database
    """
    global frn, conn
    try:
        print(PROMPT_NEW_ENTRY_TITLE)
        continue_confirmed = False
        while not continue_confirmed:
            new_name = prompt_entry_name()
            new_id = prompt_entry_userid()
            new_pw = prompt_entry_password()
            print()
            continue_confirmed = ask_yn(PROMPT_NEW_ENTRY_CONFIRM_ENTRY.format(new_name, new_id, new_pw))
        # Encrypt Password
        new_pw_enc = frn.encrypt(new_pw.encode())
        # Current timestamp
        current_ts = get_current_ts()
        with conn:
            conn.execute(SQL_INSERT_ENTRY, [new_name, new_id, new_pw_enc, current_ts, current_ts])
    except KeyboardInterrupt:
        handle_keyboardinterrupt()
        return

def run_view(args:list):
    global conn
    try:
        # Options
        show_password = False
        show_all = False

        # Parse arguments for options
        for arg in args:
            if arg in FLAG_SHOW_PW:
                show_password = True
            elif arg in FLAG_ALL:
                show_all = True
        
        if show_all:
            with conn:
                cur = conn.cursor()
                cur.execute('SELECT * FROM credentials')
                print_many_entry(cur, show_password=show_password)
            return

        # Query is first positional argument
        query = ''
        for arg in args:
            if arg[0] in QUOTATION_MARK and arg[-1] in QUOTATION_MARK:
                query = arg[1:-1]
                break
            elif arg[0] != '-':
                query = arg
                break
        
        # If query was not given as arguments, ask
        if not query:
            query = prompt_search_query()
        
        # Search from database
        with conn:
            cur = conn.cursor()
            cur.execute(SELECT_WHERE_NAME_LIKE, [f"%{query}%"])
            rows = cur.fetchall()
            if len(rows) > 1:
                print(VIEW_SEARCH_RESULT.format(len(rows), query), end="\n\n")
                print_many_entry(cur, show_password=show_password, raw_rows=rows)
            elif len(rows) > 0:
                # Only one entry found
                print(VIEW_SEARCH_RESULT.format(len(rows), query), end="\n\n")
                print_one_entry(rows[0], show_password=show_password)
            else:
                # Nothing found :(
                print(ERROR_VIEW_NO_SEARCH_RESULTS.format(query))
            cur.close()
    except KeyboardInterrupt:
        handle_keyboardinterrupt()
        return

def run_edit(args):
    try:
        # Look for view password flag
        show_password = False
        for arg in args:
            if arg in FLAG_SHOW_PW:
                show_password = True
                args.remove(arg)
        
        # Check if query was provided as a positional argument
        query = ''
        for arg in args:
            if arg[0] in QUOTATION_MARK and arg[-1] in QUOTATION_MARK:
                query = arg[1:-1]
                break
            elif arg[0] != '-':
                query = arg
                break

        # If query was not given as arguments, ask
        if not query:
            query = prompt_search_query()

        chosen_row = get_one_entry(show_password=show_password, query=query)
        # If search returned no results, stop.
        if not chosen_row:
            return
        
        confirm_choice = ask_yn(PROMPT_EDIT_CONFIRM_CHOICE)
        if not confirm_choice:
            return
        
        # Execute edit job
        print()
        entry_id = chosen_row[0]
        ori_name = chosen_row[1]
        ori_user_id = chosen_row[2]
        ori_user_pw = b''
        if show_password:
            ori_user_pw = chosen_row[3]

        new_name = prompt_edit_name(ori_name)
        new_user_id = prompt_edit_userid(ori_user_id)
        new_user_pw = prompt_edit_password(ori_user_pw)

        # Encrypt new password, if exists
        if new_user_pw:
            global frn
            new_user_pw_enc = frn.encrypt(new_user_pw.encode())
        
        # Construct SQL command
        to_update = {}
        if new_name:
            to_update['name'] = new_name
        if new_user_id:
            to_update['user_id'] = new_user_id
        if new_user_pw:
            to_update['user_pw'] = new_user_pw_enc
        
        sql = 'UPDATE credentials SET '
        cnt = 0
        sql_params = []
        for k, v in to_update.items():
            sql += f"{k}=?"
            sql_params.append(v)
            cnt += 1
            if cnt < len(to_update):
                sql += ', '
        sql += 'WHERE entry_id=?'
        sql_params.append(entry_id)

        if len(to_update) == 0:
            print(EDIT_NO_CHANGES_AT_ALL)
            return

        # Execute SQL
        with conn:
            print(EDIT_DB_UPDATE_IN_PROGRES, flush=True)
            conn.execute(sql, sql_params)
            print(SUCCESS_EDIT)

    except KeyboardInterrupt:
        handle_keyboardinterrupt()
        return

def run_del(args):
    try:
        # Look for show password flags
        show_password = FLAG_SHOW_PW in args
        if show_password:
            for flg in FLAG_SHOW_PW:
                if flg in args:
                    args.remove(flg)
        
        # Check if query was provided as a positional argument
        query = ''
        for arg in args:
            if arg[0] in QUOTATION_MARK and arg[-1] in QUOTATION_MARK:
                query = arg[1:-1]
                break
            elif arg[0] != '-':
                query = arg
                break

        # If query was not given as arguments, ask
        if not query:
            query = prompt_search_query()

        # Find an unique entry with search query
        chosen_row = get_one_entry(show_password=show_password, query=query)
        if not chosen_row:
            return
        
        # Ask twice before continuing
        print()
        confirm_1 = ask_yn(PROMPT_DELETE_CONFIRM)
        if not confirm_1:
            print(ERROR_USER_ABORT)
            return
        confirm_2 = ask_yn(PROMPT_DELETE_CONFIRM_2)
        if not confirm_2:
            print(ERROR_USER_ABORT)
            return
        
        # Perform delete
        entry_id = chosen_row[0]
        global conn
        # If not initialized or not decrypted
        if type(conn) != sqlite3.Connection:
            print(ERROR_DELETE_NOT_INIT)
            return
        
        try:
            with conn:
                conn.execute(DELETE_WHERE_ENTRY_ID, [entry_id])
                print(SUCCESS_DELETE)
        except sqlite3.DatabaseError:
            # Inform user of error in case delete fails
            print(ERROR_DELETE_FAILED)

    except KeyboardInterrupt:
        handle_keyboardinterrupt()
        return

def run_lock():
    print()
    global frn, conn
    before_exit(frn, conn)
    init()

def run_sql():
    global conn
    with conn:
        cur = conn.cursor()
        cur.execute(SELECT_WHERE_NAME_LIKE, [f"%{input('query: ')}%"])
        rows = cur.fetchall()
        for row in rows:
            print(row)

def run_passwd():
    pass

def get_cmd():
    # init
    cmd = ''
    args = []
    try:
        # Get user input
        user_input = input(PROMPT_CMD).strip()
        while not user_input:
            user_input = input(PROMPT_CMD).strip()
        user_input = user_input.split(" ")

        # Correctly parse quotation marks
        if len(user_input) > 0:
            cmd = user_input[0]
        if len(user_input) > 1:
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
    except KeyboardInterrupt:
        print(ERROR_USER_ABORT)
        raise KeyboardInterrupt

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
    elif cmd in CMD_PASSWD:
        run_passwd()
    elif cmd == 'sql': # DEBUG
        run_sql()
    else:
        print("Unsupported command!")

def display_splash():
    f = Figlet(font='slant')
    print(f.renderText("PYPASS"), end="\n\n")
    print(SPLASH_WELCOME)
    print(SPLASH_TIP, end="\n\n")

def main():
    display_splash()
    global master_key, master_salt, frn, conn
    master_key, master_salt, frn, conn = init()
    try:
        cmd, args = get_cmd()
        while cmd not in CMD_EXIT:
            run_cmd(cmd, args)
            print()
            cmd, args = get_cmd()
    finally:
        before_exit(frn, conn)
        master_key = None
        master_salt = None


if __name__ == "__main__":
    main()