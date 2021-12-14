# Python standard libraries
import os, sqlite3
from hashlib import blake2b
from typing import List
from getpass import getpass

# 3rd parties
from cryptography.fernet import Fernet, InvalidToken

# Local
from pypass.consts import *
from pypass.params import *
from pypass.helpers import *

class UserAuth:
    def __init__(self, username, master_key):
        if username and master_key:
            self.username = username
            self.master_key = master_key
            self.frn = Fernet(master_key)
            self.conn = db_connect(self.username, init=True)
        else:
            raise ValueError("<masterauth.UserAuth> Username and master key not provided.")

    def encrypt(self, data:bytes)->bytes:
        """
        Encrypts the given data using the user's key

        data
            The data to encrypt. Data must either be a string or a correctly encoded bytes type.
        
        (Returns)
            The encrypted data in bytes type.
        """
        if type(data) != bytes:
            data = data.encode(HASH_ENCODING)
        return self.frn.encrypt(data)
    
    def decrypt(self, data:bytes)->bytes:
        """
        Decrypts the given data using the user's key.
        Returns an empty bytes object when decryption fails.
        """
        decrypted = b''
        try:
            decrypted = self.frn.decrypt(data)
        except InvalidToken:
            decrypted = b''
        return decrypted
    
    def update_entry_hash(self, entry_id, entry_hash:bytes, entry_salt:bytes):
        sql = f'UPDATE {DB_TABLE} SET entry_hash=?, entry_salt=? WHERE entry_id=?'
        sql_params = [entry_hash, entry_salt, entry_id]
        with self.conn as conn:
            cur = conn.cursor()
            cur.execute(sql, sql_params)
            cur.close()

    def sign_entry(self, entry_id:int=0, *, row:list=[], update_db:bool=False, entry_salt:bytes=b''):
        """
        Sign an entry (row of a sqlite database) using BLAKE2, and return the signature
        """
        # If salt not provided, randomly generate one
        return_salt = False
        if not entry_salt:
            entry_salt = os.urandom(hashlib.blake2b.SALT_SIZE)
            return_salt = True
        
        # If row is not provided, try to select from database
        if not row:
            if entry_id > 0:
                try:
                    sql = f'SELECT * FROM {DB_TABLE} WHERE entry_id=?'
                    with self.conn as conn:
                        cur = conn.cursor()
                        cur.execute(sql, [entry_id])
                        row = cur.fetchone()
                        cur.close()
                except sqlite3.DatabaseError:
                    row = []
        
        # Initialize hash object
        h = blake2b(digest_size=64, key=self.master_key, salt=entry_salt)

        # hash except hash and salt columns
        if len(row) == 9:
            row = row[:-2]
        
        # Validate row
        if len(row) != 7:
            raise ValueError("pypass.UserAuth.sign_entry(): row length must be either 9 or 7.")
        
        # Hash row
        for column in row:
            if type(column) != bytes:
                if type(column != str):
                    column = str(column)
                column = column.encode(HASH_ENCODING)
            h.update(column)
        entry_hash = h.hexdigest().encode(HASH_ENCODING)

        # Update the DB if necessary
        if update_db:
            entry_id = row[0]
            try:
                self.update_entry_hash(entry_id, entry_hash, entry_salt)
            except sqlite3.DatabaseError:
                print(ERROR_DATABASE_ERROR)
                return False
        
        # Return hash digest
        if return_salt:
            # and salt, if necessary
            return entry_hash, entry_salt
        
        if not update_db:
            return entry_hash
        
        return True
    
    def verify_entry(self, row)->bool:
        """
        Verify that the signature of a credential entry is valid. 
        Returns True if signature is valid, and False otherwise.
        """
        row_d = row_to_dict(row)
        good_entry_hash = self.sign_entry(row=row, entry_salt=row_d['entry_salt'])
        return row_d['entry_hash'] == good_entry_hash
    
    def __del__(self):
        # Connection
        if type(self.conn) == sqlite3.Connection:
            self.conn.close()
        del self.conn
        # Fernet
        del self.frn
        # Username
        self.username == ''
        del self.username
        # Master key overwrite and delete
        master_key_len = len(self.master_key)
        self.master_key = os.urandom(master_key_len)
        del self.master_key

# ######## DB HELPERS #########

def master_db_create_table(conn:sqlite3.Connection):
    db_create_table(conn, MASTER_DB_TABLE, MASTER_DB_COLUMNS)

def master_db_connect()->sqlite3.Connection:
    """Connect to database for master authentication"""
    conn = sqlite3.connect(os.path.join(DATA_DNAME, MASTER_DB_FNAME))
    master_db_create_table(conn)
    return conn

def get_user_if_exists(username:str, conn:sqlite3.Connection)->list:
    """
    Get user information from the master authentication database. 
    Returns empty list if user is not found.
    """
    with conn:
        cur = conn.cursor()
        sql = f'SELECT * FROM {MASTER_DB_TABLE} WHERE username=?'
        cur.execute(sql, [username])
        rows = cur.fetchall()
        cur.close()
        if len(rows) > 0:
            return rows[0]
    
    return []

def master_db_add_entry(user_auth:UserAuth, \
    master_conn:sqlite3.Connection, username:str, auth_salt:bytes):
    """
    Adds a new entry to the Pypass user database.

    user_auth
        A UserAuth class object
    
    master_conn
        A connection to the master database.

    username
        username of the new user
    
    auth_salt
        Salt for hashing the user's master password
    """
    username_enc = user_auth.encrypt(username)
    current_ts = get_current_ts()
    sql = f'INSERT INTO {MASTER_DB_TABLE}(username, username_enc, auth_salt, \
        date_created, date_pw_change) VALUES (?, ?, ?, ?, ?)'
    sql_params = [username, username_enc, auth_salt, current_ts, current_ts]
    try:
        with master_conn:
            cur = master_conn.cursor()
            cur.execute(sql, sql_params)
    except sqlite3.DatabaseError:
        print(ERROR_CREATE_PYPASS_USER_DATABASEERROR)
        raise

# ######### Validators #########

def validate_master_username(master_username, *, new_user=False, verbose=False)->bool:
    # Empty
    if not master_username:
        if verbose:
            print(ERROR_MASTER_USERNAME_EMPTY)
        return False
    
    # Too long
    if len(master_username) > MASTER_USERNAME_MAX_LEN:
        if verbose:
            print(ERROR_MASTER_USERNAME_TOO_LONG.format(len(master_username)))
        return False
    
    # Unsupported chars
    for ch in master_username:
        if ch not in PRINTABLE:
            if verbose:
                print(ERROR_MASTER_USERNAME_UNSUPPORTED_CHARS.format(ch))
            return False

    # If new user, check if username is unique
    if new_user:
        if get_user_if_exists(master_username):
            if verbose:
                print(ERROR_MASTER_USERNAME_ALREADY_EXISTS.format(master_username))
            return False
    
    # All tests passed!
    return True

def validate_master_pw(pw:str, pw_confirm:str)->bool:
    """Validate master password"""
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

# ######### PROMPTS #########

def prompt_master_username(new_user=False)->str:
    """Prompt user for master username"""
    master_username = ''
    while not master_username:
        master_username = input(PROMPT_MASTER_USERNAME)
        if not validate_master_username(master_username):
            master_username = ''
    return master_username

def prompt_master_pw()->str:
    """Prompt user for master password"""
    entered_pw = ''
    while not entered_pw:
        entered_pw = getpass(PROMPT_MASTER_PW)
    return entered_pw

def prompt_new_master_pw()->tuple[bytes, bytes]:
    """Create or change master password"""
    pw = ''
    validated = False
    while not validated:
        pw = getpass(PROMPT_NEW_MASTER_PW)
        pw_confirm = getpass(PROMPT_CONFIRM_PW)
        validated = validate_master_pw(pw, pw_confirm)
    key, salt = generate_key(pw)
    return key, salt

def create_pypass_user(master_conn:sqlite3.Connection, username:str):
    """
    Creates a new Pypass user and updates the master database.

    username
        Username of the new user. A user must supply this username
        along with the password to login to Pypass.
    """
    master_key, master_salt = prompt_new_master_pw()
    user_auth = UserAuth(username, master_key)
    try:
        master_db_add_entry(user_auth, master_conn, username, master_salt)
        return user_auth
    except sqlite3.DatabaseError:
        print(ERROR_CREATE_PYPASS_USER_FAIL)
        raise

def authenticate():
    """
    Performs the master authentication, and returns a Fernet object if authentication succeeded.
    Returns literal None if authentication fails.
    External modules should directly call only this method.
    """
    conn = master_db_connect()
    username = ''
    master_key = b''
    user_auth = None # return value

    try:
        username = prompt_master_username()
        user = get_user_if_exists(username, conn)
        if user:
            # Returning user. Load user information from DB
            user = row_to_dict(row=user, cols=MASTER_DB_COLUMNS)
            master_salt = user['auth_salt']
            # Ask user for the master password,
            master_pw = prompt_master_pw()
            # and initialize a Fernet object with it
            master_key, master_salt = generate_key(master_pw, master_salt)
            user_auth = UserAuth(username, master_key)
            # Attempt to decrypt
            username_dec = user_auth.decrypt(user['username_enc'])
            if username_dec:
                # If decryption fails, return None and fail initialization
                if username_dec.decode(HASH_ENCODING) != username:
                    print(ERROR_WRONG_MASTER_PASSWORD)
                    user_auth = None
            else:
                print(ERROR_WRONG_MASTER_PASSWORD)
                user_auth = None
        else:
            # User not found
            print(ERROR_MASTER_USERNAME_DOES_NOT_EXIST.format(username))
            # Ask if user wants to create new user
            if ask_yn(PROMPT_MASTER_USER_CREATE):
                try:
                    # Create a new PyPass user,
                    user_auth = create_pypass_user(master_conn=conn, username=username)
                    # and initialize a Fernet object
                except sqlite3.DatabaseError:
                    # Create user failed. (Auth failed)
                    username = ''
            else:
                # authentication failed
                username = ''
    except KeyboardInterrupt:
        # Control + C
        print(ERROR_MASTER_AUTH_KEYBOARD_INTERRUPT)
        raise KeyboardInterrupt
    finally:
        # Cleanup
        if type(conn) == sqlite3.Connection:
            conn.close()
        if not username:
            return None
        return user_auth