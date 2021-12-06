# Python standard Libraries
import os, hashlib, base64, hmac, datetime, sqlite3
from typing import List, Union

# 3rd parties
from cryptography.fernet import Fernet, InvalidToken
import PyInquirer as pyinq

# Local
from params import *

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

# Row: entry_id, name, user_id, user_pw, url, date_created, date_modified, entry_hash, entry_salt
def sign_entry(row:list, key:bytes)->bytes:
    """
    Sign an entry (row of a sqlite database) using BLAKE2, and return the signature
    """
    entry_salt = os.urandom(hashlib.blake2b.SALT_SIZE)
    h = hashlib.blake2b(digest_size=64, key=key, salt=entry_salt)
    
    # hash except hash and salt columns
    if len(row) == 9:
        row = row[:-2]
    
    # Validate row
    if len(row) != 7:
        raise ValueError("pypass.helpers.sign_entry(): row length must be either 9 or 7.")
    
    for column in row:
        h.update(column)
    
    return h.hexdigest().encode(HASH_ENCODING)

def verify_entry(row:list, key:bytes)->bool:
    """
    Verify the signature of a credential entry, and returns verification result
    """
    # Validate row
    if len(row) != 9:
        raise ValueError("pypass.helpers.verify_entry(): row length must be 9.")
    
    entry_hash = row[7]
    entry_salt = row[8]
    row = row[:-2]

    h = hashlib.blake2b(digest_size=64, key=key, salt=entry_salt)
    for column in row:
        h.update(column)
    good_hash = h.hexdigest().encode(HASH_ENCODING)
    
    return hmac.compare_digest(entry_hash, good_hash)

def fencrypt(payload:Union[bytes, str], frn:Fernet=None, *, key:bytes=b''):
    """
    Encrypt the payload data with a given Fernet object (or a key).
    Either the Fernet object or the key must be specified.
    If the given payload data is a string type, encode it.
    """
    if not frn:
        if not key:
            raise ValueError("pypass.helpers.fencrypt: \
                Key must be specified when a Fernet object is not given.")
        frn = Fernet(key)

    if type(payload) == str:
        payload = payload.encode(HASH_ENCODING)

    return frn.encrypt(payload)

def fdecrypt(encrypted_payload:bytes, frn:Fernet=None, *, key:bytes=b'', decode=False)->bytes:
    """
    Decrypt an encrypted data with a given Fernet object (or a key).
    Either the Fernet object or the key must be specified.
    Returns the decrypted bytes object, or an empty bytes object 
    (falsy) when decryption fails
    """
    decrypted_data = b''
    if not frn:
        if not key:
            raise ValueError("pypass.helpers.fencrypt: \
                Key must be specified when a Fernet object is not given.")
        frn = Fernet(key)
    
    try:
        decrypted_data = frn.decrypt(encrypted_payload)
    except InvalidToken:
        decrypted_data = b''
    
    if decode:
        decrypted_data = decrypted_data.decode(HASH_ENCODING)
    
    return decrypted_data

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

def ask_yn(prompt_msg:str, default_ans:False)->bool:
    """
    Ask a yes/no question to the user, return answer as boolean value
    """
    question = [
        {
            'type':'confirm',
            'name':'question',
            'message': prompt_msg,
            'default': default_ans
        }
    ]
    ans = pyinq.prompt(question)
    return ans[question]

# ######### DB HELPERS #########

def db_connect():
    db_filepath = os.path.join(DATA_DNAME, DB_FNAME)
    return sqlite3.connect(db_filepath)

def db_init(conn:sqlite3.Connection):
    with conn:
        conn.execute()

def row_to_dict(row:list)->dict:
    """
    Convert a database row to a dictionary for easy access
    """
    row_dict = dict()
    for col_name in DB_COLUMNS:
        row_dict[col_name] = row[DB_COLUMNS[col_name].index]
    return row_dict

def decrypt_row(row, frn:Fernet, decrypt_pw=False, to_dict=False):
    """
    Decrypts a row of credentials database.
    """
    row = row_to_dict(row)
    d_row = [] # decrypted row
    for col_name, col_value in row.items():
        decrypt_needed = DB_COLUMNS[col_name].encrypted and (decrypt_pw or col_name != 'user_pw')
        if decrypt_needed:
            d_row.append(fdecrypt(col_value, frn, decode=True))
        else:
            d_row.append(col_value)
    if to_dict:
        row_to_dict(d_row)
    return d_row

def prompt_choose_one_entry(rows:List[sqlite3.Row], frn:Fernet, *, return_entry_id_only=False)->sqlite3.Row:
    """
    Takes multiple rows obtained from a sqlite3 query as input, 
    and prompts the user to select one. Returns the selected row.
    """
    chosen_row = []  # The Chosen One

    # Key: Text to display in PyInquirer prompt, Value: Entry ID
    prompt_list = dict() 

    for row in rows:
        row = row_to_dict(row)
        # e.g. Github (userid001)
        row_to_txt = f"{row['name']} ({fdecrypt(row['user_id'], frn, decode=True)})"
        prompt_list[row_to_txt] = row['entry_id']

    # Ask user
    question = [
        {
            'type':'list',
            'name':'chosen_row',
            'message': 'Choose one entry (use arrow keys + ENTER):',
            'list': prompt_list.keys()
        }
    ]
    ans = pyinq.prompt(question)
    chosen_entry_id = prompt_list[ans['chosen_row']]

    if return_entry_id_only:
        return chosen_entry_id

    for row in rows:
        if row[DB_COLUMNS['entry_id'].index] == chosen_entry_id:
            chosen_row = row
            break
    
    return chosen_row

def get_multiple_entries(conn:sqlite3.Connection, frn: Fernet, query:str='', *, query_by:str='', decrypt=False):
    # Construct SQL query
    sql = f'SELECT * FROM {DB_TABLE}'
    sql_params = []
    if query:
        if not query_by:
            # Search by name and url
            sql += ' WHERE (name LIKE ?) OR (url LIKE ?)'
            sql_params.append(f'%{query}%')
            sql_params.append(f'%{query}%')
        else:
            if query in DB_COLUMN_NAMES:
                sql += f' WHERE {query_by} LIKE ?'
                sql_params.append(f'%{query}%')
            else:
                raise ValueError(f"helpers.get_multiple_entries(): \
                    Invalid query_by '{query_by}'.")
    
    # Execute the query
    try:
        with conn:
            cur = conn.cursor()
            if sql_params:
                cur.execute(sql, sql_params)
            else:
                cur.execute(sql)
    except sqlite3.DatabaseError as dbe:
        print(f"helpers.get_multiple_entries(): {query=}, {query_by=}")
        raise dbe
    
    # Clean up and return the results
    rows = cur.fetchall()
    cur.close()

    # Decrypt row before returning
    if decrypt:
        decrypted_rows = []
        for row in rows:
            decrypted_rows.append(decrypt_row(row, frn))
        return decrypted_rows

    return rows

def get_one_entry(conn:sqlite3.Connection, frn:Fernet, query:str, *, query_by:str='', return_entry_id_only=False):
    """
    Run query on database and retrive only one query. If query returns more than one rows,
    prompt user to select one.
    """
    # All the rows matching returned from DB query
    rows = get_multiple_entries(conn, query, query_by=query_by)
    # The Chosen One
    row = []

    if len(rows) > 1:
        row = prompt_choose_one_entry(rows, frn)
    elif len(rows) > 0:
        row = rows[0]
    else:
        row = []
    
    if return_entry_id_only:
        return row[DB_COLUMNS['entry_id'].index]
    
    return row