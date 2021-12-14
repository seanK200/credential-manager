# Python standard Libraries
import os, hashlib, base64, datetime, sqlite3

# 3rd parties
import PyInquirer as pyinq
from PyInquirer import prompt

# Local
from pypass.params import *
from pypass.consts import ERROR_USER_ABORT, ERROR_DATABASE_ERROR, ERROR_INVALID_SIGNATURE

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

def ask_yn(prompt_msg:str, default_ans=False)->bool:
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
    return ans['question']

def handle_keyboard_interrupt():
    print()
    print(ERROR_USER_ABORT)

# ######### DB HELPERS #########

def db_create_table(conn:sqlite3.Connection, table_name:str, cols:dict, if_not_exists:bool=True):
    # Construct SQL query
    sql = 'CREATE TABLE '
    if if_not_exists:
        sql += 'IF NOT EXISTS '
    sql += table_name
    sql += '('
    sql_cols = ''
    for col_name in cols:
        sql_cols += col_name + ' '
        sql_cols += cols[col_name]['type']
        sql_cols += ', '
    # Remove the last trailing comma
    sql += sql_cols[:-2]
    sql += ')'
    # and execute
    with conn:
        cur = conn.cursor()
        cur.execute(sql)
        cur.close()

def db_connect(username, *, init=False):
    db_filename = username + DB_FILE_EXT
    db_filepath = os.path.join(DATA_DNAME, db_filename)
    conn = sqlite3.connect(db_filepath)
    if init:
        db_create_table(conn, DB_TABLE, DB_COLUMNS)
    return conn

def db_add_entry(user_auth,\
     name:str, user_id:str, user_pw:str, url:str=''):
    """
    Add an entry into the credentials database, and returns the inserted row.
    If insertion fails, return None.
    """
    # SQL Query
    sql = f'INSERT INTO {DB_TABLE}'
    sql += '(name, user_id, user_pw, url, date_created, date_modified) '
    sql += 'VALUES(?, ?, ?, ?, ?, ?)'

    # Params
    user_id_enc = user_auth.encrypt(user_id)
    user_pw_enc = user_auth.encrypt(user_pw)
    current_ts = get_current_ts()
    sql_params = [name, user_id_enc, user_pw_enc, url, current_ts, current_ts]

    entry_id = -1
    # Run SQL
    try:
        with user_auth.conn as conn:
            cur = conn.cursor()
            cur.execute(sql, sql_params)
            entry_id = cur.lastrowid
            cur.close()
    except sqlite3.DatabaseError:
        return False
    
    # Sign the entry
    user_auth.sign_entry(entry_id, update_db=True)

    return True

def db_update_entry(user_auth, entry_id:int, name:str='', user_id:str='', user_pw:str='', url:str=''):
    to_update = {}
    if name: to_update['name'] = name
    if user_id: 
        if type(user_id) != bytes:
            user_id = user_auth.encrypt(user_id)
        to_update['user_id'] = user_id
    if user_pw: 
        if type(user_pw) != bytes:
            user_pw = user_auth.encrypt(user_id)
        to_update['user_pw'] = user_pw
    if url: to_update['url'] = url
    
    # Quit if nothing to update
    if len(to_update) == 0: return False

    # Construct query
    sql = f'UPDATE {DB_TABLE} SET '
    sql_params = []
    for k, v in to_update.items():
        sql += f"{k}=?, "
        sql_params.append(v)
    sql = sql[:-2] # Drop last trailing comma
    sql += 'WHERE entry_id=?'
    sql_params.append(entry_id)

    # Execute query
    conn = user_auth.conn
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(sql, sql_params)
            cur.close()
    except sqlite3.DatabaseError:
        print(ERROR_DATABASE_ERROR)
        return False
    
    # Re-sign the updated entry
    try:
        user_auth.sign_entry(entry_id, update_db=True)
    except sqlite3.DatabaseError:
        print(ERROR_DATABASE_ERROR)
        return False

    return True

def db_delete_entry(user_auth, entry_id:int):
    sql = f'DELETE FROM {DB_TABLE} WHERE entry_id=?'
    try:
        with user_auth.conn as conn:
            cur = conn.cursor()
            cur.execute(sql, [entry_id])
            cur.close()
    except sqlite3.DatabaseError:
        print(ERROR_DATABASE_ERROR)
        raise # DEBUG
        # return False
    
    return True

def row_to_dict(row:list, cols=DB_COLUMNS)->dict:
    """
    Convert a database row to a dictionary for easy access
    """
    if type(row) == dict:
        return row

    row_dict = dict()
    for col_name in cols:
        row_dict[col_name] = row[cols[col_name]['index']]
    
    # Formate datetime string from timestamp
    if 'date_created' in row_dict:
        if type(row_dict['date_created']) == int:
            row_dict['date_created'] = format_date_from_ts(row_dict['date_created'])
    if 'date_modified' in row_dict:
        if type(row_dict['date_modified']) == int:
            row_dict['date_modified'] = format_date_from_ts(row_dict['date_modified'])

    return row_dict

def decrypt_row(row, user_auth, decrypt_pw=False, to_dict=False):
    """
    Decrypts a row of credentials database.
    """
    row = row_to_dict(row)
    d_row = [] # decrypted row
    for col_name, col_value in row.items():
        decrypt_needed = DB_COLUMNS[col_name]['encrypted'] and \
                            (decrypt_pw or col_name != 'user_pw') and \
                                type(col_value) == bytes
        if decrypt_needed:
            d_row.append(user_auth.decrypt(col_value).decode(HASH_ENCODING))
        else:
            d_row.append(col_value)
    if to_dict:
        d_row = row_to_dict(d_row)
    return d_row

def prompt_choose_one_entry(rows:list, user_auth, *, return_entry_id_only=False)->sqlite3.Row:
    """
    Takes multiple rows obtained from a sqlite3 query as input, 
    and prompts the user to select one. Returns the selected row.
    """
    chosen_row = []  # The Chosen One

    # Key: Text to display in PyInquirer prompt, Value: Entry ID
    prompt_choices = []

    for row in rows:
        row_dict = row_to_dict(row)
        # e.g. Github (userid001)
        row_txt = f"{row_dict['name']} ({user_auth.decrypt(row_dict['user_id']).decode()})"
        try:
            # If there is duplicate
            duplicate_idx = prompt_choices.index(row_txt)
            duplicate_txt = prompt_choices[duplicate_idx]
            duplicate_row = row_to_dict(rows[duplicate_idx])
            # Try adding url
            if row_dict['url'] == duplicate_row['url']:
                # Add last modified
                row_txt += ' ' + row_dict['date_modified']
                duplicate_txt += ' ' + duplicate_row['date_modified']
            else:
                # Add url
                row_txt += ' ' + row_dict['url']
                duplicate_txt += ' ' + duplicate_row['url']
            
            prompt_choices.append(row_txt)
            prompt_choices[duplicate_idx] = duplicate_txt
        except ValueError:
            # No duplicates, just add
            prompt_choices.append(row_txt)

    # Ask user
    question = [
        {
            'type':'list',
            'name':'chosen_row_txt',
            'message': 'Choose one entry',
            'choices': prompt_choices
        }
    ]
    
    chosen_row_txt = pyinq.prompt(question).get('chosen_row_txt', prompt_choices[0])
    chosen_row_idx = prompt_choices.index(chosen_row_txt)
    chosen_row = rows[chosen_row_idx]

    if return_entry_id_only:
        chosen_row = row_to_dict(chosen_row)
        return chosen_row['entry_id']
    
    return chosen_row

def prompt_invalid_entry_action():
    """
    Asks users what to do with for a database entry with an invalid signature

    (Returns)
        The action that the user chose. Possible values are: 'delete', 'view', \
            'mark_valid', and 'return_to_menu'
    """
    print(ERROR_INVALID_SIGNATURE)
    question = [
        {
            'type':'list',
            'name':'action',
            'message':'Choose action',
            'choices': [
                {
                    'name': 'Delete entry from database (recommended)',
                    'value': 'delete'
                },
                {
                    'name': 'View entry anyway (UNSAFE)',
                    'value': 'view'
                },
                {
                    'name': 'Mark entry as valid (UNSAFE)',
                    'value': 'mark_valid'
                },
                {
                    'name': 'Return to menu',
                    'value': 'return_to_menu'
                }
            ]
        }
    ]
    chosen_action = prompt(question).get('chosen_action', '')
    return chosen_action


def get_multiple_entries(user_auth, query:str='', *, query_by:str='', decrypt=False):
    # If no query is supplied, ask.
    if not query:
        search_query_question = [
            {
                'type':'input',
                'name':'query',
                'message':'Enter search query:',
                'validate': lambda answer: len(answer) > 0 and len(answer) < 128
            }
        ]
        query = prompt(search_query_question)['query']

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
    else:
        raise ValueError("helpers.get_multiple_entries(): Empty query")
    
    # Execute the query
    try:
        with user_auth.conn as conn:
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
            decrypted_rows.append(decrypt_row(row, user_auth))
        return decrypted_rows

    return rows

def get_one_entry(user_auth, query:str, *, \
    query_by:str='', decrypt:bool=False, decrypt_pw:bool=False, \
        return_entry_id_only=False, to_dict=False):
    """
    Run query on database and retrive only one query. If query returns more than one rows,
    prompt user to select one.
    """
    # All the rows matching returned from DB query
    rows = get_multiple_entries(user_auth, query, query_by=query_by)
    # The Chosen One
    row = []

    if len(rows) > 1:
        row = prompt_choose_one_entry(rows, user_auth)
    elif len(rows) > 0:
        row = rows[0]
    else:
        # Not found
        print(f"Found no entry for search '{query}'.")
        return row
    
    # Verify the entry
    verified = user_auth.verify_entry(row)
    if not verified:
        invalid_row= row_to_dict(row)
        # Invalid signature. Ask user what to do
        invalid_entry_action = prompt_invalid_entry_action()
        if invalid_entry_action == 'delete':
            # Delete the invalid entry
            db_delete_entry(user_auth, invalid_row['entry_id'])
            row = []
        elif invalid_entry_action == 'view':
            # View the entry
            return row
        elif invalid_entry_action == 'mark_valid':
            # Mark the entry valid by re-signing it
            user_auth.sign_entry(invalid_row['entry_id'], update_db=True)
        elif invalid_entry_action == 'return_to_menu':
            row = []

        return row

    if return_entry_id_only:
        return row[DB_COLUMNS['entry_id']['index']]
    
    if decrypt:
        row = decrypt_row(row, user_auth, decrypt_pw)

    if to_dict:
        row = row_to_dict(row)
    
    return row

def get_entry_by_id(user_auth, entry_id:int, *, \
    decrypt:bool=False, decrypt_pw:bool=False, to_dict=False):
    conn = user_auth.conn
    row = []
    try: 
        with conn:
            sql = f'SELECT * FROM {DB_TABLE} WHERE entry_id=?'
            cur = conn.cursor()
            cur.execute(sql, [entry_id])
            row = cur.fetchone()
            cur.close()
    except sqlite3.DatabaseError:
        print(ERROR_DATABASE_ERROR)
        row = []
    
    if decrypt:
        row = decrypt_row(row, user_auth, decrypt_pw, to_dict=to_dict)
    elif to_dict:
        row = row_to_dict(row)
    
    return row