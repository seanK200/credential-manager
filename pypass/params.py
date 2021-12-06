DATA_DNAME = 'data'

SCRYPT_R = 8
SCRYPT_N = 2 ** 15
SCRYPT_P = 1
SCRYPT_MAX_MEM = 64 * 2 ** 20
SCRYPT_DKLEN = 32

HASH_ENCODING = 'utf-8'

# DB
DB_FNAME = 'credentials.db'
DB_TABLE = 'credentials'
DB_COLUMNS = {
    'entry_id': {
        'index': 0,
        'type': 'INTEGER PRIMARY KEY', 
        'encrypted': False
    }, 
    'name': {
        'index': 1,
        'type': 'TEXT', 
        'encrypted': False
    }, 
    'user_id': {
        'index': 2,
        'type': 'BLOB', 
        'encrypted': True
    }, 
    'user_pw': {
        'index': 3,
        'type': 'BLOB', 
        'encrypted': True
    }, 
    'url': {
        'index': 4,
        'type': 'TEXT', 
        'encrypted': False
    }, 
    'date_created': {
        'index': 5,
        'type': 'INTEGER', 
        'encrypted': False
    },
    'date_modified': {
        'index': 6,
        'type': 'INTEGER', 
        'encrypted': False
    },
    'entry_hash': {
        'index': 7,
        'type': 'BLOB', 
        'encrypted': False
    },
    'entry_salt': {
        'index': 8,
        'type': 'BLOB', 
        'encrypted': False
    }
}
DB_COLUMN_NAMES = list(DB_COLUMNS.keys())