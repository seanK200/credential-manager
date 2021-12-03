SQL_CREATE_TABLE = 'CREATE TABLE IF NOT EXISTS credentials(entry_id INTEGER PRIMARY KEY, \
name TEXT, user_id TEXT, user_pw BLOB, date_created TEXT, date_modified TEXT)'

SQL_INSERT_ENTRY = 'INSERT INTO credentials(name, user_id, user_pw, date_created, \
date_modified) VALUES (?, ?, ?, ?, ?)'

SELECT_WHERE_NAME_LIKE = 'SELECT * FROM credentials WHERE name LIKE ?'

DELETE_WHERE_ENTRY_ID = 'DELETE FROM credentials WHERE entry_id=?'