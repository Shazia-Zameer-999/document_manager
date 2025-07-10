import sqlite3

conn = sqlite3.connect('users.db')

conn.execute('''
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    filename TEXT NOT NULL,
    category TEXT NOT NULL
)
''')

conn.commit()
conn.close()
print("File table created!")