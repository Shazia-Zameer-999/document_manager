import sqlite3

# Connect to the database (or create it if it doesn't exist)
conn = sqlite3.connect('users.db')

# Create a table to store users
conn.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
''')

conn.commit()
conn.close()
print("Database created and users table ready.")