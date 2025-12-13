import sqlite3


conn = sqlite3.connect("viroscan.db")
cursor = conn.cursor()


cursor.execute('''
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT NOT NULL
)
''')

conn.commit()
conn.close()

print(" Database and table created successfully!")
