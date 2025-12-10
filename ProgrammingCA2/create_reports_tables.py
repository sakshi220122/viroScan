import sqlite3


def create_reports_table():
    conn = sqlite3.connect('viroscan.db')  
    c=conn.cursor
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS suspicious_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            email TEXT NOT NULL,
            issue TEXT NOT NULL,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("suspicious_reports table created successfully.")
