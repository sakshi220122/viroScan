import sqlite3


conn = sqlite3.connect('viroscan.db')
cursor = conn.cursor()


cursor.execute("SELECT * FROM scan_history")
rows = cursor.fetchall()


if rows:
    for row in rows:
        print(row)
else:
    print("No scan records found.")

conn.close()
