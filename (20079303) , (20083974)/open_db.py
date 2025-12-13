import sqlite3

conn = sqlite3.connect(r'C:\Users\Admin\Desktop\ProgrammingCA2\viroscan.db')
cursor = conn.cursor()


cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("Tables inside viroscan.db:", tables)

cursor.execute("SELECT * FROM scan_history;")
rows = cursor.fetchall()

print("\nData inside scan_history table:")
for row in rows:
    print(row)


conn.close()
