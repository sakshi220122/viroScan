import sqlite3

conn = sqlite3.connect("C:\Users\Admin\Desktop\ProgrammingCA2\viroscan.db")
cursor = conn.cursor()


cursor.execute("DELETE FROM scan_history WHERE target = 'http://example.com'")

conn.commit()
conn.close()

print("Deleted all 'http://example.com' records from database!")
