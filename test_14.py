import sqlite3

# Connect to your existing Easy Cash database
conn = sqlite3.connect("easy_cash.db")
cur = conn.cursor()

# Fetch all transactions to inspect user_id and note
cur.execute("SELECT id, user_id, note FROM transactions LIMIT 10")
rows = cur.fetchall()

print("\n=== Transaction Table Preview ===")
for r in rows:
    print(f"ID: {r[0]}, User_ID: {r[1]}, Note: {r[2]}")

conn.close()
