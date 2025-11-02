# view_db.py
import sqlite3
from cryptography.fernet import Fernet

DB = "easy_cash.db"
KEY_FILE = "fernet.key"

def show_users():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash FROM users")
    rows = cur.fetchall()
    print("=== users table ===")
    for r in rows:
        uid, uname, phash = r
        # show a readable prefix of the hash (avoid huge binary)
        # if phash is bytes, print repr; otherwise print as-is
        print(uid, "|", uname, "|", repr(phash)[:80])
    conn.close()

def show_transactions():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT id, user_id, amount_encrypted FROM transactions LIMIT 10")
    rows = cur.fetchall()
    print("\n=== transactions table (amount_encrypted) ===")
    for r in rows:
        tid, uid, amt = r
        print(tid, "| user:", uid, "|", repr(amt)[:120])
    conn.close()

def try_decrypt():
    try:
        key = open(KEY_FILE, "rb").read()
        f = Fernet(key)
    except Exception as e:
        print("\nCould not load Fernet key:", e)
        return
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT id, amount_encrypted FROM transactions LIMIT 5")
    rows = cur.fetchall()
    print("\n=== decrypt sample ===")
    for r in rows:
        tid, token = r
        try:
            val = f.decrypt(token).decode()
        except Exception:
            val = "<decryption error>"
        print(tid, "|", val)
    conn.close()

if __name__ == "__main__":
    show_users()
    show_transactions()
    try_decrypt()
