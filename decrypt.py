from cryptography.fernet import Fernet
import sqlite3

key = open('fernet.key','rb').read()
f = Fernet(key)
db = sqlite3.connect('easy_cash.db')
cur = db.cursor()
cur.execute("SELECT id, amount_encrypted FROM transactions")
for id, token in cur.fetchall():
    try:
        print(id, f.decrypt(token).decode())
    except:
        print(id, "<decryption error>")
