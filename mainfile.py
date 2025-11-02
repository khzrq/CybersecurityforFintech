
import streamlit as st
import sqlite3
import bcrypt
from datetime import datetime, timedelta
import html
import os
from cryptography.fernet import Fernet

DB_FILE = "easy_cash.db"
KEY_FILE = "fernet.key"
ALLOWED_EXT = {"png", "jpg", "jpeg", "pdf", "txt"}
PRIMARY_GREEN = "#1e8f4a"
BG_WHITE = "#ffffff"


def get_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

FERNET = Fernet(get_key())

def init_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE,
                 password_hash BLOB,
                 email TEXT,
                 created_at TEXT,
                 locked_until TEXT DEFAULT NULL,
                 failed_attempts INTEGER DEFAULT 0)""")
    c.execute("""CREATE TABLE IF NOT EXISTS transactions(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 amount_encrypted BLOB,
                 note TEXT,
                 created_at TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS auditlog(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user TEXT,
                 action TEXT,
                 ts TEXT)""")
    conn.commit()
    return conn

DB = init_db()

def run_query(query, params=(), fetch=False):
    try:
        cur = DB.cursor()
        cur.execute(query, params)
        if fetch:
            res = cur.fetchall()
        else:
            res = None
        DB.commit()
        return res
    except Exception as e:
        log_action("system", f"db_error: {str(e)[:120]}")
        return None

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def check_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except Exception:
        return False

def encrypt_amount(amount: str) -> bytes:
    return FERNET.encrypt(amount.encode("utf-8"))

def decrypt_amount(token: bytes) -> str:
    try:
        return FERNET.decrypt(token).decode("utf-8")
    except Exception:
        return "<decryption error>"

def log_action(user: str, action: str):
    ts = datetime.utcnow().isoformat()
    run_query("INSERT INTO auditlog(user, action, ts) VALUES(?,?,?)", (user, action, ts))

# ---------- Password Policy ----------

def validate_password_rules(pw: str) -> (bool, str):
    if len(pw) < 8:
        return False, "Password must be at least 8 characters."
    if not any(c.isdigit() for c in pw):
        return False, "Password must include at least one digit."
    if not any(not c.isalnum() for c in pw):
        return False, "Password must include at least one symbol."
    return True, "OK"

# ---------- UI ----------

def local_css():
    st.markdown(f"""
    <style>
    .stApp {{background-color: {BG_WHITE};}}
    .big-title {{font-size:28px; color: {PRIMARY_GREEN}; font-weight:600}}
    .stButton>button {{background-color: {PRIMARY_GREEN}; color: white;}}
    </style>
    """, unsafe_allow_html=True)

def app_header():
    st.markdown("<div class='big-title'>Easy Cash — Lending Platform</div>", unsafe_allow_html=True)
    st.markdown("<div>Secure lending demo for manual cybersecurity testing</div>", unsafe_allow_html=True)

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.login_time = None

st.set_page_config(page_title="Easy Cash", layout="centered")
local_css()
app_header()

menu = st.sidebar.selectbox("Navigation", ["Home", "Register", "Login", "Dashboard", "Audit Log"])

# ---------- Register ----------
if menu == "Register":
    st.subheader("Create an account")
    with st.form("reg", clear_on_submit=False):
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")
    if submitted:
        if not username or not password:
            st.error("Username and password required.")
        else:
            ok, msg = validate_password_rules(password)
            if not ok:
                st.error(msg)
            elif password != confirm:
                st.error("Passwords do not match.")
            else:
                try:
                    phash = hash_password(password)
                    run_query("INSERT INTO users(username, password_hash, email, created_at) VALUES(?,?,?,?)",
                              (username, phash, email, datetime.utcnow().isoformat()))
                    st.success("Account created — please login.")
                    log_action(username, "register")
                except Exception:
                    st.error("Could not create account (username may already exist).")

# ---------- Login ----------
elif menu == "Login":
    st.subheader("Login to Easy Cash")
    with st.form("login"):
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pw")
        submitted = st.form_submit_button("Login")
    if submitted:
        if not username or not password:
            st.error("Provide both username and password.")
        else:
            r = run_query("SELECT id, password_hash, failed_attempts, locked_until FROM users WHERE username=?",
                          (username,), fetch=True)
            if not r:
                st.error("Invalid credentials.")
            else:
                uid, phash, failed, locked_until = r[0]
                if locked_until:
                    try:
                        until = datetime.fromisoformat(locked_until)
                        if datetime.utcnow() < until:
                            st.error(f"Account locked until {until.isoformat()} UTC due to failed attempts.")
                            log_action(username, "login_attempt_locked")
                            st.stop()
                    except Exception:
                        pass
                if check_password(password, phash):
                    st.success("Login successful.")
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.login_time = datetime.utcnow()
                    run_query("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
                    log_action(username, "login")
                else:
                    failed = (failed or 0) + 1
                    locked_until_ts = None
                    if failed >= 5:
                        locked_until_ts = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
                        run_query("UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?", (failed, locked_until_ts, username))
                        st.error("Account locked due to too many failed attempts. Try again later.")
                    else:
                        run_query("UPDATE users SET failed_attempts=? WHERE username=?", (failed, username))
                        st.error(f"Invalid credentials. Attempt {failed}/5")
                    log_action(username, f"failed_login_{failed}")

# ---------- Dashboard ----------
elif menu == "Dashboard":
    if not st.session_state.logged_in:
        st.warning("Please login first.")
        st.stop()

    st.sidebar.write(f"Logged in as: {st.session_state.username}")
    if st.sidebar.button("Logout"):
        log_action(st.session_state.username, "logout")
        st.session_state.logged_in = False
        st.session_state.username = None
        st.experimental_rerun()

    # ✅ Session Expiry set to 5 minutes for testing
    if st.session_state.login_time and datetime.utcnow() - st.session_state.login_time > timedelta(minutes=5):
        st.warning("Session expired due to inactivity.")
        log_action(st.session_state.username, "session_expired")
        st.session_state.logged_in = False
        st.session_state.username = None
        st.experimental_rerun()

    st.header("Dashboard — Create Loan Transaction")
    st.markdown("Use the form below to create a mock loan transaction. Amount is encrypted in DB.")

    with st.form("tx"):
        amount = st.text_input("Loan Amount (numeric)")
        note = st.text_area("Purpose / Note")
        uploaded = st.file_uploader("Optional: upload supporting doc (png/jpg/pdf/txt)")
        submit_tx = st.form_submit_button("Submit Transaction")

    if submit_tx:
        try:
            amt_val = float(amount)
            if amt_val <= 0:
                st.error("Amount must be positive.")
            else:
                if len(note) > 500:
                    st.error("Note too long (max 500 characters).")
                    log_action(st.session_state.username, "input_length_violation")
                    st.stop()

                if uploaded:
                    fname = uploaded.name
                    ext = fname.split('.')[-1].lower()
                    if ext not in ALLOWED_EXT:
                        st.error("File type not allowed.")
                        log_action(st.session_state.username, "upload_rejected")
                    elif uploaded.size > 2_000_000:
                        st.error("File too large (max 2MB).")
                        log_action(st.session_state.username, "upload_rejected_size")
                    else:
                        os.makedirs("uploads", exist_ok=True)
                        upath = os.path.join("uploads", f"{datetime.utcnow().timestamp()}_{fname}")
                        with open(upath, "wb") as f:
                            f.write(uploaded.getbuffer())
                        log_action(st.session_state.username, f"upload_saved:{fname}")

                token = encrypt_amount(str(amt_val))
                safe_note = html.escape(note)
                uid = run_query("SELECT id FROM users WHERE username=?", (st.session_state.username,), fetch=True)[0][0]
                run_query("INSERT INTO transactions(user_id, amount_encrypted, note, created_at) VALUES(?,?,?,?)",
                          (uid, token, safe_note, datetime.utcnow().isoformat()))
                st.success("Transaction recorded.")
                log_action(st.session_state.username, f"create_tx:{amt_val}")
        except ValueError:
            st.error("Invalid amount (must be numeric).")

    st.subheader("Your Transactions")
    try:
        uid = run_query("SELECT id FROM users WHERE username=?", (st.session_state.username,), fetch=True)[0][0]
        rows = run_query("SELECT id, amount_encrypted, note, created_at FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 20",
                         (uid,), fetch=True)
        if rows:
            for r in rows:
                tid, amt_enc, note, ts = r
                amt = decrypt_amount(amt_enc) if amt_enc else ""
                st.markdown(f"**ID:** {tid} — **Amount:** {html.escape(str(amt))} — **When:** {ts}")
                st.markdown(f"Note: {note}")
        else:
            st.info("No transactions yet.")
    except Exception:
        st.info("No transactions yet or error fetching them.")

    st.markdown("---")
    st.subheader("Profile")
    try:
        rec = run_query("SELECT email FROM users WHERE username=?", (st.session_state.username,), fetch=True)
        curr_email = rec[0][0] if rec else ""
        new_email = st.text_input("Email", value=curr_email)
        if st.button("Update Profile"):
            if not new_email or "@" not in new_email:
                st.error("Enter a valid email.")
            else:
                run_query("UPDATE users SET email=? WHERE username=?", (new_email, st.session_state.username))
                st.success("Profile updated.")
                log_action(st.session_state.username, "update_profile")
    except Exception:
        st.error("Error loading profile.")

# ---------- Audit Log ----------
elif menu == "Audit Log":
    st.header("Audit / Activity Log")
    logs = run_query("SELECT user, action, ts FROM auditlog ORDER BY id DESC LIMIT 200", fetch=True) or []
    for l in logs:
        st.write(f"{l[2]} — {html.escape(l[0] or 'system')} — {html.escape(l[1])}")

# ---------- Home ----------
else:
    st.title("Welcome to Easy Cash")
    st.markdown("Easy Cash is a demo lending platform built to perform manual cybersecurity tests. Use the sidebar to navigate.")
    st.markdown("**Theme:** Green & White — secure lending demo")
    st.markdown("---")
    st.subheader("Quick testing tips")
    st.markdown("- Try SQL injection payloads in login (app uses parameterized queries).\n- Try XSS strings in the note field (escaped).\n- Attempt to upload disallowed file types.\n- Try repeated failed logins to trigger lockout.")
