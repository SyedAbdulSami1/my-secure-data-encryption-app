import streamlit as st
import json, os, time
import hashlib, base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# ------------ Constants ------------
DATA_FILE = "data.json"
LOCK_DURATION = 60  # in seconds

# ------------ Utility Functions ------------

# Load user data from file
def load_data():
    if not os.path.exists(DATA_FILE):
        return {"users": {}}
    with open(DATA_FILE, "r") as file:
        return json.load(file)

# Save user data to file
def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

# Generate Fernet key
def generate_fernet_key():
    return Fernet.generate_key()

# Secure Hash with PBKDF2
def pbkdf2_hash(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(salt).decode(), base64.b64encode(hash_bytes).decode()

# Verify password with PBKDF2
def verify_pbkdf2(password, salt, stored_hash):
    salt_bytes = base64.b64decode(salt)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, 100000)
    return base64.b64encode(hash_bytes).decode() == stored_hash

# Encryption/Decryption
def encrypt_data(fernet_key, plain_text):
    f = Fernet(fernet_key.encode())
    return f.encrypt(plain_text.encode()).decode()

def decrypt_data(fernet_key, encrypted_text):
    f = Fernet(fernet_key.encode())
    return f.decrypt(encrypted_text.encode()).decode()

# ------------ Session Initialization ------------

if "user" not in st.session_state:
    st.session_state.user = None

if "lock_time" not in st.session_state:
    st.session_state.lock_time = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# ------------ UI Starts Here ------------

st.title("🔐 Secure Data Encryption System")

#menu = ["Home", "Login", "Sign Up", "Store Data", "Retrieve Data", "Logout"]
#choice = st.sidebar.selectbox("Navigation", menu)
menu_options = ["Home"]

if "authenticated_user" not in st.session_state:
    menu_options += ["Login", "Sign Up"]
else:
    menu_options += ["Store Data", "Retrieve Data", "Logout"]

choice = st.sidebar.selectbox("Navigation", menu_options)

if "authenticated_user" in st.session_state:
    st.sidebar.markdown(f"👋 Welcome, **{st.session_state['authenticated_user']}**!")



data = load_data()

# ------------ Home ------------
if choice == "Home":
    st.subheader("🏡 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using your credentials.")

# ------------ Sign Up ------------
elif choice == "Sign Up":
    st.subheader("👤 Create New Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")

    if st.button("Sign Up"):
        if new_user in data["users"]:
            st.error("❌ Username already exists!")
        elif new_user and new_pass:
            salt, hashed = pbkdf2_hash(new_pass)
            fernet_key = generate_fernet_key().decode()
            data["users"][new_user] = {
                "password": {"salt": salt, "hash": hashed},
                "fernet_key": fernet_key,
                "data": {}
            }
            save_data(data)
            st.success("✅ Account created successfully! Please login.")
        else:
            st.warning("⚠️ Fill in all fields.")

# ------------ Login ------------
elif choice == "Login":
    st.subheader("🔐 Login to Your Account")
    user = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user_record = data["users"].get(user)

        if user_record and verify_pbkdf2(password, user_record["password"]["salt"], user_record["password"]["hash"]):
            st.session_state.user = user
            st.session_state.authenticated_user = user
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome back, {user}!")
            st.rerun()
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Incorrect credentials. Attempts remaining: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lock_time = time.time()
                st.warning("🚫 Too many failed attempts. Please wait 1 minute.")
                st.session_state.failed_attempts = 0

# ------------ Lockout Logic ------------
if st.session_state.lock_time:
    if time.time() - st.session_state.lock_time < LOCK_DURATION:
        remaining = int(LOCK_DURATION - (time.time() - st.session_state.lock_time))
        st.warning(f"⏳ Locked out for {remaining} seconds due to failed login attempts.")
        st.stop()
    else:
        st.session_state.lock_time = None

# ------------ Store Data ------------
elif choice == "Store Data":
    if not st.session_state.user:
        st.warning("⚠️ Please login first.")
        st.stop()

    st.subheader("💾 Store Encrypted Data")
    plain_text = st.text_area("Enter Data to Encrypt")
    passkey = st.text_input("Enter Encryption Passkey", type="password")

    if st.button("Encrypt and Save"):
        if plain_text and passkey:
            salt, hashed_passkey = pbkdf2_hash(passkey)
            user = st.session_state.user
            fernet_key = data["users"][user]["fernet_key"]
            encrypted = encrypt_data(fernet_key, plain_text)
            data["users"][user]["data"][encrypted] = {
                "encrypted_text": encrypted,
                "passkey": {"salt": salt, "hash": hashed_passkey}
            }
            save_data(data)
            st.success("✅ Data encrypted and saved successfully!")
            st.code(encrypted, language="text")
        else:
            st.error("❌ Please enter both fields.")

# ------------ Retrieve Data ------------
elif choice == "Retrieve Data":
    if not st.session_state.user:
        st.warning("⚠️ Please login first.")
        st.stop()

    st.subheader("🔍 Retrieve Your Data")
    encrypted_input = st.text_area("Enter Encrypted Text")
    passkey_input = st.text_input("Enter Your Passkey", type="password")

    if st.button("Decrypt"):
        user = st.session_state.user
        user_data = data["users"][user]["data"]

        if encrypted_input in user_data:
            stored = user_data[encrypted_input]
            if verify_pbkdf2(passkey_input, stored["passkey"]["salt"], stored["passkey"]["hash"]):
                fernet_key = data["users"][user]["fernet_key"]
                decrypted = decrypt_data(fernet_key, encrypted_input)
                st.success("✅ Data Decrypted:")
                st.code(decrypted)
            else:
                st.error("❌ Incorrect passkey.")
        else:
            st.error("⚠️ Data not found.")

# ------------ Logout ------------
elif choice == "Logout":
    st.session_state.user = None
    st.success("👋 Logged out successfully!")

if choice == "Logout":
    st.session_state.pop("authenticated_user", None)
    st.success("Logged out successfully!")
    st.rerun()
