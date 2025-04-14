import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Now Generate a key (This should be stored securely in production)
KEY = Fernet.generate_key()
chiper = Fernet(KEY)

# In memory Data Storage 
stored_data = {} #{"user_data":{"encrypted_text":"xyz", "passkey": "hashed"}}
failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    return chiper.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return chiper.decrypt(encrypted_text.encode()).decode()
        
    failed_attempts += 1 
    return None

# Streamlit UI
st.title("🔐Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏡Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
elif choice == "Store Data":
    st.subheader("🚀Store Data Securely")
    user_data = st.text_area("Enter Data")
    passkey = st.text_input("Enter Passkey:", type= "password")

    if st.button("Encrypt and Save"):
        if user_data and passkey:
            hash_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hash_passkey}
            st.success("💪Data Stored Securely!")
        else:
            st.error("❌Please enter both data and passkey.")
    
elif choice == "Retrieve Data":
    st.subheader("🔍Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data: ")
    passkey = st.text_input ("Enter Passskey", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
        
            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")

                if failed_attempts > 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")
elif choice == "Login":
    st.subheader("Reauthorized Required🔐")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "sami123":
            global failed_attempts
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
