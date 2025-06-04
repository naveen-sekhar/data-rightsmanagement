
import streamlit as st
from datetime import datetime
from io import BytesIO
import os, json, getpass, socket
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ======= Crypto Functions =======

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_pdf_with_kdf(pdf_bytes, password, expiry_datetime_str):
    identity = f"{getpass.getuser()}@{socket.gethostname()}"
    metadata = {
        "identity": identity,
        "expiry": expiry_datetime_str,
    }

    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    metadata_json = json.dumps(metadata).encode()
    combined = metadata_json + b"\n\n---PDF_START---\n\n" + pdf_bytes
    encrypted = aesgcm.encrypt(nonce, combined, None)

    final_data = salt + nonce + encrypted
    return final_data

def decrypt_pdf_with_kdf(encrypted_data, password):
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    encrypted = encrypted_data[28:]

    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)

    decrypted = aesgcm.decrypt(nonce, encrypted, None)
    metadata_part, pdf_data = decrypted.split(b"\n\n---PDF_START---\n\n", 1)
    metadata = json.loads(metadata_part.decode())

    identity = f"{getpass.getuser()}@{socket.gethostname()}"
    if identity != metadata["identity"]:
        raise ValueError("Access denied: Not the original creator.")

    expiry_time = datetime.strptime(metadata["expiry"], "%Y-%m-%dT%H:%M:%S")
    if datetime.now() > expiry_time:
        raise ValueError("File has expired.")

    return pdf_data

# ======= Admin Auth =======

def admin_auth():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    if st.session_state["authenticated"]:
        return True

    with st.expander("🔐 Admin Login", expanded=True):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if username == "admin" and password == "admin":
                st.session_state["authenticated"] = True
                st.success("Logged in as admin")
                return True
            else:
                st.error("Invalid credentials")
    return False

# ======= Streamlit App =======

st.set_page_config(page_title="OpenDRM - Secure PDF", layout="centered")

st.title("🔒 OpenDRM - Secure PDF Encryption & Decryption")

menu = st.sidebar.radio("Select Operation", ["Encrypt", "Decrypt"])

if admin_auth():
    if menu == "Encrypt":
        st.subheader("🔐 Encrypt PDF with Expiry")
        uploaded_file = st.file_uploader("Upload PDF", type=["pdf"])
        password = st.text_input("Set a password to encrypt", type="password")
        expiry_date = st.date_input("Set expiry date")
        expiry_time = st.time_input("Set expiry time")
        expiry_datetime = datetime.combine(expiry_date, expiry_time)

        if st.button("Encrypt PDF"):
            if uploaded_file and password:
                pdf_bytes = uploaded_file.read()
                encrypted_data = encrypt_pdf_with_kdf(
                    pdf_bytes, password, expiry_datetime.strftime("%Y-%m-%dT%H:%M:%S")
                )
                st.success("PDF encrypted successfully!")
                st.download_button("📥 Download Encrypted File", data=encrypted_data,
                                   file_name="encrypted_output.bin")
            else:
                st.error("Please upload a PDF and set password.")

    elif menu == "Decrypt":
        st.subheader("🔓 Decrypt PDF")
        encrypted_file = st.file_uploader("Upload Encrypted File", type=["bin"])
        password = st.text_input("Enter the password to decrypt", type="password")

        if st.button("Decrypt PDF"):
            if encrypted_file and password:
                try:
                    encrypted_data = encrypted_file.read()
                    decrypted_pdf = decrypt_pdf_with_kdf(encrypted_data, password)
                    st.success("Decryption successful!")
                    st.download_button("📥 Download Decrypted PDF", data=decrypted_pdf,
                                       file_name="decrypted_output.pdf")
                except Exception as e:
                    st.error(f"Failed to decrypt: {str(e)}")
            else:
                st.error("Please upload an encrypted file and enter the password.")
