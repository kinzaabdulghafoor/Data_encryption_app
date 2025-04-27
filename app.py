import streamlit as st
from cryptography.fernet import Fernet

st.set_page_config(page_title="🔐 Secure Data Encryption App", layout="centered")
st.title("🔐 Secure Data Encryption System")

# Use a fixed key for the demo (In real scenarios, store the key securely)
key = b'J5Wz0Gg5JzGb_1qzH-kwA2HSPPAtYXGo1H4G6U_v5h8='  # Example key (make sure to use your own key in practice)
cipher = Fernet(key)

# User input
option = st.selectbox("Choose action:", ["Encrypt", "Decrypt"])
text = st.text_area("Enter your text:")
st.write("Note: This is a basic demo. Real systems use secure key storage.")

# Encrypt
if option == "Encrypt":
    if st.button("Encrypt Text"):
        if text:
            encrypted = cipher.encrypt(text.encode())
            st.code(encrypted.decode(), language="plaintext")
        else:
            st.warning("Please enter some text to encrypt.")

# Decrypt
elif option == "Decrypt":
    if st.button("Decrypt Text"):
        if text:
            try:
                decrypted = cipher.decrypt(text.encode())
                st.code(decrypted.decode(), language="plaintext")
            except Exception as e:
                st.error(f"Invalid encrypted text or key. Error: {str(e)}")
        else:
            st.warning("Please enter encrypted text to decrypt.")
