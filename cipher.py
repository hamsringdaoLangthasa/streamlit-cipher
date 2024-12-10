import streamlit as st
import utils

st.title("🔐 Cipher Stream - Secure Your Secrets")
st.header("A Simple Tool for Encryption and Decryption")

seed = st.text_input(label="Seed", placeholder="Enter the seed for encryption/decryption", type="password")

encrypt, decrypt, about, help = st.tabs(["Encrypt", "Decrypt", "About", "Help"])

with encrypt:
    secret = st.text_input(label="Secret", placeholder="Enter the secret to encrypt", type="password")
    if st.button("Generate Encrypted Value"):
        if secret and seed:
            encrypted = utils.encrypt(secret, seed)
            st.write(encrypted)
        else:
            st.error("Please provide both seed and secret.")

with decrypt:
    encrypted_str = st.text_area(label="Encrypted Data", placeholder="Enter the encrypted data to decrypt")
    if st.button("Generate Decrypted Value"):
        if encrypted_str and seed:
            try:
                encrypted_object = utils.convert_str_to_json(encrypted_str)
                decrypted = utils.decrypt(encrypted_object, seed)
                st.code(decrypted, language="text")
            except Exception as e:
                st.error(f"Decryption failed: {e}", icon="🚨")
        else:
            st.error("Please provide a valid seed and encrypted value.")

with about:
    st.subheader("About Cipher Stream")
    st.markdown("""
    Cipher Stream is a simple tool for securely encrypting and decrypting sensitive information. 
    It uses a **seed** (or key) to ensure your data remains private and secure.

    ### Features
    - Encrypt any text using a seed phrase.
    - Decrypt previously encrypted text using the same seed phrase.
    - Provides a simple, user-friendly interface for security enthusiasts.

    ### How It Works
    1. Enter a **seed** (encryption key) and a **secret/encrypted data** (the text to encrypt or decrypt).
    2. Click the appropriate button in the **Encrypt** or **Decrypt** tab.
    3. View the encrypted or decrypted result in real-time.
    """)

with help:
    st.subheader("Help")
    st.markdown("""
    **How to Use the Cipher Tool**
    - Navigate to the **Encrypt** tab to encrypt text:
        1. Enter a **seed** (e.g., a passphrase or keyword).
        2. Enter the **secret** you want to encrypt.
        3. Click the **Generate Encrypted Value** button.
    - Navigate to the **Decrypt** tab to decrypt text:
        1. Enter the same **seed** you used for encryption.
        2. Enter the **encrypted data** you want to encrypt.
        3. Click the **Generate Decrypted Value** button.
        4. The decrypted text will be displayed.
        
    **Tips for Better Security**
    - Use a strong and unique **seed**.
    - Keep your seed private and do not share it with others.
    - Store your encrypted data securely.

    **Troubleshooting**
    - Ensure you are using the same seed for decryption as was used for encryption.
    - If decryption fails, verify the encrypted text and seed are correct.
    """)