from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import json

def encrypt(input_text: str, seedphrase: str) -> dict:
    """Encrypt the input text using the seedphrase."""
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(seedphrase, salt)
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Add padding to the input text
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(input_text.encode()) + padder.finalize()
    
    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "cipher_text": base64.b64encode(encrypted_data).decode()
    }

def derive_key(seedphrase: str, salt: bytes) -> bytes:
    """Derive a key from the seedphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(seedphrase.encode())

def decrypt(encrypted_data: dict, seedphrase: str) -> str:
    """Decrypt the encrypted data using the seedphrase."""
    salt = base64.b64decode(encrypted_data["salt"])
    iv = base64.b64decode(encrypted_data["iv"])
    ciphertext = base64.b64decode(encrypted_data["cipher_text"])
    key = derive_key(seedphrase, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode()
    except ValueError:
        return "Decryption failed. Incorrect seedphrase or corrupted data."
    
def convert_str_to_json(json_string):
    try:
        json_obj = json.loads(json_string)
        return json_obj
    except json.JSONDecodeError:
        raise ValueError("Invalid encrypted data.")