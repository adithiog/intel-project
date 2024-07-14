from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# To Generate a key for encryption and decryption
def generate_key():
    return os.urandom(32)  # 256-bit

# To Save the key securely, possibly using environment variables or a secure vault in production
key = generate_key()
key_file = 'encryption_key.key'

with open(key_file, 'wb') as f:
    f.write(key)

# To Load the key from file
def load_key():
    return open(key_file, 'rb').read()

# To Encrypt a password
def encrypt_password(password):
    key = load_key()
    backend = default_backend()
    iv = os.urandom(16)  # Generate a random IV for encryption
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()
    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_password
# To Decrypt a password
def decrypt_password(encrypted_password):
    key = load_key()
    backend = default_backend()
    iv = encrypted_password[:16]  # Extract the IV from the encrypted data
    encrypted_data = encrypted_password[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

# Example usage
password = "user_password123"
encrypted_password = encrypt_password(password)
print("Encrypted:", encrypted_password)

decrypted_password = decrypt_password(encrypted_password)
print("Decrypted:", decrypted_password)