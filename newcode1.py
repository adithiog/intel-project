from cryptography.fernet import Fernet
import os

# To Generate a key for encryption and decryption
def generate_key():
    return Fernet.generate_key()

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
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# To Decrypt a password
def decrypt_password(encrypted_password):
    key = load_key()
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# To Decrypt a password
def decrypt_password(encrypted_password):
    key = load_key()
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password

# Example usage
password = "user_password123"
encrypted_password = encrypt_password(password)
print("Encrypted:", encrypted_password)

decrypted_password = decrypt_password(encrypted_password)
print("Decrypted:", decrypted_password)