from cryptography.fernet import Fernet
import os

# Generate a key and instantiate a Fernet instance
#key = Fernet.generate_key()
key = os.getenv('FERNET_KEY')
cipher_suite = Fernet(key)

def encrypt_password(password):
    """Encrypts a password using Fernet symmetric encryption."""
    return cipher_suite.encrypt(password.encode('utf-8'))


def decrypt_password(encrypted_password):
    """Decrypts a password using Fernet symmetric encryption."""
    return cipher_suite.decrypt(encrypted_password).decode('utf-8')


def decrypt_passwords(passwords):
    decrypted_passwords = []
    for p in passwords:
        try:
            decrypted_password = {
                'site_name': p.site_name,
                'site_url': p.site_url,
                'username': p.username,
                'password': decrypt_password(p.password),
                'password_id': p.password_id
            }
            decrypted_passwords.append(decrypted_password)
        except Exception as e:
            # Log the error or handle specific decryption errors individually
            print(f"Failed to decrypt password for {p.username}: {str(e)}")
            decrypted_password = {
                'site_name': p.site_name,
                'site_url': p.site_url,
                'username': p.username,
                'password': 'Error decrypting password'
            }
            decrypted_passwords.append(decrypted_password)
    return decrypted_passwords


