from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

#I stored this AES key securely as system environment variable
static_key = os.getenv('AES_256_KEY')
if static_key is None:
    raise ValueError("AES_256_KEY is not set in the environment variables")


#For testing program you can use this already generated key below
#so you don't need to set environment variable. !THIS IS NOT SECURE WAY!

#key = '06b4ad939051d0c46892f7a753fab6c2fcbb2622cef82acbade161df461accca'


def generate_key(password: str, salt: bytes, iterations: int = 100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_password(message: str, password: str = static_key):
    salt = os.urandom(16)
    password_key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(password_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(message.encode()) + encryptor.finalize()
    return urlsafe_b64encode(salt + iv + encrypted_data).decode('utf-8')


def decrypt_password(token: str, password: str = static_key):
    token = urlsafe_b64decode(token.encode('utf-8'))
    salt = token[:16]
    iv = token[16:32]
    data = token[32:]
    password_key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(password_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return decrypted_data.decode('utf-8')


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
            print(f"Failed to decrypt password for {p.username}: {str(e)}")
            decrypted_password = {
                'site_name': p.site_name,
                'site_url': p.site_url,
                'username': p.username,
                'password': 'Error decrypting password'
            }
            decrypted_passwords.append(decrypted_password)
    return decrypted_passwords
