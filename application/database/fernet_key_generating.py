#run this to generate new random key for AES-256 encryption
import os
key = os.urandom(32)
print(key.hex())