#encryption
import os 
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def gen_key(password,salt):
    if isinstance(salt,str):
        salt = salt.encode()
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=20000,
    )
    #gen a key from the password
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def setup_fernet(key):
    return Fernet(key)


def encrypt(f,message):
    # be encoded to byte string before encryption
    token = f.encrypt(message.encode())
    return token

def decrypt(f,token):
    message = f.decrypt(token.decode)
    return message

