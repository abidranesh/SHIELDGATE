# Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import hashlib
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def bad(password, key, data):
    # ruleid: shieldgate.python.weak-password-hash
    h = hashlib.md5(password.encode()).hexdigest()
    # ruleid: shieldgate.python.weak-password-hash
    h2 = hashlib.sha1(user_password).hexdigest()
    # ruleid: shieldgate.python.ecb-mode
    c = AES.new(key, AES.MODE_ECB)
    # ruleid: shieldgate.python.ecb-mode
    c2 = Cipher(algorithms.AES(key), modes.ECB())
    return h, h2, c, c2

def good(password, data, key, iv):
    # ok: shieldgate.python.weak-password-hash
    etag = hashlib.md5(data).hexdigest()
    # ok: shieldgate.python.weak-password-hash
    h = hashlib.scrypt(password.encode(), salt=b"s", n=2**14, r=8, p=1)
    # ok: shieldgate.python.ecb-mode
    c = AES.new(key, AES.MODE_GCM)
    return etag, h, c
