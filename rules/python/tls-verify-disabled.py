# Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import ssl
import requests

def bad(url):
    # ruleid: shieldgate.python.tls-verify-disabled
    requests.get(url, verify=False)
    s = requests.Session()
    # ruleid: shieldgate.python.tls-verify-disabled
    s.verify = False
    # ruleid: shieldgate.python.tls-verify-disabled
    ctx = ssl._create_unverified_context()
    return ctx

def good(url):
    # ok: shieldgate.python.tls-verify-disabled
    requests.get(url, verify="/etc/ssl/certs/internal-ca.pem")
    # ok: shieldgate.python.tls-verify-disabled
    requests.get(url, timeout=5)
