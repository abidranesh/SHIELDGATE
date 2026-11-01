# Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import os
import jwt
from flask import Flask

app = Flask(__name__)
# ruleid: shieldgate.python.hardcoded-jwt-secret
app.config["JWT_SECRET_KEY"] = "super-secret-dev-key"

def bad(user):
    # ruleid: shieldgate.python.hardcoded-jwt-secret
    return jwt.encode({"sub": user}, "s3cr3t", algorithm="HS256")

def bad2(token):
    key = "hunter2-jwt"
    # ruleid: shieldgate.python.hardcoded-jwt-secret
    return jwt.decode(token, key, algorithms=["HS256"])

def good(user):
    # ok: shieldgate.python.hardcoded-jwt-secret
    return jwt.encode({"sub": user}, os.environ["JWT_SECRET"], algorithm="HS256")
