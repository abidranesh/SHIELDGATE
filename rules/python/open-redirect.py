# Shieldgate rule test fixture -- intentionally vulnerable code, never run.
from flask import Flask, redirect, request, url_for

app = Flask(__name__)

@app.route("/login")
def login():
    nxt = request.args.get("next")
    # ruleid: shieldgate.python.open-redirect
    return redirect(nxt)

@app.route("/logout")
def logout():
    # ok: shieldgate.python.open-redirect
    return redirect(url_for("index"))

@app.route("/back")
def back():
    # ok: shieldgate.python.open-redirect
    return redirect(request.referrer or url_for("index"))
