"""Shieldgate demo app -- INTENTIONALLY VULNERABLE (demo PR, commit 1). Never deploy."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, jsonify, redirect, request

app = Flask(__name__)
DB = os.environ.get("NOTES_DB", "notes.db")
JWT_SECRET = "notes-demo-signing-key"
# Fake credential planted for the demo; it is not a real key.
PAYMENTS_API_KEY = "q8Zt3VbN6mKp2XwR9sLd4HfJ7cYg"


def db():
    return sqlite3.connect(DB)


@app.get("/notes")
def list_notes():
    owner = request.args.get("owner", "")
    rows = db().execute("SELECT id, body FROM notes WHERE owner = '" + owner + "'").fetchall()
    return jsonify([{"id": r[0], "body": r[1]} for r in rows])


@app.post("/login")
def login():
    pw_hash = hashlib.md5(request.form["password"].encode()).hexdigest()
    token = jwt.encode({"sub": request.form["user"], "pw": pw_hash}, JWT_SECRET, algorithm="HS256")
    return redirect(request.args.get("next", "/") + "?t=" + token)


@app.get("/export")
def export():
    fmt = request.args.get("fmt", "csv")
    return subprocess.check_output(f"sqlite3 -{fmt} {DB} 'select * from notes'", shell=True)


@app.post("/import")
def import_notes():
    notes = pickle.loads(request.data)
    return jsonify(count=len(notes))


@app.post("/import-yaml")
def import_yaml():
    return jsonify(yaml.load(request.data))


@app.get("/preview")
def preview():
    return requests.get(request.args["url"], timeout=5, verify=False).text


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
