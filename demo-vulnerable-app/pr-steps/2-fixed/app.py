"""Shieldgate demo app -- demo PR, commit 2: every Shieldgate finding from commit 1 fixed."""
import json
import os
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, abort, jsonify, redirect, request, url_for
from werkzeug.security import generate_password_hash

app = Flask(__name__)
DB = os.environ.get("NOTES_DB", "notes.db")
JWT_SECRET = os.environ["JWT_SECRET"]
PAYMENTS_API_KEY = os.environ.get("PAYMENTS_API_KEY", "")
PREVIEW_PAGES = {"docs": "https://docs.example.com/", "status": "https://status.example.com/"}
EXPORT_FORMATS = {"csv", "json", "html"}


def db():
    return sqlite3.connect(DB)


@app.get("/notes")
def list_notes():
    owner = request.args.get("owner", "")
    rows = db().execute("SELECT id, body FROM notes WHERE owner = ?", (owner,)).fetchall()
    return jsonify([{"id": r[0], "body": r[1]} for r in rows])


@app.post("/login")
def login():
    pw_hash = generate_password_hash(request.form["password"])
    token = jwt.encode({"sub": request.form["user"], "pw": pw_hash}, JWT_SECRET, algorithm="HS256")
    return redirect(url_for("list_notes", t=token))


@app.get("/export")
def export():
    fmt = request.args.get("fmt", "csv")
    if fmt not in EXPORT_FORMATS:
        abort(400)
    return subprocess.check_output(["sqlite3", f"-{fmt}", DB, "select * from notes"])


@app.post("/import")
def import_notes():
    notes = json.loads(request.data)
    return jsonify(count=len(notes))


@app.post("/import-yaml")
def import_yaml():
    return jsonify(yaml.safe_load(request.data))


@app.get("/preview")
def preview():
    # callers pick a page by key; the server only ever fetches URLs it owns
    page = request.args.get("page", "")
    if page not in PREVIEW_PAGES:
        abort(400)
    return requests.get(PREVIEW_PAGES[page], timeout=5, allow_redirects=False).text


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
