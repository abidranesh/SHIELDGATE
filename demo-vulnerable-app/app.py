"""Shieldgate demo app: a tiny notes service.

This file is the clean starting point. The demo PR (see README.md) replaces it with
pr-steps/1-vulnerable/app.py -- an INTENTIONALLY VULNERABLE version -- and then fixes
it in a second commit with pr-steps/2-fixed/app.py. Never deploy the vulnerable version.
"""
import os
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB = os.environ.get("NOTES_DB", "notes.db")


def db():
    return sqlite3.connect(DB)


@app.get("/notes")
def list_notes():
    owner = request.args.get("owner", "")
    rows = db().execute("SELECT id, body FROM notes WHERE owner = ?", (owner,)).fetchall()
    return jsonify([{"id": r[0], "body": r[1]} for r in rows])


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
