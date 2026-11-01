# Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # ruleid: shieldgate.python.ssrf-requests
    return requests.get(url, timeout=5).text

@app.route("/hook", methods=["POST"])
def hook():
    target = request.get_json()["callback"]
    # ruleid: shieldgate.python.ssrf-requests
    requests.post(target, json={"ok": True})
    return "ok"

@app.route("/static-fetch")
def static_fetch():
    page = request.args.get("page")
    # ok: shieldgate.python.ssrf-requests
    return requests.get("https://api.example.com/items", params={"page": page}).text
