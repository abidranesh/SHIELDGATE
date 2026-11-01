# Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import os
from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)

@app.route("/download")
def download():
    name = request.args.get("file")
    # ruleid: shieldgate.python.path-traversal
    return send_file("/srv/uploads/" + name)

@app.route("/read")
def read():
    # ruleid: shieldgate.python.path-traversal
    with open(os.path.join("/srv/data", request.args["p"])) as fh:
        return fh.read()

@app.route("/safe")
def safe():
    name = secure_filename(request.args.get("file"))
    # ok: shieldgate.python.path-traversal
    return send_file(os.path.join("/srv/uploads", name))
