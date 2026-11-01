# Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import os
from flask import Flask

app = Flask(__name__)

# ruleid: shieldgate.python.django-debug-true
DEBUG = True

if __name__ == "__main__":
    # ruleid: shieldgate.python.flask-debug-true
    app.run(host="0.0.0.0", debug=True)
    # ok: shieldgate.python.flask-debug-true
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
