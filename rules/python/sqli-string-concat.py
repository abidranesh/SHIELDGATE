# Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import sqlite3

def bad(conn, user_id, name):
    cur = conn.cursor()
    # ruleid: shieldgate.python.sqli-string-concat
    cur.execute("SELECT * FROM users WHERE id = " + user_id)
    # ruleid: shieldgate.python.sqli-string-concat
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: shieldgate.python.sqli-string-concat
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ruleid: shieldgate.python.sqli-string-concat
    cur.execute("SELECT * FROM t WHERE a = '" + name + "' AND b = 1")
    q = "DELETE FROM users WHERE id = {}".format(user_id)
    # ruleid: shieldgate.python.sqli-string-concat
    cur.execute(q)

def good(conn, user_id):
    cur = conn.cursor()
    # ok: shieldgate.python.sqli-string-concat
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    # ok: shieldgate.python.sqli-string-concat
    cur.execute("SELECT 1")
    # ok: shieldgate.python.sqli-string-concat
    cur.execute(f"SELECT 1")
