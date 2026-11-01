// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
async function bad(db, req) {
  // ruleid: shieldgate.js.sqli-string-concat
  await db.query("SELECT * FROM users WHERE id = " + req.params.id);
  // ruleid: shieldgate.js.sqli-string-concat
  await db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);
  const sql = "DELETE FROM sessions WHERE token = '" + req.cookies.t + "'";
  // ruleid: shieldgate.js.sqli-string-concat
  db.run(sql);
}

async function good(db, req) {
  // ok: shieldgate.js.sqli-string-concat
  await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  // ok: shieldgate.js.sqli-string-concat
  cache.get("user:" + req.params.id);
}
