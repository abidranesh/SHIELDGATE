// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
const jwt = require("jsonwebtoken");
const SECRET = "my-dev-secret";

function bad(user, token) {
  // ruleid: shieldgate.js.hardcoded-jwt-secret
  const t = jwt.sign({ sub: user.id }, "shhhhh");
  // ruleid: shieldgate.js.hardcoded-jwt-secret
  jwt.verify(token, SECRET);
  return t;
}

function good(user) {
  // ok: shieldgate.js.hardcoded-jwt-secret
  return jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
}
