// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
const crypto = require("crypto");

function bad(password, key) {
  // ruleid: shieldgate.js.weak-password-hash
  const h = crypto.createHash("md5").update(password).digest("hex");
  // ruleid: shieldgate.js.ecb-or-des-cipher
  const c = crypto.createCipheriv("aes-128-ecb", key, null);
  return [h, c];
}

function good(fileBuf, key, iv) {
  // ok: shieldgate.js.weak-password-hash
  const etag = crypto.createHash("md5").update(fileBuf).digest("hex");
  // ok: shieldgate.js.ecb-or-des-cipher
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  return [etag, c];
}
