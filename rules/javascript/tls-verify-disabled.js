// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
const https = require("https");

// ruleid: shieldgate.js.tls-verify-disabled
const agent = new https.Agent({ rejectUnauthorized: false });
// ruleid: shieldgate.js.tls-verify-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// ok: shieldgate.js.tls-verify-disabled
const good = new https.Agent({ rejectUnauthorized: true, ca: caPem });
