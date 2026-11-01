// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
const fs = require("fs");
const path = require("path");

app.get("/file", (req, res) => {
  // ruleid: shieldgate.js.path-traversal
  fs.readFile("/srv/files/" + req.query.name, (e, d) => res.send(d));
});

app.get("/dl", (req, res) => {
  const p = path.join(__dirname, "uploads", req.params.file);
  // ruleid: shieldgate.js.path-traversal
  res.sendFile(p);
});

app.get("/safe", (req, res) => {
  const name = path.basename(req.query.name);
  // ok: shieldgate.js.path-traversal
  res.sendFile(name, { root: "/srv/files" });
});
