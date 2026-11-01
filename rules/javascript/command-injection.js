// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
const { exec, execFile } = require("child_process");
const cp = require("child_process");

app.get("/ping", (req, res) => {
  // ruleid: shieldgate.js.child-process-exec-injection
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.post("/convert", (req, res) => {
  const file = req.body.file;
  // ruleid: shieldgate.js.child-process-exec-injection
  cp.execSync(`convert ${file} out.png`);
});

app.get("/ok", (req, res) => {
  // ok: shieldgate.js.child-process-exec-injection
  execFile("ping", ["-c", "1", req.query.host]);
  // ok: shieldgate.js.child-process-exec-injection
  exec("uptime");
});
