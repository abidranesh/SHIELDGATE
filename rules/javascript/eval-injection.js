// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
app.post("/calc", (req, res) => {
  // ruleid: shieldgate.js.eval-injection
  res.send(String(eval(req.body.expr)));
});

app.post("/parse", (req, res) => {
  // ok: shieldgate.js.eval-injection
  res.send(JSON.parse(req.body.data));
});
