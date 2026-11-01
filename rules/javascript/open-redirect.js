// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
app.get("/login", (req, res) => {
  // ruleid: shieldgate.js.open-redirect
  res.redirect(req.query.next);
});

app.get("/go", (req, res) => {
  const target = req.query.to;
  // ruleid: shieldgate.js.open-redirect
  res.redirect(302, target);
});

app.get("/home", (req, res) => {
  // ok: shieldgate.js.open-redirect
  res.redirect("/dashboard");
});
