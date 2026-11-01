// Shieldgate rule test fixture -- intentionally vulnerable code, never run.
const axios = require("axios");

app.get("/preview", async (req, res) => {
  // ruleid: shieldgate.js.ssrf
  const r = await axios.get(req.query.url);
  res.send(r.data);
});

app.post("/image", async (req, res) => {
  const src = req.body.imageUrl;
  // ruleid: shieldgate.js.ssrf
  const img = await fetch(src);
  res.send(await img.text());
});

app.get("/weather", async (req, res) => {
  // ok: shieldgate.js.ssrf
  const r = await axios.get("https://api.weather.example/v1", { params: { city: req.query.city } });
  res.send(r.data);
});
