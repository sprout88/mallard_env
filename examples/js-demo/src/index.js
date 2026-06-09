require("dotenv").config();

const { suspiciousExfil, likelyBenignInternalCall } = require("./flows");

async function main() {
  await suspiciousExfil();
  await likelyBenignInternalCall();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
