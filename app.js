// app.js (ESM)
import express from "express";
import crypto from "crypto";

const app = express();
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "changeme-verify-token";
const APP_SECRET = process.env.APP_SECRET || "";
const PORT = process.env.PORT || 3000;

app.use(express.raw({ type: "*/*", limit: "2mb" }));

function validateSignature(req) {
  if (!APP_SECRET) return true;
  const signature = req.header("X-Hub-Signature-256");
  if (!signature) return false;
  const expected =
    "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(req.body).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && token === VERIFY_TOKEN) return res.status(200).send(challenge);
  return res.sendStatus(403);
});

app.post("/webhook", (req, res) => {
  if (!validateSignature(req)) return res.sendStatus(401);
  let payload = {};
  try { payload = JSON.parse(req.body.toString("utf8") || "{}"); } catch {}
  console.log("[Webhook] Evento:", JSON.stringify(payload, null, 2));
  res.sendStatus(200);
});

app.get("/", (_req, res) => res.status(200).send("OK - Meta Webhook up"));

app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
